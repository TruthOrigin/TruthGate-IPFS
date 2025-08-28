using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using TruthGate_Web.Security;
using TruthGate_Web.Security.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Services
{
    public static class RateLimiterConstants
    {
        public const string KeyValidationResultItem = "KeyValidationResult";
    }

    public enum KeyValidationResult { Valid = 0, Invalid = 1, Missing = 2 }

    public interface IRateLimiterService
    {
        Task<bool> BanIpAsync(
       string ip,
       TimeSpan duration,
       RateScope scope = RateScope.Public,
       bool isTrueBan = false,
       string reasonCode = "MANUAL_BAN");

        Task<bool> BanIpv6PrefixAsync(
            string ipv6Prefix64,
            TimeSpan duration,
            RateScope scope = RateScope.Gateway,
            bool isTrueBan = false,
            string reasonCode = "MANUAL_PREFIX_BAN");
        bool IsBanned(HttpContext context, string? apiKey = null, bool isAdminScope = false);
        bool IsBanned(string ip, string? apiKey = null, bool isAdminScope = false);
        Task RecordFailureAsync(HttpContext context, string? apiKey = null, bool isAdminScope = false);
        Task RecordSuccessAsync(HttpContext context, string? apiKey = null);

        Task<(IReadOnlyList<BanDto> Items, int Total)> GetBansAsync(int page, int pageSize,
            string? ipFilter = null, string? ipv6PrefixFilter = null,
            BanScopeFilter? scope = null, bool? isTrueBan = null,
            DateTimeOffset? createdFrom = null, DateTimeOffset? createdTo = null);

        Task<bool> UnbanIpAsync(
    string ip,
    int resetWindowMinutes = 60,
    bool cooldownWhitelist = false,
    TimeSpan? cooldown = null,
    bool alsoClearPrefixBan = false);
        Task<bool> UnbanIpv6PrefixAsync(string ipv6Prefix);
        Task<bool> UnbanByIdAsync(Guid banId, int resetWindowMinutes = 60);

        Task<bool> AddWhitelistIpAsync(string ip, string? reason = null, DateTimeOffset? expiresUtc = null, bool auto = false);
        Task<bool> AddWhitelistIpv6PrefixAsync(string ipv6Prefix, string? reason = null, DateTimeOffset? expiresUtc = null, bool auto = false);
        Task<bool> RemoveWhitelistIpAsync(string ip);
        Task<bool> RemoveWhitelistIpv6PrefixAsync(string ipv6Prefix);

        Task<bool> IsWhitelistedAsync(string ip);
        Task<bool> IsWhitelistedPrefixAsync(string ipv6Prefix);
    }

    public class RateLimiterService : IRateLimiterService
    {
        private readonly IMemoryCache _cache;
        internal IDbContextFactory<RateLimiterDbContext> _dbf;
        private readonly IOptions<RateLimiterOptions> _opt;
        private readonly ILogger<RateLimiterService> _log;

        // minute counters in-memory (flush every 5–10s)
        private readonly ConcurrentDictionary<(string Ip, string Minute), MinuteAccumulator> _ipMinute = new();
        private readonly ConcurrentDictionary<string, GlobalAccumulator> _globalMinute = new();

        // whitelist caches
        private readonly ConcurrentDictionary<string, DateTimeOffset?> _whitelistIps = new();
        private readonly ConcurrentDictionary<string, DateTimeOffset?> _whitelistPrefixes = new();

        // active bans cache (true bans & soft bans)
        private readonly ConcurrentDictionary<string, (DateTimeOffset Exp, bool True, RateScope Scope)> _banIp = new();
        private readonly ConcurrentDictionary<string, (DateTimeOffset Exp, bool True, RateScope Scope)> _banPrefix = new();

        // TLS churn tracking
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTimeOffset>> _connIdsByIp = new();
        private readonly ConcurrentDictionary<(string Ip, long Sec), (int NewConns, int Reqs)> _churnSec = new();

        public RateLimiterService(
            IMemoryCache cache,
            IDbContextFactory<RateLimiterDbContext> dbf,
            IOptions<RateLimiterOptions> opt,
            ILogger<RateLimiterService> log)
        {
            _cache = cache; _dbf = dbf; _opt = opt; _log = log;
        }

        public bool IsBanned(string ip, string? apiKey = null, bool isAdminScope = false)
        {
            if (_whitelistIps.ContainsKey(ip)) return false;
            if (IpUtils.TryGetIpv6Prefix64(ip, out var pfx) && _whitelistPrefixes.ContainsKey(pfx)) return false;

            // prefix true ban check first
            if (IpUtils.TryGetIpv6Prefix64(ip, out var prefix) && _banPrefix.TryGetValue(prefix, out var pban))
            {
                if (pban.Exp > DateTimeOffset.UtcNow) return true; else _banPrefix.TryRemove(prefix, out _);
            }

            if (_banIp.TryGetValue(ip, out var ban))
            {
                if (ban.Exp > DateTimeOffset.UtcNow) return true; else _banIp.TryRemove(ip, out _);
            }
            return false;
        }

        public bool IsBanned(HttpContext context, string? apiKey = null, bool isAdminScope = false)
        {
            var ip = IpUtils.GetClientIpString(context);
            if (_whitelistIps.ContainsKey(ip)) return false;
            if (IpUtils.TryGetIpv6Prefix64(ip, out var pfx) && _whitelistPrefixes.ContainsKey(pfx)) return false;

            // prefix true ban check first
            if (IpUtils.TryGetIpv6Prefix64(ip, out var prefix) && _banPrefix.TryGetValue(prefix, out var pban))
            {
                if (pban.Exp > DateTimeOffset.UtcNow) return true; else _banPrefix.TryRemove(prefix, out _);
            }

            if (_banIp.TryGetValue(ip, out var ban))
            {
                if (ban.Exp > DateTimeOffset.UtcNow) return true; else _banIp.TryRemove(ip, out _);
            }
            return false;
        }

        public async Task RecordFailureAsync(HttpContext context, string? apiKey = null, bool isAdminScope = false)
        {
            var ip = IpUtils.GetClientIpString(context);
            var now = DateTimeOffset.UtcNow;
            var currBucket = TimeUtils.MinuteBucketUtc(now);

            // increment minute counters
            var acc = _ipMinute.GetOrAdd((ip, currBucket), _ => new MinuteAccumulator());
            var gacc = _globalMinute.GetOrAdd(currBucket, _ => new GlobalAccumulator());
            if (isAdminScope) acc.AdminBadKeyCalls++; else acc.PublicCalls++;
            gacc.TotalCalls++;

            if (!isAdminScope) return;

            await using var db = await _dbf.CreateDbContextAsync();
            var fromBucketInclusive = TimeUtils.MinuteBucketUtc(now.AddHours(-24));

            // DB sum over last 24h using lexicographic range (yyyyMMddHHmm sorts correctly)
            var bad24Db = await db.IpMinuteCounters
                .Where(x => x.Ip == ip && x.MinuteBucket.CompareTo(fromBucketInclusive) >= 0)
                .SumAsync(x => (int?)x.AdminBadKeyCalls) ?? 0;

            // Include current in-memory minute (just incremented)
            var bad24 = bad24Db;
            if (_ipMinute.TryGetValue((ip, currBucket), out var memAcc))
                bad24 += memAcc.AdminBadKeyCalls;

            if (bad24 >= _opt.Value.Admin.MaxBadKeyPerIpPer24h)
            {
                await AddBanAsync(db, new Ban
                {
                    Ip = ip,
                    Scope = RateScope.Admin,
                    Type = BanType.Soft,
                    IsTrueBan = false,
                    ReasonCode = "ADMIN_BAD_KEY_THRESHOLD",
                    CreatedUtc = now,
                    ExpiresUtc = now.Add(_opt.Value.Admin.BanDurationSoft)
                }, cacheOnly: false);
            }
        }



        public async Task RecordSuccessAsync(HttpContext context, string? apiKey = null)
        {
            var ip = IpUtils.GetClientIpString(context);
            var now = DateTimeOffset.UtcNow;
            var bucket = TimeUtils.MinuteBucketUtc(now);

            var acc = _ipMinute.GetOrAdd((ip, bucket), _ => new MinuteAccumulator());
            var gacc = _globalMinute.GetOrAdd(bucket, _ => new GlobalAccumulator());
            acc.AdminGoodKeyCalls++; gacc.TotalCalls++;

            if (!string.IsNullOrEmpty(apiKey))
            {
                var keyHash = HashUtils.Sha256Hex(apiKey);
                await using var db = await _dbf.CreateDbContextAsync();
                var exist = await db.GracePairs.FindAsync(ip, keyHash);
                var exp = now.AddDays(_opt.Value.Admin.GraceDays);
                if (exist == null)
                {
                    db.GracePairs.Add(new GracePair { Ip = ip, KeyHash = keyHash, ExpiresUtc = exp });
                }
                else exist.ExpiresUtc = exp;
                await db.SaveChangesAsync();
            }
        }

        // Admin ops --------------------------------------------------------------
        public async Task<bool> BanIpAsync(
    string ip,
    TimeSpan duration,
    RateScope scope = RateScope.Public,
    bool isTrueBan = false,
    string reasonCode = "MANUAL_BAN")
        {
            var canon = CanonicalizeIp(ip?.Trim() ?? "");
            if (string.IsNullOrWhiteSpace(canon)) return false;

            await using var db = await _dbf.CreateDbContextAsync();
            var now = DateTimeOffset.UtcNow;
            var ban = new Ban
            {
                Ip = canon,
                Scope = scope,
                Type = isTrueBan ? BanType.True : BanType.Soft,
                IsTrueBan = isTrueBan,
                ReasonCode = reasonCode,
                CreatedUtc = now,
                ExpiresUtc = now.Add(duration)
            };
            await AddBanAsync(db, ban, cacheOnly: false);
            return true;
        }

        public async Task<bool> BanIpv6PrefixAsync(
            string ipv6Prefix64,
            TimeSpan duration,
            RateScope scope = RateScope.Gateway,
            bool isTrueBan = false,
            string reasonCode = "MANUAL_PREFIX_BAN")
        {
            var pfx = CanonicalizeIpv6Prefix64(ipv6Prefix64?.Trim() ?? "");
            if (string.IsNullOrWhiteSpace(pfx)) return false;

            await using var db = await _dbf.CreateDbContextAsync();
            var now = DateTimeOffset.UtcNow;
            var ban = new Ban
            {
                IpV6Prefix = pfx,
                Scope = scope,
                Type = isTrueBan ? BanType.True : BanType.Soft,
                IsTrueBan = isTrueBan,
                ReasonCode = reasonCode,
                CreatedUtc = now,
                ExpiresUtc = now.Add(duration)
            };
            await AddBanAsync(db, ban, cacheOnly: false);
            return true;
        }
        public async Task<(IReadOnlyList<BanDto> Items, int Total)> GetBansAsync(
            int page, int pageSize, string? ipFilter = null, string? ipv6PrefixFilter = null,
            BanScopeFilter? scope = null, bool? isTrueBan = null,
            DateTimeOffset? createdFrom = null, DateTimeOffset? createdTo = null)
        {
            await using var db = await _dbf.CreateDbContextAsync();
            var q = db.Bans.AsQueryable();
            if (!string.IsNullOrWhiteSpace(ipFilter)) q = q.Where(x => x.Ip == ipFilter);
            if (!string.IsNullOrWhiteSpace(ipv6PrefixFilter)) q = q.Where(x => x.IpV6Prefix == ipv6PrefixFilter);
            if (scope.HasValue) q = q.Where(x => x.Scope == (RateScope)scope.Value);
            if (isTrueBan.HasValue) q = q.Where(x => x.IsTrueBan == isTrueBan.Value);
            if (createdFrom.HasValue) q = q.Where(x => x.CreatedUtc >= createdFrom.Value);
            if (createdTo.HasValue) q = q.Where(x => x.CreatedUtc <= createdTo.Value);

            var total = await q.CountAsync();
            var items = await q.OrderByDescending(x => x.CreatedUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(x => new BanDto
                {
                    Id = x.Id,
                    Ip = x.Ip,
                    Ipv6Prefix = x.IpV6Prefix,
                    Scope = x.Scope,
                    IsTrueBan = x.IsTrueBan,
                    ReasonCode = x.ReasonCode,
                    CreatedUtc = x.CreatedUtc,
                    ExpiresUtc = x.ExpiresUtc
                }).ToListAsync();
            return (items, total);
        }

        public async Task<bool> UnbanIpAsync(
    string ip,
    int resetWindowMinutes = 60,
    bool cooldownWhitelist = false,
    TimeSpan? cooldown = null,
    bool alsoClearPrefixBan = false)
        {
            var raw = ip?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(raw)) return false;

            var canon = CanonicalizeIp(raw); // "::ffff:198.51.100.23" or v6 compressed
            var keys = (raw == canon) ? new[] { raw } : new[] { raw, canon };

            var any = false;

            // 1) Clear in-memory ban(s)
            foreach (var k in keys)
                if (_banIp.TryRemove(k, out _)) any = true;

            // 2) Clear DB ban rows for either representation
            await using (var db = await _dbf.CreateDbContextAsync())
            {
                // EF translates Contains(...) to IN (...)
                var bans = await db.Bans.Where(x => keys.Contains(x.Ip)).ToListAsync();
                if (bans.Count > 0)
                {
                    db.Bans.RemoveRange(bans);
                    await db.SaveChangesAsync();
                    any = true;
                }
            }

            // 3) Reset last hour so next call doesn't insta-reban
            ResetRecentActivityInMemory(keys, resetWindowMinutes);
            await ResetRecentCountersInDbAsync(keys, resetWindowMinutes);

            // 4) (Optional) If you want a full pardon even when a /64 prefix ban exists
            if (alsoClearPrefixBan && IpUtils.TryGetIpv6Prefix64(canon, out var pfx))
            {
                _banPrefix.TryRemove(pfx, out _);
                await using var db2 = await _dbf.CreateDbContextAsync();
                var pfxRows = await db2.Bans.Where(x => x.IpV6Prefix == pfx).ToListAsync();
                if (pfxRows.Count > 0)
                {
                    db2.Bans.RemoveRange(pfxRows);
                    await db2.SaveChangesAsync();
                    any = true;
                }
            }

            // 5) (Optional) short cooldown so heavy clients don’t smack limits immediately
            if (cooldownWhitelist && cooldown.GetValueOrDefault() > TimeSpan.Zero)
            {
                var exp = DateTimeOffset.UtcNow + cooldown.Value;
                foreach (var k in keys) _whitelistIps[k] = exp;
            }

            return any;
        }




        private static string CanonicalizeIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr))
                return ip.Trim();

            var v6 = addr.AddressFamily == AddressFamily.InterNetwork
                ? addr.MapToIPv6()
                : addr;

            return v6.ToString(); // compressed canonical
        }

        // Normalize an IPv6 /64 prefix string. Accepts "2001:db8::/64" or "2001:db8::"
        private static string CanonicalizeIpv6Prefix64(string ipv6OrPrefix)
        {
            var s = ipv6OrPrefix.Trim();
            var slash = s.IndexOf('/');
            if (slash >= 0) s = s[..slash];

            if (!IPAddress.TryParse(s, out var addr))
                return ipv6OrPrefix.Trim();

            var v6 = addr.AddressFamily == AddressFamily.InterNetwork
                ? addr.MapToIPv6()
                : addr;

            var bytes = v6.GetAddressBytes();
            for (int i = 8; i < 16; i++) bytes[i] = 0;  // zero lower 64 bits
            var net = new IPAddress(bytes).ToString();
            return net + "/64";
        }


        // Wipe in-memory usage for a SINGLE ip (last N minutes), and churn windows
        private void ResetRecentActivityInMemory(IEnumerable<string> ips, int windowMinutes)
        {
            var now = DateTimeOffset.UtcNow;
            var secNow = now.ToUnixTimeSeconds();

            foreach (var ip in ips.Distinct(StringComparer.Ordinal))
            {
                // minute counters
                for (int i = 0; i <= windowMinutes; i++)
                {
                    var b = TimeUtils.MinuteBucketUtc(now.AddMinutes(-i));
                    _ipMinute.TryRemove((ip, b), out _);
                }

                // TLS churn
                _connIdsByIp.TryRemove(ip, out _);
                for (int i = 0; i <= windowMinutes * 60; i++)
                    _churnSec.TryRemove((ip, secNow - i), out _);
            }
        }

        private async Task ResetRecentCountersInDbAsync(IEnumerable<string> ips, int windowMinutes)
        {
            var fromBucketInclusive = TimeUtils.MinuteBucketUtc(DateTimeOffset.UtcNow.AddMinutes(-windowMinutes));
            await using var db = await _dbf.CreateDbContextAsync();

            foreach (var k in ips.Distinct(StringComparer.Ordinal))
            {
                // Async version fixes the GetAwaiter issue
                await db.Database.ExecuteSqlInterpolatedAsync($@"
DELETE FROM IpMinuteCounters
WHERE Ip = {k} AND MinuteBucket >= {fromBucketInclusive}");
            }
        }



        public async Task<bool> UnbanIpv6PrefixAsync(string ipv6Prefix)
        {
            var canonPfx = CanonicalizeIpv6Prefix64(ipv6Prefix);
            var any = false;

            // In-memory cache removals
            if (_banPrefix.TryRemove(canonPfx, out _)) any = true;
            if (!string.Equals(canonPfx, ipv6Prefix, StringComparison.OrdinalIgnoreCase))
                if (_banPrefix.TryRemove(ipv6Prefix, out _)) any = true;

            // DB rows
            await using var db = await _dbf.CreateDbContextAsync();
            var bans = await db.Bans
                .Where(x => x.IpV6Prefix == canonPfx || x.IpV6Prefix == ipv6Prefix)
                .ToListAsync();

            if (bans.Count == 0) return any;

            db.Bans.RemoveRange(bans);
            await db.SaveChangesAsync();
            return true;
        }



        public async Task<bool> UnbanByIdAsync(Guid banId, int resetWindowMinutes = 60)
        {
            await using var db = await _dbf.CreateDbContextAsync();
            var ban = await db.Bans.FindAsync(banId);
            if (ban == null) return false;

            db.Bans.Remove(ban);
            await db.SaveChangesAsync();

            var any = true; // DB removal happened

            if (!string.IsNullOrWhiteSpace(ban.Ip))
            {
                var raw = ban.Ip.Trim();
                var canon = CanonicalizeIp(raw);
                var keys = (raw == canon) ? new[] { raw } : new[] { raw, canon };

                foreach (var k in keys)
                    _banIp.TryRemove(k, out _);

                ResetRecentActivityInMemory(keys, resetWindowMinutes);
                await ResetRecentCountersInDbAsync(keys, resetWindowMinutes);
            }

            if (!string.IsNullOrWhiteSpace(ban.IpV6Prefix))
            {
                var pfx = CanonicalizeIpv6Prefix64(ban.IpV6Prefix);
                _banPrefix.TryRemove(pfx, out _);
                if (!string.Equals(pfx, ban.IpV6Prefix, StringComparison.Ordinal))
                    _banPrefix.TryRemove(ban.IpV6Prefix, out _);
            }

            return any;
        }



        public async Task<bool> AddWhitelistIpAsync(string ip, string? reason = null, DateTimeOffset? expiresUtc = null, bool auto = false)
        {
            await using var db = await _dbf.CreateDbContextAsync();
            db.Whitelists.Add(new Whitelist { Ip = ip, Reason = reason, CreatedUtc = DateTimeOffset.UtcNow, ExpiresUtc = expiresUtc, Auto = auto });
            await db.SaveChangesAsync();
            _whitelistIps[ip] = expiresUtc;
            return true;
        }

        public async Task<bool> AddWhitelistIpv6PrefixAsync(string ipv6Prefix, string? reason = null, DateTimeOffset? expiresUtc = null, bool auto = false)
        {
            await using var db = await _dbf.CreateDbContextAsync();
            db.Whitelists.Add(new Whitelist { Ipv6Prefix = ipv6Prefix, Reason = reason, CreatedUtc = DateTimeOffset.UtcNow, ExpiresUtc = expiresUtc, Auto = auto });
            await db.SaveChangesAsync();
            _whitelistPrefixes[ipv6Prefix] = expiresUtc;
            return true;
        }

        public async Task<bool> RemoveWhitelistIpAsync(string ip)
        {
            await using var db = await _dbf.CreateDbContextAsync();
            var items = await db.Whitelists.Where(x => x.Ip == ip).ToListAsync();
            if (items.Count == 0) return false;
            db.Whitelists.RemoveRange(items);
            await db.SaveChangesAsync();
            _whitelistIps.TryRemove(ip, out _);
            return true;
        }

        public async Task<bool> RemoveWhitelistIpv6PrefixAsync(string ipv6Prefix)
        {
            await using var db = await _dbf.CreateDbContextAsync();
            var items = await db.Whitelists.Where(x => x.Ipv6Prefix == ipv6Prefix).ToListAsync();
            if (items.Count == 0) return false;
            db.Whitelists.RemoveRange(items);
            await db.SaveChangesAsync();
            _whitelistPrefixes.TryRemove(ipv6Prefix, out _);
            return true;
        }

        public Task<bool> IsWhitelistedAsync(string ip)
            => Task.FromResult(_whitelistIps.ContainsKey(ip));

        public Task<bool> IsWhitelistedPrefixAsync(string ipv6Prefix)
            => Task.FromResult(_whitelistPrefixes.ContainsKey(ipv6Prefix));

        // Internal helpers -------------------------------------------------------

        internal async Task FlushAsync()
        {
            var snapIp = _ipMinute.ToArray();
            var snapGlob = _globalMinute.ToArray();
            if (snapIp.Length == 0 && snapGlob.Length == 0) return;

            await using var db = await _dbf.CreateDbContextAsync();
            using var tx = await db.Database.BeginTransactionAsync();
            try
            {
                foreach (var ((ip, minute), acc) in snapIp)
                {
                    var existing = await db.IpMinuteCounters.FindAsync(ip, minute);
                    if (existing == null)
                    {
                        db.IpMinuteCounters.Add(new IpMinuteCounter
                        {
                            Ip = ip,
                            MinuteBucket = minute,
                            PublicCalls = acc.PublicCalls,
                            AdminBadKeyCalls = acc.AdminBadKeyCalls,
                            AdminGoodKeyCalls = acc.AdminGoodKeyCalls,
                            GatewayCalls = acc.GatewayCalls,
                            GatewayOverageUsed = acc.GatewayOverageUsed,
                            Scope = RateScope.Global // informational
                        });
                    }
                    else
                    {
                        existing.PublicCalls += acc.PublicCalls;
                        existing.AdminBadKeyCalls += acc.AdminBadKeyCalls;
                        existing.AdminGoodKeyCalls += acc.AdminGoodKeyCalls;
                        existing.GatewayCalls += acc.GatewayCalls;
                        existing.GatewayOverageUsed += acc.GatewayOverageUsed;
                    }
                    _ipMinute.TryRemove((ip, minute), out _);
                }

                foreach (var (minute, acc) in snapGlob)
                {
                    var existing = await db.GlobalMinuteCounters.FindAsync(minute);
                    if (existing == null) db.GlobalMinuteCounters.Add(new GlobalMinuteCounter { MinuteBucket = minute, TotalCalls = acc.TotalCalls });
                    else existing.TotalCalls += acc.TotalCalls;
                    _globalMinute.TryRemove(minute, out _);
                }

                await db.SaveChangesAsync();
                await tx.CommitAsync();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "RateLimiter flush failed; keeping counters in memory");
                await tx.RollbackAsync();
            }
        }

        internal async Task ApplyPragmasAsync(RateLimiterDbContext db)
        {
            await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
            await db.Database.ExecuteSqlRawAsync("PRAGMA synchronous=NORMAL;");
            await db.Database.ExecuteSqlRawAsync("PRAGMA temp_store=MEMORY;");
        }

        internal async Task AddBanAsync(RateLimiterDbContext db, Ban ban, bool cacheOnly)
        {
            if (!cacheOnly)
            {
                db.Bans.Add(ban);
                await db.SaveChangesAsync();
            }
            if (!string.IsNullOrWhiteSpace(ban.Ip)) _banIp[ban.Ip!] = (ban.ExpiresUtc, ban.IsTrueBan, ban.Scope);
            if (!string.IsNullOrWhiteSpace(ban.IpV6Prefix)) _banPrefix[ban.IpV6Prefix!] = (ban.ExpiresUtc, ban.IsTrueBan, ban.Scope);
        }

        internal int GetGlobalLastHourTotal(DateTimeOffset now)
        {
            var total = 0;
            for (int i = 0; i < 60; i++)
            {
                var b = TimeUtils.MinuteBucketUtc(now.AddMinutes(-i));
                if (_globalMinute.TryGetValue(b, out var acc)) total += acc.TotalCalls;
            }
            return total;
        }

        internal (int MinuteCount, int HourOverageUsed) GetGatewayUsage(string ip, DateTimeOffset now, int freePerMinute)
        {
            var currBucket = TimeUtils.MinuteBucketUtc(now);
            var minuteCount = 0;
            var hourOverage = 0;

            for (int i = 0; i < 60; i++)
            {
                var b = TimeUtils.MinuteBucketUtc(now.AddMinutes(-i));
                if (_ipMinute.TryGetValue((ip, b), out var acc))
                {
                    minuteCount = (i == 0) ? acc.GatewayCalls : minuteCount;
                    var over = Math.Max(0, acc.GatewayCalls - freePerMinute);
                    hourOverage += over;
                }
            }
            return (minuteCount, hourOverage);
        }

        internal void IncGateway(string ip, DateTimeOffset now, int freePerMinute, ref int overageUsed)
        {
            var bucket = TimeUtils.MinuteBucketUtc(now);
            var acc = _ipMinute.GetOrAdd((ip, bucket), _ => new MinuteAccumulator());
            acc.GatewayCalls++;
            var over = Math.Max(0, acc.GatewayCalls - freePerMinute);
            acc.GatewayOverageUsed = over;
            overageUsed = over;
            var gacc = _globalMinute.GetOrAdd(bucket, _ => new GlobalAccumulator());
            gacc.TotalCalls++;
        }

        internal async Task<bool> IsInGraceAsync(string ip, string keyHash)
        {
            await using var db = await _dbf.CreateDbContextAsync();
            var now = DateTimeOffset.UtcNow;
            var g = await db.GracePairs.FindAsync(ip, keyHash);
            return g != null && g.ExpiresUtc > now;
        }

        // Add near your fields (top of RateLimiterService)
        private long _fallbackConnSeq = 0;

        // Replace your method with this version
        internal void TrackTlsChurn(HttpContext ctx)
        {
            if (!_opt.Value.TlsChurn.Enabled) return;

            // 1) IP may be null under TestServer → if no IP, skip churn accounting
            var ip = IpUtils.GetClientIpString(ctx);
            if (string.IsNullOrWhiteSpace(ip)) return;

            // 2) Connection.Id can be null/empty under TestServer → synthesize one
            var connId = ctx.Connection.Id;
            if (string.IsNullOrEmpty(connId))
            {
                connId = $"{ip}:{Interlocked.Increment(ref _fallbackConnSeq)}";
                try { ctx.Connection.Id = connId; } catch { /* ignore if setter not allowed */ }
            }

            var now = DateTimeOffset.UtcNow;
            var sec = now.ToUnixTimeSeconds();

            // 3) Per-IP connection set; safe because ip is non-empty
            var set = _connIdsByIp.GetOrAdd(ip, _ => new());
            var isNewConn = set.TryAdd(connId, now);

            // 4) Second-bucket aggregation; safe tuple key (ip, sec) since ip not null
            var entry = _churnSec.AddOrUpdate(
                (ip, sec),
                _ => (isNewConn ? 1 : 0, 1),
                (_, prev) => (prev.NewConns + (isNewConn ? 1 : 0), prev.Reqs + 1));

            // 5) Compute over the last ObserveSeconds
            int newConnSum = 0, reqSum = 0;
            var window = Math.Max(1, _opt.Value.TlsChurn.ObserveSeconds);
            for (int i = 0; i < window; i++)
            {
                var key = (ip, sec - i);
                if (_churnSec.TryGetValue(key, out var r))
                {
                    newConnSum += r.NewConns;
                    reqSum += r.Reqs;
                }
            }

            if (newConnSum > _opt.Value.TlsChurn.NewConnectionsPerSec * window)
            {
                var avgReqPerConn = reqSum == 0 ? 0 : (double)reqSum / Math.Max(1, newConnSum);
                if (avgReqPerConn <= _opt.Value.TlsChurn.MinReqPerConn)
                {
                    // soft ban 15 minutes (your shared escalation will handle the rest)
                    var exp = DateTimeOffset.UtcNow.AddMinutes(15);
                    _banIp[ip] = (exp, false, RateScope.Gateway);
                }
            }
        }

    }
}

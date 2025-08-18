using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Services
{
    public sealed class IpnsUpdateOptions
    {
        /// <summary>Max number of IPNS entries processed in parallel (different keys).</summary>
        public int MaxConcurrency { get; set; } = 4;

        /// <summary>Minimum time between scheduled runs for the same key. Manual runs ignore this.</summary>
        public TimeSpan ScheduledPerKeyCooldown { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>Main scheduler wake interval. Concurrency happens inside each pass.</summary>
        public TimeSpan SchedulerInterval { get; set; } = TimeSpan.FromMinutes(30);
    }

    public interface IIpnsUpdateService
    {
        /// <summary>Runs the updater for a single IPNS name now (runs concurrently with others, but serialized for this key).</summary>
        Task RunOnceForAsync(string name, CancellationToken ct = default);

        /// <summary>Runs the updater for all IPNS entries now (up to MaxConcurrency in parallel).</summary>
        Task RunOnceAllAsync(CancellationToken ct = default);

        /// <summary>Applies retroactive KeepOld policy for the given name (e.g., after toggling).</summary>
        Task EnsureKeepOldPolicyAsync(string name, CancellationToken ct = default);
    }

    public sealed class IpnsUpdateWorker : BackgroundService, IIpnsUpdateService
    {
        private readonly IHttpClientFactory _http;
        private readonly IConfigService _config;
        private readonly IMemoryCache _cache;
        private readonly ILogger<IpnsUpdateWorker> _log;
        private readonly IpnsUpdateOptions _opts;
        private readonly IApiKeyProvider _keys;

        private static readonly Regex VersionRx = new(@"-v(?<n>\d+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private const string ManagedRoot = "/production/pinned";
        private const string StagingRoot = "/production/.staging/ipns";

        // --- Concurrency + scheduling state ---
        private readonly SemaphoreSlim _globalSlots; // caps overall concurrency
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _perKeyLocks = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _lastScheduledRun = new(StringComparer.OrdinalIgnoreCase);

        // A small guard to avoid two full "RunAll" passes overlapping (manual vs scheduler).
        private readonly SemaphoreSlim _runAllOnce = new(1, 1);

        public IpnsUpdateWorker(
            IHttpClientFactory http,
            IConfigService config,
            IMemoryCache cache,
            ILogger<IpnsUpdateWorker> log,
            IApiKeyProvider keys,
            IOptions<IpnsUpdateOptions> opts)
        {
            _http = http;
            _config = config;
            _cache = cache;
            _log = log;
            _keys = keys;
            _opts = opts?.Value ?? new IpnsUpdateOptions();

            if (_opts.MaxConcurrency < 1) _opts.MaxConcurrency = 1;
            _globalSlots = new SemaphoreSlim(_opts.MaxConcurrency, _opts.MaxConcurrency);
            if (_opts.SchedulerInterval <= TimeSpan.Zero) _opts.SchedulerInterval = TimeSpan.FromMinutes(30);
            if (_opts.ScheduledPerKeyCooldown <= TimeSpan.Zero) _opts.ScheduledPerKeyCooldown = TimeSpan.FromMinutes(10);
        }

        // =========================
        // Background scheduler loop
        // =========================
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Crash-safe: cleanup orphaned staging at start
            try { await CleanupStagingAsync(stoppingToken); }
            catch (Exception ex) { _log.LogWarning(ex, "Staging cleanup failed on startup."); }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await RunScheduledPassAsync(stoppingToken);
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    _log.LogError(ex, "IPNS scheduled pass failed.");
                }

                try { await Task.Delay(_opts.SchedulerInterval, stoppingToken); }
                catch (TaskCanceledException) { }
            }
        }

        private async Task RunScheduledPassAsync(CancellationToken ct)
        {
            // One "RunAll" style pass at a time
            await _runAllOnce.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var entries = (cfg.IpnsKeys ?? new List<IpnsKey>()).ToList();
                if (entries.Count == 0)
                {
                    // opportunistic staging cleanup
                    try { await CleanupStagingAsync(ct); } catch { }
                    return;
                }

                // Build tasks for items that are either AutoUpdate or need policy enforcement.
                var now = DateTimeOffset.UtcNow;

                var toProcess = new List<IpnsKey>();
                foreach (var e in entries)
                {
                    // Always apply retroactive pruning if KeepOld=false
                    // (We enforce inside the update pipeline as well, but this makes sure "AutoUpdate=false" keys still prune.)
                    if (!e.KeepOldCidPinned)
                        _ = EnsureKeepOldPolicyAsync(e.Name, ct); // fire-and-forget; it takes key lock inside

                    if (!e.AutoUpdateToPin) continue;

                    // Per-key cooldown for scheduled runs
                    if (_lastScheduledRun.TryGetValue(e.Name, out var last) &&
                        now - last < _opts.ScheduledPerKeyCooldown)
                        continue;

                    toProcess.Add(e);
                    _lastScheduledRun[e.Name] = now;
                }

                if (toProcess.Count == 0)
                {
                    // opportunistic staging cleanup
                    try { await CleanupStagingAsync(ct); } catch { }
                    return;
                }

                // Launch with bounded parallelism
                var tasks = toProcess.Select(k => ProcessOneAsync(k.Name, forceResolve: false, ct));
                await WhenAllBounded(tasks, ct);

                // Final: opportunistic staging cleanup
                try { await CleanupStagingAsync(ct); } catch { /* ignore */ }
            }
            finally
            {
                _runAllOnce.Release();
            }
        }

        // ==================================================
        // Public API (manual) — integrates with same pipeline
        // ==================================================
        public async Task RunOnceForAsync(string name, CancellationToken ct = default)
        {
            // Manual: ignore cooldown, run now (but still respect concurrency + per-key lock)
            await ProcessOneAsync(name, forceResolve: true, ct);
        }

        public async Task RunOnceAllAsync(CancellationToken ct = default)
        {
            await _runAllOnce.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var entries = (cfg.IpnsKeys ?? new List<IpnsKey>()).Select(k => k.Name).ToList();
                var tasks = entries.Select(n => ProcessOneAsync(n, forceResolve: true, ct));
                await WhenAllBounded(tasks, ct);

                try { await CleanupStagingAsync(ct); } catch { }
            }
            finally
            {
                _runAllOnce.Release();
            }
        }

        public async Task EnsureKeepOldPolicyAsync(string name, CancellationToken ct = default)
        {
            var keyLock = GetKeyLock(name);
            await keyLock.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var entry = cfg.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase));
                if (entry is null) return;

                if (!entry.KeepOldCidPinned)
                    await RemoveAllButLatestAsync(entry.Name, ct);
            }
            finally { keyLock.Release(); }
        }

        // ======================
        // Core per-key operation
        // ======================
        private async Task ProcessOneAsync(string name, bool forceResolve, CancellationToken ct)
        {
            // Throttle global concurrency
            await _globalSlots.WaitAsync(ct);
            try
            {
                var keyLock = GetKeyLock(name);
                await keyLock.WaitAsync(ct);
                try
                {
                    var cfg = _config.Get();
                    var e = cfg.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase));
                    if (e is null) return;

                    // If scheduled pass and auto-update is off, just enforce pruning and exit
                    if (!forceResolve && !e.AutoUpdateToPin)
                    {
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        return;
                    }

                    // Resolve IPNS
                    var ipnsKey = CanonicalizeIpnsKey(e.Key);
                    string latestCid;
                    try
                    {
                        latestCid = await ResolveIpnsAsync(ipnsKey, ct);
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "IPNS resolve failed for '{Name}'.", e.Name);
                        // Even on resolve failure, still enforce pruning policy
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        return;
                    }

                    if (string.IsNullOrWhiteSpace(latestCid))
                    {
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        return;
                    }

                    // Already current?
                    if (string.Equals(latestCid, e.CurrentCID, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        return;
                    }

                    // New version flow
                    var nextVersion = await ComputeNextVersionAsync(e.Name, ct);
                    var targetFolder = $"{ManagedRoot}/{e.Name}-v{nextVersion:000}";
                    var staged = $"{StagingRoot}/{e.Name}/{Guid.NewGuid():N}";

                    // Stage → pin → provide → promote
                    await EnsureFolderAsync($"{StagingRoot}/{e.Name}", ct);
                    await FilesCpFromIpfsAsync(latestCid, staged, ct);
                    await PinAddRecursiveAsync(latestCid, ct);
                    _ = TryProvideAsync(latestCid, ct); // best-effort

                    await EnsureFolderAsync(ManagedRoot, ct);
                    await FilesMvAsync(staged, targetFolder, ct);

                    // Update CurrentCID in config
                    await _config.UpdateAsync(config =>
                    {
                        var t = config.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, e.Name, StringComparison.OrdinalIgnoreCase));
                        if (t is not null) t.CurrentCID = latestCid;
                    });

                    // Retroactive cleanup if KeepOld=false
                    if (!e.KeepOldCidPinned)
                        await RemoveAllButLatestAsync(e.Name, ct);
                }
                finally { keyLock.Release(); }
            }
            finally { _globalSlots.Release(); }
        }

        private SemaphoreSlim GetKeyLock(string name)
            => _perKeyLocks.GetOrAdd(name ?? string.Empty, _ => new SemaphoreSlim(1, 1));

        // =====================
        // Internal helper bits
        // =====================
        private static string CanonicalizeIpnsKey(string key)
        {
            var s = (key ?? "").Trim();
            if (s.StartsWith("/ipns/", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(6);
            return s;
        }

        private async Task<string> ResolveIpnsAsync(string ipnsKey, CancellationToken ct)
        {
            var rest = $"/api/v0/name/resolve?arg={Uri.EscapeDataString($"/ipns/{ipnsKey}")}&recursive=false&nocache=false";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"name/resolve failed ({(int)res.StatusCode})");

            var el = await ReadLastJsonAsync(res);
            var path = el?.GetProperty("Path").GetString();
            if (string.IsNullOrWhiteSpace(path) || !path.StartsWith("/ipfs/", StringComparison.Ordinal))
                throw new InvalidOperationException("IPNS resolution did not return /ipfs/<cid>.");

            return path.Substring("/ipfs/".Length);
        }

        private async Task FilesCpFromIpfsAsync(string cid, string destPath, CancellationToken ct)
        {
            var from = $"/ipfs/{cid}";
            var rest = $"/api/v0/files/cp?arg={Uri.EscapeDataString(from)}&arg={Uri.EscapeDataString(destPath)}&parents=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"files/cp failed → {destPath} ({(int)res.StatusCode})");
        }

        private async Task FilesRmRecursiveAsync(string mfsPath, CancellationToken ct)
        {
            mfsPath = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/rm?arg={Uri.EscapeDataString(mfsPath)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode)
                throw new InvalidOperationException($"files/rm failed '{mfsPath}' ({(int)res.StatusCode})");
        }

        private async Task FilesMvAsync(string from, string to, CancellationToken ct)
        {
            var rest = $"/api/v0/files/mv?arg={Uri.EscapeDataString(from)}&arg={Uri.EscapeDataString(to)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode)
                throw new InvalidOperationException($"files/mv failed '{from}' → '{to}' ({(int)res.StatusCode})");
        }

        private async Task EnsureFolderAsync(string mfsPath, CancellationToken ct)
        {
            await IpfsGateway.EnsureMfsFolderExistsAsync(mfsPath, _http);
            _ = await IpfsGateway.GetCidForMfsPathAsync(mfsPath, _http, _cache, TimeSpan.FromHours(1), IpfsGateway.CacheMode.Refresh);
        }

        private async Task PinAddRecursiveAsync(string cid, CancellationToken ct)
        {
            var rest = $"/api/v0/pin/add?arg={Uri.EscapeDataString(cid)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"pin/add failed ({(int)res.StatusCode})");
        }

        private async Task PinRmRecursiveAsync(string cid, CancellationToken ct)
        {
            var rest = $"/api/v0/pin/rm?arg={Uri.EscapeDataString(cid)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"pin/rm failed ({(int)res.StatusCode})");
        }

        private async Task<JsonElement?> ReadLastJsonAsync(HttpResponseMessage res)
        {
            var text = await res.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(text)) return null;

            try { using var doc = JsonDocument.Parse(text); return doc.RootElement.Clone(); }
            catch { }

            foreach (var line in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Reverse())
            {
                var t = line.Trim();
                if (!t.StartsWith("{") || !t.EndsWith("}")) continue;
                try { using var doc = JsonDocument.Parse(t); return doc.RootElement.Clone(); } catch { }
            }
            return null;
        }

        private async Task<int> ComputeNextVersionAsync(string name, CancellationToken ct)
        {
            var children = await ListMfsChildrenAsync(ManagedRoot, ct);
            var prefix = $"{name}-v";
            var max = 0;
            foreach (var k in children.Keys)
            {
                if (!k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                var m = VersionRx.Match(k);
                if (m.Success && int.TryParse(m.Groups["n"].Value, out var n))
                    max = Math.Max(max, n);
            }
            return max + 1;
        }

        private async Task RemoveAllButLatestAsync(string name, CancellationToken ct)
        {
            var children = await ListMfsChildrenAsync(ManagedRoot, ct);
            var prefix = $"{name}-v";
            var versions = new List<(int n, string path, string cid)>();
            foreach (var kv in children)
            {
                if (!kv.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                var m = VersionRx.Match(kv.Key);
                if (!m.Success || !int.TryParse(m.Groups["n"].Value, out var n)) continue;
                versions.Add((n, kv.Value.Path, kv.Value.Cid));
            }
            if (versions.Count <= 1) return;

            var latest = versions.OrderByDescending(v => v.n).First();
            foreach (var v in versions.Where(v => v.n != latest.n))
            {
                try
                {
                    await FilesRmRecursiveAsync(v.path, ct);
                    await PinRmRecursiveAsync(v.cid, ct);
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to remove old version {Name}-v{Version}.", name, v.n);
                }
            }
        }

        private async Task CleanupStagingAsync(CancellationToken ct)
        {
            // Wipe and recreate staging; safe because we only ever put transient data here.
            try { await FilesRmRecursiveAsync(StagingRoot, ct); } catch { }
            try { await EnsureFolderAsync(StagingRoot, ct); } catch { }
        }

        private async Task<Dictionary<string, (string Cid, string Path)>> ListMfsChildrenAsync(string parent, CancellationToken ct)
        {
            parent = IpfsGateway.NormalizeMfs(parent);
            var rest = $"/api/v0/files/ls?arg={Uri.EscapeDataString(parent)}&long=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            var dict = new Dictionary<string, (string Cid, string Path)>(StringComparer.OrdinalIgnoreCase);
            if (!res.IsSuccessStatusCode) return dict;

            var el = await ReadLastJsonAsync(res);
            if (el is null) return dict;
            if (el.Value.TryGetProperty("Entries", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in arr.EnumerateArray())
                {
                    var name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
                    var cid = e.TryGetProperty("Hash", out var h) ? h.GetString() ?? "" : "";
                    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(cid)) continue;
                    var path = IpfsGateway.NormalizeMfs($"{parent}/{name}");
                    dict[name] = (cid, path);
                }
            }
            return dict;
        }

        private async Task TryProvideAsync(string cid, CancellationToken ct)
        {
            try
            {
                // Not all Kubo builds expose routing/provide; ignore failures.
                var rest = $"/api/v0/routing/provide?arg={Uri.EscapeDataString(cid)}";
                using var _ = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            }
            catch { /* ignore */ }
        }

        // Bounded concurrency helper (awaits all while honoring _globalSlots inside each ProcessOneAsync)
        private static async Task WhenAllBounded(IEnumerable<Task> tasks, CancellationToken ct)
        {
            // Just await them all; each ProcessOneAsync grabs/releases _globalSlots.
            await Task.WhenAll(tasks);
        }
    }
}

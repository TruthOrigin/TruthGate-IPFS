using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using TruthGate_Web.Services;

namespace TruthGate_Web.Configuration
{
    public enum SslDecisionKind
    {
        SelfSigned,
        NoneFailTls,
        RealIfPresent
    }

    public interface IAcmeIssuerLabel
    {
        string Label { get; }
    }

    public readonly record struct SslDecision(SslDecisionKind Kind);

    public sealed class LiveCertProvider
    {
        private static readonly SemaphoreSlim _throttle = new(2);
        private readonly ConcurrentDictionary<string, Task> _inflight =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, (DateTimeOffset until, int failures)> _cooldown =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly SelfSignedCertCache _self;
        private readonly ICertificateStore _store;
        private readonly IAcmeIssuer _acme;
        private readonly IConfigService _config;
        private readonly ILogger<LiveCertProvider>? _log;
        private readonly string _acmeLabel;

        public LiveCertProvider(
            SelfSignedCertCache self,
            ICertificateStore store,
            IAcmeIssuer acme,
            IConfigService config,
            ILogger<LiveCertProvider>? log = null)
        {
            _self = self;
            _store = store;
            _acme = acme;
            _config = config;
            _log = log;
            _acmeLabel = (acme as IAcmeIssuerLabel)?.Label ?? "unknown";
        }

        // ---------- IPNS wildcard base helpers ----------

        private (string? baseHost, bool enabled) GetIpnsWildcardBase()
        {
            var w = _config.Get().IpnsWildCardSubDomain;
            if (w is null) return (null, false);

            var baseHost = (w.WildCardSubDomain ?? "").Trim().ToLowerInvariant();
            var useSsl = bool.TryParse(w.UseSSL, out var ok) && ok;

            if (string.IsNullOrWhiteSpace(baseHost) || !useSsl) return (null, false);
            return (baseHost, true);
        }

        private static string? LeftLabel(string host)
        {
            host = (host ?? "").Trim().ToLowerInvariant();
            var ix = host.IndexOf('.');
            if (ix <= 0) return null;
            return host[..ix];
        }

        private bool IsAuthorizedIpnsStarishHost(string host)
        {
            host = (host ?? "").Trim().ToLowerInvariant();
            var (baseHost, enabled) = GetIpnsWildcardBase();
            if (!enabled || baseHost is null) return false;

            if (!(host == baseHost || host.EndsWith("." + baseHost, StringComparison.OrdinalIgnoreCase)))
                return false;

            var left = LeftLabel(host);
            if (left is null) return false;

            var cfg = _config.Get();
            var authorized = cfg.Domains
                .Where(d => bool.TryParse(d.UseSSL, out var ok) && ok)
                .Select(d => new { d.IpnsPeerId, d.IpnsKeyName });

            foreach (var a in authorized)
            {
                if (!string.IsNullOrWhiteSpace(a.IpnsPeerId) &&
                    string.Equals(left, a.IpnsPeerId.Trim(), StringComparison.OrdinalIgnoreCase))
                    return true;

                if (!string.IsNullOrWhiteSpace(a.IpnsKeyName) &&
                    string.Equals(left, a.IpnsKeyName.Trim(), StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }


        /// <summary>
        /// Main decision including star-ish ipns hosts.
        /// </summary>
        public SslDecision DecideForHostIncludingStarish(string host)
        {
            host = (host ?? "").Trim().ToLowerInvariant();

            // 1) Exact configured domain
            var cfg = _config.Get();
            var match = cfg.Domains.FirstOrDefault(d =>
                string.Equals(d.Domain?.Trim(), host, StringComparison.OrdinalIgnoreCase));

            if (match is not null)
            {
                var useSsl = bool.TryParse(match.UseSSL, out var ok) && ok;
                return useSsl ? new SslDecision(SslDecisionKind.RealIfPresent)
                              : new SslDecision(SslDecisionKind.NoneFailTls);
            }

            // 2) Authorized ipns star-ish subdomain
            if (IsAuthorizedIpnsStarishHost(host))
                return new SslDecision(SslDecisionKind.RealIfPresent);

            // 3) Fallback
            return new SslDecision(SslDecisionKind.SelfSigned);
        }

        // ---------- Load / Queue using EXACT host as the cert key ----------

        // in LiveCertProvider fields
        private readonly ConcurrentDictionary<string, (X509Certificate2 cert, DateTimeOffset notAfter)> _issuedCache
            = new(StringComparer.OrdinalIgnoreCase);

        private static bool IsExpiringSoon(DateTimeOffset notAfter)
            => (notAfter - DateTimeOffset.UtcNow) <= TimeSpan.FromDays(30);

        // util
        private static DateTimeOffset? TryGetNotAfter(X509Certificate2 c)
            => DateTimeOffset.TryParse(c.GetExpirationDateString(), out var d) ? d : null;

        // replace TryLoadIssued(...) with:
        public X509Certificate2? TryLoadIssued(string exactHostKey)
        {
            // 1) cache
            if (_issuedCache.TryGetValue(exactHostKey, out var entry))
            {
                if (!IsExpiringSoon(entry.notAfter))
                    return entry.cert;
                // drop expiring
                _issuedCache.TryRemove(exactHostKey, out _);
            }

            // 2) disk
            var cert = _store.LoadAsync(exactHostKey, CancellationToken.None).GetAwaiter().GetResult();
            if (cert is null) return null;

            var notAfter = TryGetNotAfter(cert);
            if (notAfter is null || IsExpiringSoon(notAfter.Value))
                return null;

            _issuedCache[exactHostKey] = (cert, notAfter.Value);
            return cert;
        }


        public bool TryQueueIssueIfMissing(string exactHostKey)
        {
            var decision = DecideForHostIncludingStarish(exactHostKey);
            if (decision.Kind != SslDecisionKind.RealIfPresent)
                return false;

            var key = (exactHostKey ?? "").Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(key)) return false;

            // Cooldown guard
            if (_cooldown.TryGetValue(key, out var cd) && DateTimeOffset.UtcNow < cd.until)
            {
                _log?.LogWarning("[TLS] {Key} in cooldown until {Until} (failures={Fails}), skip queue",
                    key, cd.until, cd.failures);
                return false;
            }

            // De-dupe
            if (_inflight.ContainsKey(key))
            {
                _log?.LogInformation("[TLS] {Key} already issuing on {Label}, skip re-queue", key, _acmeLabel);
                return false;
            }

            _inflight[key] = Task.Run(async () =>
            {
                try
                {
                    var existing = await _store.LoadAsync(key, CancellationToken.None);
                    var need = existing is null || IsCloseToExpiry(existing);
                    if (!need)
                    {
                        _log?.LogInformation("[TLS] {Key} has fresh PFX; no issuance needed", key);
                        return;
                    }

                    await _throttle.WaitAsync();
                    try
                    {
                        _log?.LogInformation("[TLS] [{Label}] issuing/renewing {Key}...", _acmeLabel, key);
                        var issued = await _acme.IssueOrRenewAsync(key, CancellationToken.None);
                        if (issued is not null)
                        {
                            await _store.SaveAsync(key, issued, CancellationToken.None);
                            _cooldown.TryRemove(key, out _);
                            _log?.LogInformation("[TLS] [{Label}] saved new PFX for {Key}", _acmeLabel, key);
                        }
                        else
                        {
                            RegisterFailure(key);
                        }
                    }
                    finally { _throttle.Release(); }
                }
                catch (Exception ex)
                {
                    _log?.LogError(ex, "[TLS] [{Label}] issuance failed for {Key}", _acmeLabel, key);
                    RegisterFailure(key);
                }
                finally
                {
                    _inflight.TryRemove(key, out _);
                }
            });

            return true;
        }

        public void QueueIssueIfMissing(string host) => TryQueueIssueIfMissing(host);

        // ---------- Other helpers ----------

        public X509Certificate2 GetSelfSigned() => _self.Get();

        // Legacy exact-match decision (kept if other code calls it)
        public SslDecision DecideForHost(string host)
        {
            var cfg = _config.Get();
            var match = cfg.Domains.FirstOrDefault(d =>
                string.Equals(d.Domain?.Trim(), host, StringComparison.OrdinalIgnoreCase));
            if (match is null) return new SslDecision(SslDecisionKind.SelfSigned);
            var useSsl = bool.TryParse(match.UseSSL, out var ok) && ok;
            return useSsl ? new SslDecision(SslDecisionKind.RealIfPresent)
                          : new SslDecision(SslDecisionKind.NoneFailTls);
        }

        public bool IsInFlight(string host) => _inflight.ContainsKey((host ?? "").Trim().ToLowerInvariant());

        private void RegisterFailure(string key)
        {
            var next = _cooldown.AddOrUpdate(key,
                _ => (DateTimeOffset.UtcNow.AddMinutes(1), 1),
                (_, prev) =>
                {
                    var failures = Math.Min(prev.failures + 1, 5);
                    var minutes = failures switch { 1 => 1, 2 => 5, 3 => 15, 4 => 30, _ => 60 };
                    return (DateTimeOffset.UtcNow.AddMinutes(minutes), failures);
                });

            _log?.LogWarning("[TLS] {Key} cooldown until {Until} (failures={Fails})",
                key, next.until, next.failures);
        }

        private static bool IsCloseToExpiry(X509Certificate2 cert)
        {
            if (!DateTimeOffset.TryParse(cert.GetExpirationDateString(), out var notAfter)) return false;
            return (notAfter - DateTimeOffset.UtcNow) <= TimeSpan.FromDays(30);
        }

        // Debug
        public object GetCooldownSnapshot(string host)
        {
            host = (host ?? "").Trim().ToLowerInvariant();
            if (_cooldown.TryGetValue(host, out var cd))
                return new { host, coolingDown = DateTimeOffset.UtcNow < cd.until, until = cd.until, failures = cd.failures };
            return new { host, coolingDown = false, failures = 0 };
        }

        // Enumerate star-ish hosts to pre-issue at startup / renew in watcher
        public IEnumerable<string> EnumerateAuthorizedIpnsHosts()
        {
            var (baseHost, enabled) = GetIpnsWildcardBase();
            if (!enabled || baseHost is null) yield break;

            var cfg = _config.Get();
            foreach (var d in cfg.Domains.Where(d => bool.TryParse(d.UseSSL, out var ok) && ok))
            {
                var ids = new[]
                {
            d.IpnsPeerId?.Trim(),
            d.IpnsKeyName?.Trim()
        }
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct(StringComparer.OrdinalIgnoreCase);

                foreach (var left in ids)
                    yield return $"{left!.ToLowerInvariant()}.{baseHost}";
            }
        }

    }
}

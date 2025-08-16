using Certes.Pkcs;
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


    public readonly record struct SslDecision(SslDecisionKind Kind);

    public sealed class LiveCertProvider
    {
        // inside LiveCertProvider class:
        private readonly ConcurrentDictionary<string, Task> _inflight = new(StringComparer.OrdinalIgnoreCase);

        public void QueueIssueIfMissing(string host)
        {
            // de-dupe concurrent kicks per host
            _inflight.GetOrAdd(host, h => Task.Run(async () =>
            {
                try
                {
                    var existing = await _store.LoadAsync(h, CancellationToken.None);
                    var need = existing is null || IsCloseToExpiry(existing);
                    if (!need) return;

                    var issued = await _acme.IssueOrRenewAsync(h, CancellationToken.None);
                    if (issued is not null)
                        await _store.SaveAsync(h, issued, CancellationToken.None);
                }
                catch
                {
                    // swallow/log if you have ILogger; the watcher or next hit will retry
                }
                finally
                {
                    _inflight.TryRemove(h, out _);
                }
            }));
        }

        private readonly SelfSignedCertCache _self;
        private readonly ICertificateStore _store;
        private readonly IAcmeIssuer _acme;
        private readonly IConfigService _config;
        private readonly ConcurrentDictionary<string, Lazy<Task<X509Certificate2?>>> _cache = new();

        public LiveCertProvider(SelfSignedCertCache self, ICertificateStore store, IAcmeIssuer acme, IConfigService config)
        {
            _self = self; _store = store; _acme = acme; _config = config;
        }

        // --- Used by ServerCertificateSelector path
        public X509Certificate2 GetSelfSigned() => _self.Get();

        public SslDecision DecideForHost(string host)
        {
            var cfg = _config.Get();
            var match = cfg.Domains.FirstOrDefault(d => string.Equals(d.Domain?.Trim(), host, StringComparison.OrdinalIgnoreCase));

            if (match is null)
                return new SslDecision(SslDecisionKind.SelfSigned); // unknown host/IP

            var useSsl = bool.TryParse(match.UseSSL, out var ok) && ok;
            if (!useSsl)
                return new SslDecision(SslDecisionKind.NoneFailTls);

            return new SslDecision(SslDecisionKind.RealIfPresent);
        }

        public X509Certificate2? TryLoadIssued(string host)
        {
            try
            {
                var cert = _store.LoadAsync(host, CancellationToken.None).GetAwaiter().GetResult();
                if (cert is null) return null;
                if (IsCloseToExpiry(cert)) return null; // force renew; handshake may fail until renewed
                return cert;
            }
            catch
            {
                return null;
            }
        }

        // --- Async path (kept for completeness; not used by the selector block)
        public async Task<X509Certificate2?> TryGetServerCertificateAsync(string? sni, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(sni) || IPAddress.TryParse(sni, out _))
                return _self.Get();

            var cfg = _config.Get();
            var match = cfg.Domains.FirstOrDefault(d => string.Equals(d.Domain, sni, StringComparison.OrdinalIgnoreCase));
            if (match is null) return _self.Get();

            if (!bool.TryParse(match.UseSSL, out var useSsl) || !useSsl)
                return null;

            var key = sni.ToLowerInvariant();
            var lazy = _cache.GetOrAdd(key, host => new Lazy<Task<X509Certificate2?>>(async () =>
            {
                var onDisk = await _store.LoadAsync(host, ct);
                if (onDisk is { } existing && !IsCloseToExpiry(existing)) return existing;

                var fresh = await _acme.IssueOrRenewAsync(host, ct);
                if (fresh is { }) await _store.SaveAsync(host, fresh, ct);
                return fresh;
            }));

            try { return await lazy.Value; }
            finally
            {
                if (lazy.Value.IsFaulted || lazy.Value.IsCanceled)
                    _cache.TryRemove(key, out _);
            }
        }

        private static bool IsCloseToExpiry(X509Certificate2 cert)
        {
            if (!DateTimeOffset.TryParse(cert.GetExpirationDateString(), out var notAfter))
                return false;
            return (notAfter - DateTimeOffset.UtcNow) <= TimeSpan.FromDays(30);
        }
    }
}

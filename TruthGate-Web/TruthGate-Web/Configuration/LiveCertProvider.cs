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
        private static readonly SemaphoreSlim _throttle = new(2); // at most 2 issuances at a time

        private readonly ConcurrentDictionary<string, Task> _inflight = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, (DateTimeOffset until, int failures)> _cooldown =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly SelfSignedCertCache _self;
        private readonly ICertificateStore _store;
        private readonly IAcmeIssuer _acme;
        private readonly IConfigService _config;
        private readonly ILogger<LiveCertProvider>? _log;

        public LiveCertProvider(SelfSignedCertCache self, ICertificateStore store, IAcmeIssuer acme, IConfigService config, ILogger<LiveCertProvider>? log = null)
        {
            _self = self; _store = store; _acme = acme; _config = config; _log = log;
        }

        public X509Certificate2 GetSelfSigned() => _self.Get();

        public SslDecision DecideForHost(string host)
        {
            var cfg = _config.Get();
            var match = cfg.Domains.FirstOrDefault(d => string.Equals(d.Domain?.Trim(), host, StringComparison.OrdinalIgnoreCase));
            if (match is null) return new SslDecision(SslDecisionKind.SelfSigned);
            var useSsl = bool.TryParse(match.UseSSL, out var ok) && ok;
            return useSsl ? new SslDecision(SslDecisionKind.RealIfPresent) : new SslDecision(SslDecisionKind.NoneFailTls);
        }

        public X509Certificate2? TryLoadIssued(string host)
        {
            try
            {
                var cert = _store.LoadAsync(host, CancellationToken.None).GetAwaiter().GetResult();
                if (cert is null) return null;
                if (IsCloseToExpiry(cert)) return null;
                return cert;
            }
            catch (Exception ex)
            {
                _log?.LogWarning(ex, "[TLS] TryLoadIssued({Host}) failed", host);
                return null;
            }
        }

        public void QueueIssueIfMissing(string host)
        {
            host = host.Trim().ToLowerInvariant();

            // Respect cooldown
            if (_cooldown.TryGetValue(host, out var cd) && DateTimeOffset.UtcNow < cd.until)
            {
                _log?.LogWarning("[TLS] {Host} in cooldown until {Until}, skipping queue", host, cd.until);
                return;
            }

            _inflight.GetOrAdd(host, _ => Task.Run(async () =>
            {
                try
                {
                    var existing = await _store.LoadAsync(host, CancellationToken.None);
                    var need = existing is null || IsCloseToExpiry(existing);
                    if (!need) { _log?.LogInformation("[TLS] {Host} already has fresh PFX", host); return; }

                    await _throttle.WaitAsync(); // global concurrency guard
                    try
                    {
                        _log?.LogInformation("[TLS] Issuing/renewing {Host}...");
                        var issued = await _acme.IssueOrRenewAsync(host, CancellationToken.None);
                        if (issued is not null)
                        {
                            await _store.SaveAsync(host, issued, CancellationToken.None);
                            (DateTimeOffset until, int failures) removedCooldown;
                            _cooldown.TryRemove(host, out removedCooldown);  // reset backoff
                            _log?.LogInformation("[TLS] Saved new PFX for {Host}", host);
                        }
                        else
                        {
                            RegisterFailure(host);
                        }
                    }
                    finally { _throttle.Release(); }
                }
                catch (Exception ex)
                {
                    _log?.LogError(ex, "[TLS] Issuance failed for {Host}", host);
                    RegisterFailure(host);
                }
                finally
                {
                    Task removedTask;
                    _inflight.TryRemove(host, out removedTask);
                }
            }));
        }

        private void RegisterFailure(string host)
        {
            var next = _cooldown.AddOrUpdate(host,
                _ => (DateTimeOffset.UtcNow.AddMinutes(1), 1),
                (_, prev) =>
                {
                    var failures = Math.Min(prev.failures + 1, 5);
                    var minutes = failures switch { 1 => 1, 2 => 5, 3 => 15, 4 => 30, _ => 60 };
                    return (DateTimeOffset.UtcNow.AddMinutes(minutes), failures);
                });

            _log?.LogWarning("[TLS] {Host} cooldown set until {Until} (failures={Fails})", host, next.until, next.failures);
        }

        private static bool IsCloseToExpiry(X509Certificate2 cert)
        {
            if (!DateTimeOffset.TryParse(cert.GetExpirationDateString(), out var notAfter)) return false;
            return (notAfter - DateTimeOffset.UtcNow) <= TimeSpan.FromDays(30);
        }
    }

}

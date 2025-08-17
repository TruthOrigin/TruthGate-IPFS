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

    public interface IAcmeIssuerLabel
    {
        string Label { get; }
    }

    public readonly record struct SslDecision(SslDecisionKind Kind);

    public sealed class LiveCertProvider
    {
        private static readonly SemaphoreSlim _throttle = new(2);
        private readonly ConcurrentDictionary<string, Task> _inflight = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, (DateTimeOffset until, int failures)> _cooldown =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly SelfSignedCertCache _self;
        private readonly ICertificateStore _store;
        private readonly IAcmeIssuer _acme;
        private readonly IConfigService _config;
        private readonly ILogger<LiveCertProvider>? _log;

        // Optional: label so your logs show which ACME dir (prod/staging) you're on
        private readonly string _acmeLabel;

        public LiveCertProvider(
            SelfSignedCertCache self,
            ICertificateStore store,
            IAcmeIssuer acme,
            IConfigService config,
            ILogger<LiveCertProvider>? log = null)
        {
            _self = self; _store = store; _acme = acme; _config = config; _log = log;
            _acmeLabel = (acme as IAcmeIssuerLabel)?.Label ?? "unknown";
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

        // --- NEW: quick check used by the TLS selector to avoid noisy re-queues
        public bool IsInFlight(string host) => _inflight.ContainsKey(host.Trim().ToLowerInvariant());

        // --- NEW: returns false if skipped due to cooldown/inflight, true if actually queued
        public bool TryQueueIssueIfMissing(string host)
        {
            host = host.Trim().ToLowerInvariant();

            // cool-down guard
            if (_cooldown.TryGetValue(host, out var cd) && DateTimeOffset.UtcNow < cd.until)
            {
                _log?.LogWarning("[TLS] {Host} in cooldown until {Until} (failures={Fails}), skip queue", host, cd.until, cd.failures);
                return false;
            }

            // de-dupe: if already in-flight, don't re-enqueue
            if (_inflight.ContainsKey(host))
            {
                _log?.LogInformation("[TLS] {Host} already issuing on {_acmeLabel}, skip re-queue", host, _acmeLabel);
                return false;
            }

            _inflight[host] = Task.Run(async () =>
            {
                try
                {
                    var existing = await _store.LoadAsync(host, CancellationToken.None);
                    var need = existing is null || IsCloseToExpiry(existing);
                    if (!need) { _log?.LogInformation("[TLS] {Host} has fresh PFX; no issuance needed", host); return; }

                    await _throttle.WaitAsync();
                    try
                    {
                        _log?.LogInformation("[TLS] [{Label}] issuing/renewing {Host}...", _acmeLabel, host);
                        var issued = await _acme.IssueOrRenewAsync(host, CancellationToken.None);
                        if (issued is not null)
                        {
                            await _store.SaveAsync(host, issued, CancellationToken.None);
                            (DateTimeOffset, int) removed;
                            _cooldown.TryRemove(host, out removed); // reset backoff on success
                            _log?.LogInformation("[TLS] [{Label}] saved new PFX for {Host}", _acmeLabel, host);
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
                    _log?.LogError(ex, "[TLS] [{Label}] issuance failed for {Host}", _acmeLabel, host);
                    RegisterFailure(host);
                }
                finally
                {
                    Task removedTask;
                    _inflight.TryRemove(host, out removedTask);
                }
            });

            return true;
        }

        // Keep original method signature if other code calls it
        public void QueueIssueIfMissing(string host) => TryQueueIssueIfMissing(host);

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

        // --- OPTIONAL: tiny introspection for debugging
        public object GetCooldownSnapshot(string host)
        {
            host = (host ?? "").Trim().ToLowerInvariant();
            if (_cooldown.TryGetValue(host, out var cd))
                return new { host, coolingDown = DateTimeOffset.UtcNow < cd.until, until = cd.until, failures = cd.failures };
            return new { host, coolingDown = false, failures = 0 };
        }
    }
}

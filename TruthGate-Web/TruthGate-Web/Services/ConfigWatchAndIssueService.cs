using System.Security.Cryptography.X509Certificates;
using TruthGate_Web.Configuration;

namespace TruthGate_Web.Services
{
    public sealed class ConfigWatchAndIssueService : BackgroundService
    {
        private readonly IConfigService _config;
        private readonly IAcmeIssuer _acme;
        private readonly ICertificateStore _store;

        public ConfigWatchAndIssueService(IConfigService config, IAcmeIssuer acme, ICertificateStore store)
        {
            _config = config; _acme = acme; _store = store;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var lastSnapshot = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var cfg = _config.Get();
                    var want = cfg.Domains
                        .Where(d => bool.TryParse(d.UseSSL, out var ok) && ok)
                        .Select(d => (d.Domain ?? "").Trim().ToLowerInvariant())
                        .Where(d => !string.IsNullOrWhiteSpace(d))
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);

                    foreach (var host in want.Except(lastSnapshot))
                        await EnsureIssued(host, stoppingToken);

                    foreach (var host in want)
                    {
                        var exist = await _store.LoadAsync(host, stoppingToken);
                        if (exist is null || IsCloseToExpiry(exist))
                            await EnsureIssued(host, stoppingToken);
                    }

                    lastSnapshot = want;
                }
                catch
                {
                    // log if you want
                }

                await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);
            }

            static bool IsCloseToExpiry(X509Certificate2 cert)
            {
                if (!DateTimeOffset.TryParse(cert.GetExpirationDateString(), out var notAfter))
                    return false;
                return (notAfter - DateTimeOffset.UtcNow) <= TimeSpan.FromDays(30);
            }
        }

        private async Task EnsureIssued(string host, CancellationToken ct)
        {
            var cert = await _acme.IssueOrRenewAsync(host, ct);
            if (cert is not null)
                await _store.SaveAsync(host, cert, ct);
        }
    }

}

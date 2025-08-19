using System.Security.Cryptography.X509Certificates;
using TruthGate_Web.Configuration;

namespace TruthGate_Web.Services
{
    public sealed class ConfigWatchAndIssueService : BackgroundService
    {
        private readonly IConfigService _config;
        private readonly LiveCertProvider _live;

        public ConfigWatchAndIssueService(IConfigService config, LiveCertProvider live)
        {
            _config = config;
            _live = live;
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
                        .Where(h => !string.IsNullOrWhiteSpace(h))
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);

                    // Add authorized star-ish ipns names
                    foreach (var h in _live.EnumerateAuthorizedIpnsHosts())
                        want.Add(h);

                    foreach (var host in want.Except(lastSnapshot))
                        _live.TryQueueIssueIfMissing(host);

                    foreach (var host in want)
                        _live.TryQueueIssueIfMissing(host);

                    lastSnapshot = want;
                }
                catch
                {
                    // optional: log
                }

                await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);
            }
        }
    }

}

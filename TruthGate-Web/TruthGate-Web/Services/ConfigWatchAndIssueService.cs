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

                    // Domains where UseSSL == true
                    var want = cfg.Domains
                        .Where(d => bool.TryParse(d.UseSSL, out var ok) && ok)
                        .Select(d => (d.Domain ?? "").Trim().ToLowerInvariant())
                        .Where(h => !string.IsNullOrWhiteSpace(h))
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);

                    // 1) New hosts since last pass → queue if needed
                    foreach (var host in want.Except(lastSnapshot))
                        _live.TryQueueIssueIfMissing(host);

                    // 2) All wanted hosts → queue if missing/expiring (provider will no-op if fresh)
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

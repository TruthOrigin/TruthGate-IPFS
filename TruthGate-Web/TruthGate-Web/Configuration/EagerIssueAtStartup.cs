using TruthGate_Web.Services;

namespace TruthGate_Web.Configuration
{
    public sealed class EagerIssueAtStartup : IHostedService
    {
        private readonly IConfigService _config;
        private readonly LiveCertProvider _live;

        public EagerIssueAtStartup(IConfigService cfg, LiveCertProvider live)
        {
            _config = cfg; _live = live;
        }

        public Task StartAsync(CancellationToken ct)
        {
            var cfg = _config.Get();
            var hosts = cfg.Domains
                .Where(d => bool.TryParse(d.UseSSL, out var ok) && ok)
                .Select(d => (d.Domain ?? "").Trim().ToLowerInvariant())
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Distinct();

            foreach (var h in hosts)
                _live.QueueIssueIfMissing(h);

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
    }

}

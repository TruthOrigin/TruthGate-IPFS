using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using TruthGate_Web.Security;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Services
{
    public sealed class RateLimiterFlushWorker : BackgroundService
    {
        private readonly RateLimiterService _svc;
        private readonly ILogger<RateLimiterFlushWorker> _log;

        public RateLimiterFlushWorker(IRateLimiterService svc, ILogger<RateLimiterFlushWorker> log)
        { _svc = (RateLimiterService)svc; _log = log; }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await _svc.FlushAsync(); }
                catch (Exception ex) { _log.LogError(ex, "RateLimiter flush loop error"); }
                await Task.Delay(TimeSpan.FromSeconds(7), stoppingToken); // 5–10s window
            }
        }
    }

    public sealed class RateLimiterPurgeWorker : BackgroundService
    {
        private readonly IDbContextFactory<RateLimiterDbContext> _dbf;
        private readonly IOptions<RateLimiterOptions> _opt;
        private readonly ILogger<RateLimiterPurgeWorker> _log;

        public RateLimiterPurgeWorker(IDbContextFactory<RateLimiterDbContext> dbf, IOptions<RateLimiterOptions> opt, ILogger<RateLimiterPurgeWorker> log)
        { _dbf = dbf; _opt = opt; _log = log; }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await using var db = await _dbf.CreateDbContextAsync();
                    var now = DateTimeOffset.UtcNow;
                    var older = now.AddDays(-_opt.Value.Retention.PurgeOlderThanDays);
                    var expiredBansOlder = now.AddDays(-_opt.Value.Retention.PurgeExpiredBanAfterDays);

                    await db.Database.ExecuteSqlRawAsync($"DELETE FROM IpMinuteCounters WHERE MinuteBucket < '{TimeUtils.MinuteBucketUtc(older)}'");
                    await db.Database.ExecuteSqlRawAsync($"DELETE FROM GlobalMinuteCounters WHERE MinuteBucket < '{TimeUtils.MinuteBucketUtc(older)}'");
                    await db.Database.ExecuteSqlRawAsync($"DELETE FROM Bans WHERE ExpiresUtc < '{expiredBansOlder.UtcDateTime:O}'");
                    await db.Database.ExecuteSqlRawAsync($"DELETE FROM GracePairs WHERE ExpiresUtc < '{now.UtcDateTime:O}'");
                    await db.Database.ExecuteSqlRawAsync($"DELETE FROM Whitelists WHERE ExpiresUtc IS NOT NULL AND ExpiresUtc < '{now.UtcDateTime:O}'");

                    // occasional VACUUM could be triggered externally or here conditionally
                }
                catch (Exception ex) { _log.LogError(ex, "RateLimiter purge loop error"); }

                await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
            }
        }
    }
}

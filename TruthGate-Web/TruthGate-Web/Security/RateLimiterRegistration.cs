using TruthGate_Web.Middleware;
using TruthGate_Web.Services;
using Microsoft.EntityFrameworkCore;

namespace TruthGate_Web.Security
{
    public static class RateLimiterRegistration
    {
        public static IServiceCollection AddTruthGateRateLimiter(
            this IServiceCollection services,
            string? connectionString = null)
        {
            services.AddDbContextFactory<RateLimiterDbContext>((sp, b) =>
            {
                // Safe to resolve dependencies here
                var cfg = sp.GetRequiredService<IConfigService>();
                var tet = cfg.Get();
                // Figure out SQLite location from cfg.ConfigPath (directory portion)
                var dir = Path.GetDirectoryName(cfg.ConfigPath) ?? AppContext.BaseDirectory;
                Directory.CreateDirectory(dir);
                var dbPath = Path.Combine(dir, "ratelimiter.db");
                var cs = connectionString ?? $"Data Source={dbPath};Cache=Shared";

                b.UseSqlite(cs);
                b.EnableSensitiveDataLogging(false);
            });


            services.AddSingleton<IRateLimiterService, RateLimiterService>();
            services.AddHostedService<RateLimiterFlushWorker>();
            services.AddHostedService<RateLimiterPurgeWorker>();

            // Don't re-Configure<RateLimiterOptions> here; the app already did it.
            return services;
        }

        public static IApplicationBuilder UseTruthGateRateLimiter(this IApplicationBuilder app)
            => app.UseMiddleware<RateLimiterMiddleware>();
    }

}

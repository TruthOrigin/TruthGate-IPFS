using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestPlatform.TestHost;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TruthGate_Web.Services;
using TruthGate_Web.Security;
using TruthGate_Web.Middleware;
using TruthGate_Web.Models;

namespace Test.TruthGate
{
    public sealed class TruthGateWebApplicationFactory : WebApplicationFactory<TruthGate_Web.Program>
    {
        private readonly SqliteTestFixture _fx;
        public TruthGateWebApplicationFactory(SqliteTestFixture fx) => _fx = fx;
        public const string ValidAdminKey = "VALID-ADMIN-KEY";
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            // Force the host to treat the web app assembly as the application
            var webAsm = typeof(TruthGate_Web.Program).Assembly;
            var appName = webAsm.GetName().Name!;
            var webAsmDir = Path.GetDirectoryName(webAsm.Location)!;
            var manifest = Path.Combine(webAsmDir, $"{appName}.staticwebassets.endpoints.json");

            // 1) Make the host think the ApplicationName is the web app (not the test project)
            builder.UseSetting(WebHostDefaults.ApplicationKey, appName);

            // 2) Provide the manifest path via host setting (this is what MapStaticAssets reads)
            builder.UseSetting(WebHostDefaults.StaticWebAssetsKey, manifest);

            // 3) Also set the legacy env var (some code paths still read it)
            if (File.Exists(manifest))
                Environment.SetEnvironmentVariable("ASPNETCORE_STATICWEBASSETS", manifest);

            // (optional but nice) make content root the web app’s output dir
            builder.UseContentRoot(webAsmDir);

            // If you guard MapStaticAssets in Program, set Testing env:
            builder.UseEnvironment("Testing");


            builder.ConfigureAppConfiguration((ctx, cfg) =>
            {
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["RateLimiterOptions:Admin:MaxBadKeyPerIpPer24h"] = "3",
                    ["RateLimiterOptions:Admin:GraceDays"] = "7",
                    ["RateLimiterOptions:Public:PerIpPerMinute"] = "6",
                    ["RateLimiterOptions:Public:GlobalTiers:0:Threshold"] = "10",
                    ["RateLimiterOptions:Public:GlobalTiers:0:NewPerMinute"] = "4",
                    ["RateLimiterOptions:Public:GlobalTiers:1:Threshold"] = "20",
                    ["RateLimiterOptions:Public:GlobalTiers:1:NewPerMinute"] = "3",
                    ["RateLimiterOptions:Public:GlobalTiers:2:Threshold"] = "30",
                    ["RateLimiterOptions:Public:GlobalTiers:2:NewPerMinute"] = "2",
                    ["RateLimiterOptions:Gateway:FreePerMinute"] = "8",
                    ["RateLimiterOptions:Gateway:HourlyOverage"] = "16",
                    ["RateLimiterOptions:Gateway:BanOnExhaustion"] = "00:00:06",
                    ["RateLimiterOptions:TlsChurn:Enabled"] = "true",
                    ["RateLimiterOptions:TlsChurn:NewConnectionsPerSec"] = "3",
                    ["RateLimiterOptions:TlsChurn:MinReqPerConn"] = "1.2",
                    ["RateLimiterOptions:TlsChurn:ObserveSeconds"] = "3",
                });
            });

            builder.ConfigureServices(services =>
            {
                services.AddSingleton<IConfigService>(new TestConfigService(_fx.ConfigPath));
                services.AddMemoryCache();



                // New signature: no cfg param
                services.AddTruthGateRateLimiter();


                // Apply EF migrations once
                using var sp = services.BuildServiceProvider();
                using var scope = sp.CreateScope();
                var dbf = scope.ServiceProvider.GetRequiredService<IDbContextFactory<RateLimiterDbContext>>();
                using var db = dbf.CreateDbContext();
                db.Database.Migrate();
            });

            builder.Configure(app =>
            {
                app.Use(async (ctx, next) =>
                {
                    // spoof IP / auth (optional)
                    if (ctx.Request.Headers.TryGetValue("X-Test-IP", out var ip))
                        ctx.Connection.RemoteIpAddress = IPAddress.Parse(ip!);

                    // resolve admin key result for this request
                    var res = KeyValidationResult.Missing;
                    if (ctx.Request.Headers.TryGetValue("X-Admin-Key", out var key))
                        res = key == TruthGateWebApplicationFactory.ValidAdminKey
                            ? KeyValidationResult.Valid
                            : KeyValidationResult.Invalid;

                    ctx.Items[RateLimiterConstants.KeyValidationResultItem] = res;

                    await next();
                });


                app.UseGatewayRateProtection();
                app.UseRouting();
                app.UseTruthGateRateLimiter();

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/admin/secret", () => Results.Ok("ok"))
                             .WithMetadata(new AdminProtectedAttribute());

                    endpoints.MapGet("/public/ping", () => Results.Ok("pong"))
                             .WithMetadata(new PublicLimitedAttribute());

                    endpoints.MapGet("/ipfs/{**rest}", (string rest) => Results.Ok($"ipfs:{rest}"));

                    endpoints.MapPost("/_test/flush", async context =>
                    {
                        var svc = (RateLimiterService)context.RequestServices.GetRequiredService<IRateLimiterService>();
                        var mi = typeof(RateLimiterService).GetMethod("FlushAsync",
                            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
                        await (Task)mi.Invoke(svc, null)!;
                        await Results.Ok().ExecuteAsync(context);
                    });

                    endpoints.MapGet("/_test/bans", async context =>
                    {
                        var svc = context.RequestServices.GetRequiredService<IRateLimiterService>();
                        var (items, total) = await svc.GetBansAsync(1, 100);
                        await Results.Json(new { total, items }).ExecuteAsync(context);
                    });
                });
            });
        }


        private sealed class TestConfigService : IConfigService
        {
            public string ConfigPath { get; }
            public TestConfigService(string path) => ConfigPath = path;

            public Task SaveAsync(Config newConfig, CancellationToken ct = default)
            {
                return Task.Delay(1);
            }

            public Task UpdateAsync(Action<Config> mutator, CancellationToken ct = default)
            {
                return Task.Delay(1);
            }

            public Config Get() => new Config();
        }
    }
}

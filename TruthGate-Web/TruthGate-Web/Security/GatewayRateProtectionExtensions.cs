using Microsoft.Extensions.Options;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Security
{
    public static class GatewayRateProtectionExtensions
    {
        public static IApplicationBuilder UseGatewayRateProtection(this IApplicationBuilder app)
        {
            return app.Use(async (ctx, next) =>
            {
                var svc = ctx.RequestServices.GetRequiredService<IRateLimiterService>();
                var opt = ctx.RequestServices.GetRequiredService<IOptions<RateLimiterOptions>>();
                var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("GatewayRateProtection");
                var rl = (RateLimiterService)svc;

                // Whitelist precedence
                var ip = IpUtils.GetClientIpString(ctx);
                if (await svc.IsWhitelistedAsync(ip) || (IpUtils.TryGetIpv6Prefix64(ip, out var pfx) && await svc.IsWhitelistedPrefixAsync(pfx)))
                { await next(); return; }

                // Ban/graylist
                if (svc.IsBanned(ctx))
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await ctx.Response.WriteAsync("Access denied.");
                    return;
                }

                // Admin-key awareness / authenticated users
                var hasAuth = ctx.User?.Identity?.IsAuthenticated == true;
                var key = ExtractApiKey(ctx);
                var keyValid = ctx.Items.TryGetValue(RateLimiterConstants.KeyValidationResultItem, out var o) && o is KeyValidationResult kv && kv == KeyValidationResult.Valid;

                if ((hasAuth || keyValid))
                {
                    if (opt.Value.Gateway.AutoWhitelistOnAuthOrValidKey)
                    {
                        await svc.AddWhitelistIpAsync(ip, reason: "Auto (Gateway auth/key)", expiresUtc: DateTimeOffset.UtcNow.AddDays(7), auto: true);
                    }
                    await svc.RecordSuccessAsync(ctx, key);
                    await next();
                    return;
                }

                // Key present but invalid/missing where route requires → count admin-origin failure
                if (!string.IsNullOrEmpty(key) && !keyValid)
                {
                    await svc.RecordFailureAsync(ctx, key, isAdminScope: true);
                    // fall through to non-api overage model (still counts)
                }

                // Non-API overage model
                // Non-API overage model
                var now = DateTimeOffset.UtcNow;
                rl.TrackTlsChurn(ctx);

                // Compute BEFORE counting this request
                var usage = rl.GetGatewayUsage(ip, now, opt.Value.Gateway.FreePerMinute);
                var overageRemaining = Math.Max(0, opt.Value.Gateway.HourlyOverage - usage.HourOverageUsed);

                // Are we already past the free budget this minute?
                var pastFreeThisMinute = Math.Max(0, usage.MinuteCount - opt.Value.Gateway.FreePerMinute);

                // Would THIS request exceed the remaining overage?
                var wouldExceed = usage.MinuteCount >= opt.Value.Gateway.FreePerMinute
                                  && pastFreeThisMinute >= overageRemaining;

                if (wouldExceed)
                {
                    await using var db = await rl._dbf.CreateDbContextAsync();
                    await rl.AddBanAsync(db, new Ban
                    {
                        Ip = ip,
                        Scope = RateScope.Gateway,
                        Type = BanType.Soft,
                        IsTrueBan = false,
                        ReasonCode = "GATEWAY_OVERAGE_EXHAUSTED",
                        CreatedUtc = now,
                        ExpiresUtc = now.Add(opt.Value.Gateway.BanOnExhaustion)
                    }, cacheOnly: false);

                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await ctx.Response.WriteAsync("Access denied.");
                    return;
                }

                // Safe to count & continue (NOW increment)
                int overageUsed = 0;
                rl.IncGateway(ip, now, opt.Value.Gateway.FreePerMinute, ref overageUsed);
                await next();

            });
        }

        private static string? ExtractApiKey(HttpContext ctx)
        {
            if (ctx.Request.Headers.TryGetValue("X-Admin-Key", out var v) && !StringValuesIsEmpty(v)) return v.ToString();
            if (ctx.Request.Headers.TryGetValue("Authorization", out var auth))
            {
                var s = auth.ToString();
                if (s.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return s.Substring("Bearer ".Length).Trim();
            }
            if (ctx.Request.Query.TryGetValue("key", out var q) && !StringValuesIsEmpty(q)) return q.ToString();
            return null;

            static bool StringValuesIsEmpty(Microsoft.Extensions.Primitives.StringValues sv) => sv.Count == 0 || string.IsNullOrWhiteSpace(sv[0]);
        }
    }
}

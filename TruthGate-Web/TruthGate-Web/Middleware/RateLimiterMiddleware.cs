using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using TruthGate_Web.Security.Models;
using TruthGate_Web.Security;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;
using TruthGate_Web.Models;

namespace TruthGate_Web.Middleware
{

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
    public sealed class AdminProtectedAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
    public sealed class PublicLimitedAttribute : Attribute { }

    public sealed class RateLimiterMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IRateLimiterService _svc;
        private readonly IOptions<RateLimiterOptions> _opt;
        private readonly ILogger<RateLimiterMiddleware> _log;
        private readonly IApiKeyProvider _keys;
        private readonly IConfigService _config;


        public RateLimiterMiddleware(RequestDelegate next, IRateLimiterService svc,
            IOptions<RateLimiterOptions> opt, ILogger<RateLimiterMiddleware> log,
            IApiKeyProvider keys, IConfigService cfg)
        { _next = next; _svc = svc; _opt = opt; _log = log; _keys = keys; _config = cfg; }

        public async Task InvokeAsync(HttpContext ctx)
        {
            var endpoint = ctx.GetEndpoint();
            var isAdmin = endpoint?.Metadata.GetMetadata<AdminProtectedAttribute>() != null;
            var isPublic = endpoint?.Metadata.GetMetadata<PublicLimitedAttribute>() != null;

            // Whitelist → Ban/Graylist → Limits order happens inside service's IsBanned + checks here
            var ip = IpUtils.GetClientIpString(ctx);

            // Whitelist check (fast): service caches whitelists
            if (await _svc.IsWhitelistedAsync(ip) || (IpUtils.TryGetIpv6Prefix64(ip, out var pfx) && await _svc.IsWhitelistedPrefixAsync(pfx)))
            {
                await _next(ctx); return;
            }

            if (_svc.IsBanned(ctx))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsync("Access denied.");
                return;
            }

            if (isAdmin)
            {
                await HandleAdminAsync(ctx);
                return;
            }
            if (isPublic)
            {
                await HandlePublicAsync(ctx);
                return;
            }

            // Not annotated → just pass-through; Gateway protection is handled by UseGatewayRateProtection extension.
            await _next(ctx);
        }

        private async Task HandleAdminAsync(HttpContext ctx)
        {
            // AdminApiKeyOnlyFilter should have set HttpContext.Items[KeyValidationResult]
            var res = ctx.Items.TryGetValue(RateLimiterConstants.KeyValidationResultItem, out var o) && o is KeyValidationResult kv
                ? kv
                : KeyValidationResult.Missing;

            if (res == KeyValidationResult.Valid)
            {
                // Optional per-key soft ceiling (off by default).
                if (_opt.Value.Admin.EnablePerKeyCeiling)
                {
                    // Placeholder for per-key ceiling logic; currently no-op (alert-only).
                }

                // Grace refresh on success (persist & cache).
                string? presentedKey = ExtractApiKey(ctx);
                await _svc.RecordSuccessAsync(ctx, presentedKey);
                await _next(ctx);
                return;
            }

            bool keyAccepted = false;

            string? providedKey = ExtractApiKey(ctx);

            var cfg = _config.Get();
            var keys = cfg.ApiKeys ?? new List<ApiKey>();

            if (!string.IsNullOrWhiteSpace(providedKey))
            {
                // (a) any stored hashed key that verifies
                if (keys.Count > 0 && keys.Any(k =>
                    !string.IsNullOrWhiteSpace(k?.KeyHashed) &&
                    StringHasher.VerifyHash(providedKey!, k.KeyHashed)))
                {
                    keyAccepted = true;
                }
                // (b) OR the current in-memory key
                else if (_keys.IsValid(providedKey))
                {
                    keyAccepted = true;
                }
            }

            // 3) If key not accepted, allow cookie-authenticated users
            bool isAuthed = ctx.User?.Identity?.IsAuthenticated ?? false;

            if (keyAccepted || isAuthed)
            {
                await _svc.RecordSuccessAsync(ctx, providedKey);
                await _next(ctx);
                return;
            }

            if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(ctx))
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                await ctx.Response.WriteAsync("Unauthorized.");
                return;
            }

            // but do NOT check/apply the ban here. The next request will hit the ban at the top of the pipeline.
            await _svc.RecordFailureAsync(ctx, ExtractApiKey(ctx), isAdminScope: true);
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsync("Unauthorized.");
            return;
        }


        private async Task HandlePublicAsync(HttpContext ctx)
        {
            var svc = (RateLimiterService)_svc;
            var now = DateTimeOffset.UtcNow;
            var ip = IpUtils.GetClientIpString(ctx);

            // Global minute totals to determine tier
            var totalLastHour = svc.GetGlobalLastHourTotal(now);
            var perMinute = _opt.Value.Public.PerIpPerMinute;
            foreach (var (threshold, newPm) in _opt.Value.Public.GlobalTiers.OrderBy(x => x.Threshold))
            {
                if (totalLastHour >= threshold) perMinute = newPm;
            }

            // Current minute count for this IP (PublicCalls)
            var bucket = TimeUtils.MinuteBucketUtc(now);
            var acc = svc.GetType().GetField("_ipMinute", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
                .GetValue(svc) as ConcurrentDictionary<(string, string), MinuteAccumulator>;
            var global = svc.GetType().GetField("_globalMinute", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
                .GetValue(svc) as ConcurrentDictionary<string, GlobalAccumulator>;

            var m = acc!.GetOrAdd((ip, bucket), _ => new MinuteAccumulator());
            var current = m.PublicCalls;

            // If the next call would exceed, block now (no increment)
            if (current >= perMinute)
            {
                await using var db = await ((RateLimiterService)_svc)._dbf.CreateDbContextAsync();
                await ((RateLimiterService)_svc).AddBanAsync(db, new Ban
                {
                    Ip = ip,
                    Scope = RateScope.Public,
                    Type = BanType.Soft,
                    IsTrueBan = false,
                    ReasonCode = "PUBLIC_RATE_LIMIT_EXCEEDED",
                    CreatedUtc = now,
                    ExpiresUtc = now.Add(_opt.Value.Public.SoftBanDuration)
                }, cacheOnly: false);

                ctx.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                ctx.Response.Headers["Retry-After"] = "60";
                await ctx.Response.WriteAsync("Rate limit exceeded.");
                return;
            }

            // safe to count & continue
            m.PublicCalls = current + 1;
            global!.GetOrAdd(bucket, _ => new GlobalAccumulator()).TotalCalls++;
            await _next(ctx);
        }

        private static string? ExtractApiKey(HttpContext ctx)
        {
            if (ctx.Request.Headers.TryGetValue("X-Admin-Key", out var v) && !StringValuesIsEmpty(v))
                return v.ToString();

            if (ctx.Request.Headers.TryGetValue("X-API-Key", out var apiKey) && !StringValuesIsEmpty(apiKey))
                return apiKey.ToString();

            if (ctx.Request.Headers.TryGetValue("Authorization", out var auth))
            {
                var s = auth.ToString();
                if (s.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    return s.Substring("Bearer ".Length).Trim();
            }

            if (ctx.Request.Query.TryGetValue("api_key", out var aq) && !StringValuesIsEmpty(aq))
                return aq.ToString();

            if (ctx.Request.Query.TryGetValue("key", out var q) && !StringValuesIsEmpty(q))
                return q.ToString();

            return null;

            static bool StringValuesIsEmpty(Microsoft.Extensions.Primitives.StringValues sv)
                => sv.Count == 0 || string.IsNullOrWhiteSpace(sv[0]);
        }

    }
}

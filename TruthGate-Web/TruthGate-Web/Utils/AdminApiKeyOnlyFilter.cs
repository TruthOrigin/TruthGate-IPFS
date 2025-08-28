using Microsoft.AspNetCore.Mvc.Filters;
using TruthGate_Web.Models;
using TruthGate_Web.Services;

namespace TruthGate_Web.Utils
{
    public sealed class AdminApiKeyOnlyFilter : IAsyncActionFilter
    {
        private readonly IConfigService _cfg;
        private readonly IApiKeyProvider _internalKey;
        private readonly IRateLimiterService _rl;

        public AdminApiKeyOnlyFilter(IConfigService cfg, IApiKeyProvider internalKey, IRateLimiterService rl)
            => (_cfg, _internalKey, _rl) = (cfg, internalKey, rl);

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var http = context.HttpContext;

            // Path A: cookie-authed user (no key required)
            if (http.User?.Identity?.IsAuthenticated == true)
            {
                http.Items[RateLimiterConstants.KeyValidationResultItem] = KeyValidationResult.Valid;
                // Count as a good admin call; no key to grace, but increments success counters.
                await _rl.RecordSuccessAsync(http, apiKey: null);

                // Optional: hide behind 404 on mapped domains
                if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(http))
                {
                    http.Response.StatusCode = StatusCodes.Status404NotFound;
                    await http.Response.WriteAsync("Not found.");
                    return;
                }

                await next();
                return;
            }

            // Path B: API key
            var provided = ExtractKey(http);

            if (string.IsNullOrWhiteSpace(provided))
            {
                http.Items[RateLimiterConstants.KeyValidationResultItem] = KeyValidationResult.Missing;
                await _rl.RecordFailureAsync(http, null, isAdminScope: true);
                await Deny(http, "Missing API key.");
                return;
            }

            var keys = _cfg.Get().ApiKeys ?? new List<ApiKey>();

            var ok =
                // (a) hashed key in config
                keys.Any(k =>
                    !string.IsNullOrWhiteSpace(k?.KeyHashed) &&
                    StringHasher.VerifyHash(provided, k.KeyHashed))
                // (b) OR rotating in-memory key
                || _internalKey.IsValid(provided);

            if (!ok)
            {
                http.Items[RateLimiterConstants.KeyValidationResultItem] = KeyValidationResult.Invalid;
                await _rl.RecordFailureAsync(http, provided, isAdminScope: true);
                await Deny(http, "Invalid API key.");
                return;
            }

            // Optional: mapped-domain 404 cloak
            if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(http))
            {
                http.Items[RateLimiterConstants.KeyValidationResultItem] = KeyValidationResult.Valid;
                http.Response.StatusCode = StatusCodes.Status404NotFound;
                await http.Response.WriteAsync("Not found.");
                return;
            }

            // Success: mark valid + refresh grace window for this IP↔key pair
            http.Items[RateLimiterConstants.KeyValidationResultItem] = KeyValidationResult.Valid;
            await _rl.RecordSuccessAsync(http, provided);

            await next();
        }

        private static string? ExtractKey(HttpContext http)
        {
            string? provided =
                http.Request.Headers["X-API-Key"].FirstOrDefault()
                ?? http.Request.Query["api_key"].FirstOrDefault()
                ?? http.Request.Query["key"].FirstOrDefault();

            if (string.IsNullOrWhiteSpace(provided))
            {
                var auth = http.Request.Headers.Authorization.ToString();
                const string bearer = "Bearer ";
                if (!string.IsNullOrEmpty(auth) && auth.StartsWith(bearer, StringComparison.OrdinalIgnoreCase))
                    provided = auth.Substring(bearer.Length).Trim();
            }
            return provided;
        }

        private static async Task Deny(HttpContext http, string reason)
        {
            http.Response.StatusCode = StatusCodes.Status401Unauthorized;
            http.Response.Headers["WWW-Authenticate"] = "ApiKey realm=\"/api/truthgate/v1/admin\"";
            await http.Response.WriteAsync(reason);
        }
    }
}

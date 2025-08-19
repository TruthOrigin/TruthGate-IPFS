using Microsoft.AspNetCore.Mvc.Filters;
using TruthGate_Web.Models;
using TruthGate_Web.Services;

namespace TruthGate_Web.Utils
{
    public sealed class AdminApiKeyOnlyFilter : IAsyncActionFilter
    {
        private readonly IConfigService _cfg;
        private readonly IApiKeyProvider _internalKey;

        public AdminApiKeyOnlyFilter(IConfigService cfg, IApiKeyProvider internalKey)
            => (_cfg, _internalKey) = (cfg, internalKey);

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var http = context.HttpContext;
            var provided = ExtractKey(http);

            if (string.IsNullOrWhiteSpace(provided))
            {
                await Deny(http, "Missing API key.");
                return;
            }

            var keys = _cfg.Get().ApiKeys ?? new List<ApiKey>();

            var ok =
                // (a) any stored hashed key
                keys.Any(k =>
                    !string.IsNullOrWhiteSpace(k?.KeyHashed) &&
                    StringHasher.VerifyHash(provided, k.KeyHashed))
                // (b) OR the current in-memory rotating key
                || _internalKey.IsValid(provided);

            if (!ok)
            {
                await Deny(http, "Invalid API key.");
                return;
            }

            // Optional: hide behind 404 on mapped domains
            if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(http))
            {
                http.Response.StatusCode = StatusCodes.Status404NotFound;
                await http.Response.WriteAsync("Not found.");
                return;
            }

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

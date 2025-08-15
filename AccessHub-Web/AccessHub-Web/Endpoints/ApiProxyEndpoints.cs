using Microsoft.Extensions.Options;
using TruthGate_Web.Models;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Endpoints
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;
    using System.Linq;
    using System.Threading.Tasks;

    public static class ApiProxyEndpoints
    {
        public static IEndpointRouteBuilder MapTruthGateApiProxyEndpoints(this IEndpointRouteBuilder app)
        {
            app.Map("/api/{**rest}", async (
                HttpContext context,
                string rest,
                IHttpClientFactory clientFactory,
                IConfigService configSvc) =>
            {
                // 1) Read provided API key (header or query)
                var provided =
                    context.Request.Headers["X-API-Key"].FirstOrDefault()
                    ?? context.Request.Query["api_key"].FirstOrDefault()
                    ?? context.Request.Query["key"].FirstOrDefault();

                // 2) Load config + validate key against hashed entries
                var cfg = configSvc.Get();
                bool keyOk = false;

                if (!string.IsNullOrWhiteSpace(provided) && cfg.ApiKeys is not null && cfg.ApiKeys.Count > 0)
                {
                    // Compare input (plain) to stored hash using your hasher
                    // Any match passes.
                    keyOk = cfg.ApiKeys.Any(k =>
                        !string.IsNullOrWhiteSpace(k.KeyHashed) &&
                        StringHasher.VerifyHash(provided, k.KeyHashed));
                }

                // 3) If no valid API key, require cookie-authenticated user
                if (!keyOk)
                {
                    bool isAuthed = context.User?.Identity?.IsAuthenticated ?? false;
                    if (!isAuthed)
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        context.Response.Headers["WWW-Authenticate"] = "ApiKey realm=\"/api\"";
                        await context.Response.CompleteAsync();
                        return;
                    }
                }

                // 4) Disallow API on mapped domains (your original guard)
                if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(context))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    await context.Response.WriteAsync("Not found.");
                    return;
                }

                // 5) Proxy through to target
                var targetUri = RequestHelpers.CombineTarget("api", rest, context);
                await IpfsGateway.Proxy(context, targetUri, clientFactory);
            });

            // CORS preflight
            app.MapMethods("/api/{**rest}", new[] { "OPTIONS" }, async context =>
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "*";
                await context.Response.CompleteAsync();
            });

            return app;
        }
    }

}

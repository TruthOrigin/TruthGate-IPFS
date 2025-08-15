using Microsoft.Extensions.Options;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Endpoints
{
    public static class ApiProxyEndpoints
    {
        public static IEndpointRouteBuilder MapTruthGateApiProxyEndpoints(this IEndpointRouteBuilder app)
        {
            app.Map("/api/{**rest}", async (HttpContext context, string rest,
                                            IHttpClientFactory clientFactory,
                                            IOptions<SecurityOptions> opt) =>
            {
                var provided =
                    context.Request.Headers["X-API-Key"].FirstOrDefault()
                    ?? context.Request.Query["api_key"].FirstOrDefault()
                    ?? context.Request.Query["key"].FirstOrDefault();

                if (string.IsNullOrWhiteSpace(provided) ||
                    !opt.Value.Keys.Any(k => RequestHelpers.SafeEquals(k, provided)))
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

                if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(context))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    await context.Response.WriteAsync("Not found.");
                    return;
                }

                var targetUri = RequestHelpers.CombineTarget("api", rest, context);
                await IpfsGateway.Proxy(context, targetUri, clientFactory);
            });

            app.MapMethods("/api/{**rest}", new[] { "OPTIONS" }, async context =>
            {
                context.Response.StatusCode = 204;
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "*";
                await context.Response.CompleteAsync();
            });

            return app;
        }
    }
}

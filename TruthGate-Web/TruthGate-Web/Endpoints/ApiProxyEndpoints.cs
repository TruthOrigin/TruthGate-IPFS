using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Http;
using TruthGate_Web.Models;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Endpoints
{
    public static class ApiProxyEndpoints
    {
        /// <summary>
        /// Calls your existing IpfsGateway.Proxy just like the HTTP endpoint would,
        /// but entirely in-process, returning an HttpResponseMessage.
        /// </summary>
        public static async Task<HttpResponseMessage> SendProxyApiRequest(
        string rest,
        IHttpClientFactory clientFactory)
        {
            // fake up an HttpContext the proxy can use
            var context = new DefaultHttpContext();

            // make sure there’s at least a valid method/scheme so downstream doesn’t choke
            context.Request.Method = "POST";     // ipfs endpoints usually accept POST
            context.Request.Scheme = "http";     // adjust if your RequestHelpers cares
                                                 // context.Request.Host = ... only if your RequestHelpers actually reads it

            // capture response into memory
            var bodyStream = new MemoryStream();
            context.Response.Body = bodyStream;

            // run your existing proxy
            
            var restNormalized = rest.TrimStart('/');
            if (restNormalized.StartsWith("api/", StringComparison.OrdinalIgnoreCase))
                restNormalized = restNormalized.Substring(4);

            var targetUri = RequestHelpers.CombineTarget("api", restNormalized, context);
            await IpfsGateway.Proxy(context, targetUri, clientFactory);

            // convert HttpContext.Response into HttpResponseMessage
            bodyStream.Position = 0;
            var response = new HttpResponseMessage((HttpStatusCode)context.Response.StatusCode)
            {
                Content = new StreamContent(new MemoryStream(bodyStream.ToArray()))
            };

            foreach (var kv in context.Response.Headers)
            {
                if (!response.Headers.TryAddWithoutValidation(kv.Key, kv.Value.ToArray()))
                {
                    response.Content.Headers.TryAddWithoutValidation(kv.Key, kv.Value.ToArray());
                }
            }

            return response;
        }

        public static IEndpointRouteBuilder MapTruthGateApiProxyEndpoints(this IEndpointRouteBuilder app)
        {
            // CORS preflight first (optional, order usually doesn't matter with explicit MapMethods)
            app.MapMethods("/api/{**rest}", new[] { "OPTIONS" }, async context =>
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "*";
                await context.Response.CompleteAsync();
            });

            app.Map("/api/{**rest}", async (HttpContext context, string rest, IHttpClientFactory clientFactory, IConfigService cfgSvc) =>
            {
                // 1) Pull plaintext key from header or query
                var providedKey =
                    context.Request.Headers["X-API-Key"].FirstOrDefault()
                    ?? context.Request.Query["api_key"].FirstOrDefault()
                    ?? context.Request.Query["key"].FirstOrDefault();

                bool keyAccepted = false;

                // 2) Validate against hashed keys in config (if any)
                var cfg = cfgSvc.Get();
                var keys = cfg.ApiKeys ?? new List<ApiKey>();

                if (!string.IsNullOrWhiteSpace(providedKey) && keys.Count > 0)
                {
                    // Any stored hashed key that verifies wins
                    keyAccepted = keys.Any(k =>
                        !string.IsNullOrWhiteSpace(k?.KeyHashed) &&
                        StringHasher.VerifyHash(providedKey, k.KeyHashed));
                }

                // 3) If key not accepted, allow cookie-authenticated users
                bool isAuthed = context.User?.Identity?.IsAuthenticated ?? false;

                if (!keyAccepted && !isAuthed)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.Headers["WWW-Authenticate"] = "ApiKey realm=\"/api\"";
                    await context.Response.CompleteAsync();
                    return;
                }

                // 4) Guard mapped domains
                if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(context))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    await context.Response.WriteAsync("Not found.");
                    return;
                }

                // 5) Proxy onward
                var targetUri = RequestHelpers.CombineTarget("api", rest, context);
                await IpfsGateway.Proxy(context, targetUri, clientFactory);
            });

            return app;
        }
    }
}

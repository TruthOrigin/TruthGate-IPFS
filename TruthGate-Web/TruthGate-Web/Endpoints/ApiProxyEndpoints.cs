using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
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
        /// <summary>
        /// Sends an IPFS API request through the in-process proxy.
        /// - rest: e.g. "/api/v0/key/import?arg=myKey"
        /// - content: optional HttpContent (MultipartFormDataContent, StringContent, etc.)
        /// - method: defaults to POST (most IPFS endpoints accept POST)
        /// - extraHeaders: optional additional request headers
        /// </summary>
        public static async Task<HttpResponseMessage> SendProxyApiRequest(
            string rest,
            IHttpClientFactory clientFactory,
            IApiKeyProvider keys,
            HttpContent? content = null,
            string? method = null,
            IDictionary<string, string>? extraHeaders = null,
            CancellationToken ct = default)
        {
            // ---- Prepare a fake HttpContext the proxy can read from ----
            var context = new DefaultHttpContext();

            // Method: default POST (IPFS API typically uses POST), but caller may override
            var httpMethod = method ?? "POST";
            context.Request.Method = httpMethod;
            context.Request.Scheme = "http"; // adjust if your RequestHelpers cares about scheme

            // Auth header your proxy expects
            context.Request.Headers["X-API-Key"] = keys.GetCurrentKey();

            // Additional caller-provided headers
            if (extraHeaders is not null)
            {
                foreach (var (k, v) in extraHeaders)
                    context.Request.Headers[k] = new StringValues(v);
            }

            // If we were given HttpContent and the method allows a body, copy it into Request.Body
            if (content is not null && !HttpMethods.IsGet(httpMethod) && !HttpMethods.IsHead(httpMethod))
            {
                // Copy the content bytes into the ASP.NET Request body
                var reqBuffer = new MemoryStream();
                await content.CopyToAsync(reqBuffer, ct);
                reqBuffer.Position = 0;
                context.Request.Body = reqBuffer;
                context.Request.ContentLength = reqBuffer.Length;

                // Hoist content headers (esp. Content-Type with boundary for multipart)
                foreach (var h in content.Headers)
                {
                    // "Content-Length" is handled by ContentLength above
                    if (h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                    context.Request.Headers[h.Key] = new StringValues(h.Value.ToArray());
                }

                // Some frameworks look at this property too
                if (content.Headers.ContentType is not null)
                    context.Request.ContentType = content.Headers.ContentType.ToString();
            }

            // ---- Run your existing proxy ----
            var bodyStream = new MemoryStream();
            context.Response.Body = bodyStream;

            var restNormalized = rest.TrimStart('/');
            if (restNormalized.StartsWith("api/", StringComparison.OrdinalIgnoreCase))
                restNormalized = restNormalized.Substring(4);

            var targetUri = RequestHelpers.CombineTarget("api", restNormalized, context);

            // Your proxy copies request headers to the outgoing HttpRequestMessage and forwards the body stream.
            await IpfsGateway.Proxy(context, targetUri, clientFactory);

            // ---- Convert HttpContext.Response → HttpResponseMessage ----
            bodyStream.Position = 0;
            var response = new HttpResponseMessage((HttpStatusCode)context.Response.StatusCode)
            {
                Content = new StreamContent(new MemoryStream(bodyStream.ToArray()))
            };

            // Copy response headers (proxy already scrubbed hop-by-hop)
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
            app.MapMethods("/api/v0/{**rest}", new[] { "OPTIONS" }, async context =>
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "*";
                await context.Response.CompleteAsync();
            });

            app.Map("/api/v0/{**rest}", async (HttpContext context, string rest,
    IHttpClientFactory clientFactory, IApiKeyProvider internalKey,
    IConfigService cfgSvc) =>
            {
                // 1) Pull plaintext key from header, query, or Authorization: Bearer
                string? providedKey =
                    context.Request.Headers["X-API-Key"].FirstOrDefault()
                    ?? context.Request.Query["api_key"].FirstOrDefault()
                    ?? context.Request.Query["key"].FirstOrDefault();

                if (string.IsNullOrWhiteSpace(providedKey))
                {
                    var auth = context.Request.Headers.Authorization.ToString();
                    const string bearerPrefix = "Bearer ";
                    if (!string.IsNullOrEmpty(auth) && auth.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
                        providedKey = auth.Substring(bearerPrefix.Length).Trim();
                }

                bool keyAccepted = false;

                // 2) Validate against hashed keys in config (if any) OR the in-memory rotating key
                var cfg = cfgSvc.Get();
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
                    else if (internalKey.IsValid(providedKey))
                    {
                        keyAccepted = true;
                    }
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
                var targetUri = RequestHelpers.CombineTarget("api/v0", rest, context);
                await IpfsGateway.Proxy(context, targetUri, clientFactory);
            });


            return app;
        }
    }
}

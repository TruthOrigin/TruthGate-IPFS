using Microsoft.Extensions.Options;
using System.Net;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Endpoints
{
    public static class IpfsEndpoints
    {
        public static IEndpointRouteBuilder MapTruthGateIpfsEndpoints(this IEndpointRouteBuilder app)
        {
            // --- /webui (exact, no rest) ---
            app.Map("/webui", async (
    HttpContext context,
    IHttpClientFactory clientFactory,
    IOptions<PortOptions> ports,
    IOptions<DomainListOptions> domainsOpt) =>
            {
                var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

                var mfsPath = DomainHelpers.GetMappedDomain(context, env, domainsOpt.Value);
                if (!string.IsNullOrWhiteSpace(mfsPath))
                    return; // handled by mapped domain logic elsewhere

                // Require authentication
                bool isAuthed = context.User?.Identity?.IsAuthenticated ?? false;

                if (!isAuthed)
                {
                    if (string.IsNullOrWhiteSpace(mfsPath))
                    {
                        if (RequestHelpers.IsHtmlRequest(context.Request))
                        {
                            var dest = context.Request.Path + context.Request.QueryString;
                            context.Response.Redirect($"/login?returnUrl={Uri.EscapeDataString(dest)}");
                        }
                        else
                        {
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        }
                        return;
                    }

                    var cid = await IpfsGateway.ResolveMfsFolderToCidAsync(mfsPath!, clientFactory);
                    if (string.IsNullOrWhiteSpace(cid) || !await IpfsGateway.IsCidLocalAsync(cid!, clientFactory))
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        await context.Response.WriteAsync("Site not available locally.");
                        return;
                    }
                }

                // If we got here, user is authorized — proxy to the node's /webui
                var targetUri = $"http://127.0.0.1:{ports.Value.Http}/webui";
                await IpfsGateway.Proxy(context, targetUri, clientFactory);
            });


            // Optional: CORS preflight for /webui
            app.MapMethods("/webui", new[] { "OPTIONS" }, async context =>
            {
                context.Response.StatusCode = 204;
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "*";
                await context.Response.CompleteAsync();
            });

            // --- /ipfs/{**rest} (requires rest) ---
            app.Map("/ipfs/{**rest}", async (
                HttpContext context, string rest,
                IHttpClientFactory clientFactory,
                IOptions<PortOptions> ports,
                IOptions<DomainListOptions> domainsOpt) =>
            {
                var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

                var mfsPath = DomainHelpers.GetMappedDomain(context, env, domainsOpt.Value);
                if (!string.IsNullOrWhiteSpace(mfsPath))
                    return;

                if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(context))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    await context.Response.WriteAsync("Not found.");
                    return;
                }

                bool isAuthed = context.User?.Identity?.IsAuthenticated ?? false;

                if (!isAuthed)
                {
                    if (string.IsNullOrWhiteSpace(mfsPath))
                    {
                        if (RequestHelpers.IsHtmlRequest(context.Request))
                        {
                            var dest = context.Request.Path + context.Request.QueryString;
                            context.Response.Redirect($"/login?returnUrl={Uri.EscapeDataString(dest)}");
                        }
                        else
                        {
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        }
                        return;
                    }

                    var cid = await IpfsGateway.ResolveMfsFolderToCidAsync(mfsPath!, clientFactory);
                    if (string.IsNullOrWhiteSpace(cid) || !await IpfsGateway.IsCidLocalAsync(cid!, clientFactory))
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        await context.Response.WriteAsync("Site not available locally.");
                        return;
                    }

                    var mappedCid = cid!;
                    var firstSeg = rest.Split('/', 2)[0];

                    if (!string.Equals(firstSeg, mappedCid, StringComparison.Ordinal))
                    {
                        if (RequestHelpers.IsHtmlRequest(context.Request))
                        {
                            context.Response.StatusCode = StatusCodes.Status404NotFound;
                            await context.Response.WriteAsync("Not found.");
                        }
                        else
                        {
                            context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        }
                        return;
                    }

                    var targetUriAuthedless = RequestHelpers.CombineTargetHttp("ipfs", rest, context, ports.Value.Http);
                    await IpfsGateway.Proxy(context, targetUriAuthedless, clientFactory);
                    return;
                }

                // Authenticated: normalize missing CID via Referer if needed
                var fallbackCid = RequestHelpers.ExtractCidFromReferer(context.Request);
                var normalizedRest = RequestHelpers.EnsureCidPrefix(rest, fallbackCid);

                var targetUriAuthed = RequestHelpers.CombineTargetHttp("ipfs", normalizedRest, context, ports.Value.Http);
                await IpfsGateway.Proxy(context, targetUriAuthed, clientFactory);
            });

            // Preflight for /ipfs/*
            app.MapMethods("/ipfs/{**rest}", new[] { "OPTIONS" }, async context =>
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

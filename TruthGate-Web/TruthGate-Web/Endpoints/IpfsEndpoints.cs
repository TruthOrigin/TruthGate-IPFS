using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Net;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;
using Microsoft.AspNetCore.Identity;

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
    IOptions<PortOptions> ports) =>
            {
                var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();
                var mfsPath = DomainHelpers.GetMappedDomain(context);
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

                    var cidv = await IpfsGateway.ResolveMfsFolderToCidAsync(mfsPath!, clientFactory);
                    if (string.IsNullOrWhiteSpace(cidv) || !await IpfsGateway.IsCidLocalAsync(cidv!, clientFactory))
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        await context.Response.WriteAsync("Site not available locally.");
                        return;
                    }
                }

                var nodeWebUi = $"http://127.0.0.1:5001/webui";   // ports.Value.Http == 5001 in your setup
                var cid = await IpfsIntrospection.TryGetWebUiCidAsync(nodeWebUi, clientFactory, context.RequestAborted);

                if (!string.IsNullOrWhiteSpace(cid))
                {
                    // 2) Redirect user to your own /ipfs/<cid> path
                    context.Response.Redirect($"/ipfs/{cid}");
                    return;
                }

                // 3) Fallback: if we couldn't find a CID, proxy the WebUI page through
                //    (use your improved Proxy that strips conditional headers / rewrites Location)
                await IpfsGateway.Proxy(context, nodeWebUi, clientFactory);
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
                IOptions<PortOptions> ports) =>
            {
                var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

                var mfsPath = DomainHelpers.GetMappedDomain(context);
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

                    var targetUriAuthedless = RequestHelpers.CombineTargetHttp("ipfs", rest, context, 9010);
                    await IpfsGateway.Proxy(context, targetUriAuthedless, clientFactory);
                    return;
                }

                // Authenticated: normalize missing CID via Referer if needed
                var fallbackCid = RequestHelpers.ExtractCidFromReferer(context.Request);
                var normalizedRest = RequestHelpers.EnsureCidPrefix(rest, fallbackCid);

                var targetUriAuthed = RequestHelpers.CombineTargetHttp("ipfs", normalizedRest, context, 9010);
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

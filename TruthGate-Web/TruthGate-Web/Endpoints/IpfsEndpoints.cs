using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Net;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;
using Microsoft.AspNetCore.Identity;
using TruthGate_Web.Services;
using System.IO;
using TruthGate_Web.Middleware;

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



            app.Map("/{**path}", async (
    HttpContext context,
    string? path,
    IHttpClientFactory clientFactory) =>
            {
               
                // Only handle our special query marker
                if (!context.Request.Query.ContainsKey("tgcid"))
                    return; // let the rest of the pipeline handle it

                var cid = context.Request.Query["tgcid"].ToString();
                if (string.IsNullOrWhiteSpace(cid))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("Missing tgcid");
                    return;
                }

                // Normalize requested path (strip leading '/')
                var cleanPath = (path ?? "").TrimStart('/');

                // Safety: block path traversal
                if (cleanPath.Contains(".."))
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("Invalid path");
                    return;
                }

                // Build the internal /ipfs/<cid>/<path> target
                var normalizedRest = string.IsNullOrEmpty(cleanPath) ? cid : $"{cid}/{cleanPath}";
                var targetUri = RequestHelpers.CombineTargetHttp("ipfs", normalizedRest, context, 9010);

                // Proxy straight through (no HTML rewriting here)
                await IpfsGateway.Proxy(context, targetUri, clientFactory, rewriteIndexForCid: false);
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
                var rewrite = ShouldRewriteIndex(context, normalizedRest);
                var ipfsPrefix = ExtractIpfsPrefix(normalizedRest);

                await IpfsGateway.Proxy(context, targetUriAuthed, clientFactory, rewriteIndexForCid: rewrite, basePrefix: ipfsPrefix);
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


            // --- /ipns/{**rest} (requires rest) ---
            app.Map("/ipns/{**rest}", async (
                HttpContext context, string rest,
                IHttpClientFactory clientFactory,
                IApiKeyProvider keys,
                IOptions <PortOptions> ports) =>
            {
                var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

                // Domain mapping logic identical to /ipfs
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
                    // No mapped domain: gate access just like /ipfs
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

                    // Mapped domain: must be locally available AND the requested IPNS name must resolve to the same CID
                    var mappedCid = await IpfsGateway.ResolveMfsFolderToCidAsync(mfsPath!, clientFactory);
                    if (string.IsNullOrWhiteSpace(mappedCid) || !await IpfsGateway.IsCidLocalAsync(mappedCid!, clientFactory))
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        await context.Response.WriteAsync("Site not available locally.");
                        return;
                    }

                    // Ensure first path segment (IPNS name) resolves to that same CID
                    var firstSeg = rest.Split('/', 2)[0];
                    var resolvedFromIpns = await IpfsGateway.ResolveIpnsToCidAsync(firstSeg, clientFactory, keys);

                    if (!string.Equals(resolvedFromIpns, mappedCid, StringComparison.Ordinal))
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

                    var targetUriAuthedless = RequestHelpers.CombineTargetHttp("ipns", rest, context, 9010);
                    await IpfsGateway.Proxy(context, targetUriAuthedless, clientFactory);
                    return;
                }

                // Authenticated: normalize missing IPNS name via Referer if needed (parallels CID normalization)
                var fallbackIpns = RequestHelpers.ExtractIpnsFromReferer(context.Request);
                var normalizedRest = RequestHelpers.EnsureIpnsPrefix(rest, fallbackIpns);

                var targetUriAuthed = RequestHelpers.CombineTargetHttp("ipns", normalizedRest, context, 9010);

                var rewrite = ShouldRewriteIndex(context, normalizedRest);
                var ipnsPrefix = ExtractIpnsPrefix(normalizedRest);

                await IpfsGateway.Proxy(context, targetUriAuthed, clientFactory, rewriteIndexForCid: rewrite, basePrefix: ipnsPrefix);

            }); 

            // Preflight for /ipns/*
            app.MapMethods("/ipns/{**rest}", new[] { "OPTIONS" }, async context =>
            {
                context.Response.StatusCode = 204;
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "*";
                await context.Response.CompleteAsync();
            });


            return app;
        }

        // Helpers
        static bool ShouldRewriteIndex(HttpContext ctx, string rest)
        {
            if (!RequestHelpers.IsHtmlRequest(ctx.Request)) return false;
            // Rewrite for index-like requests
            if (string.IsNullOrWhiteSpace(rest)) return true;
            if (rest.EndsWith("/", StringComparison.Ordinal)) return true;
            if (rest.EndsWith("index.html", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        static string? ExtractIpfsPrefix(string normalizedRest)
        {
            // normalizedRest expected like: "{cid}/..." or "{cid}" or empty (handled earlier)
            var seg = normalizedRest.Split('/', 2)[0];
            return string.IsNullOrWhiteSpace(seg) ? null : $"/ipfs/{seg}/";
        }

        static string? ExtractIpnsPrefix(string normalizedRest)
        {
            var seg = normalizedRest.Split('/', 2)[0];
            return string.IsNullOrWhiteSpace(seg) ? null : $"/ipns/{seg}/";
        }

    }
}

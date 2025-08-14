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
            app.Map("/{firstSegment}/{**rest}", async (HttpContext context, string firstSegment, string rest,
                                            IHttpClientFactory clientFactory,
                                            IOptions<PortOptions> ports,
                                            IOptions<DomainListOptions> domainsOpt) =>
            {
                var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();

                var mfsPath = DomainHelpers.GetMappedDomain(context, env, domainsOpt.Value);
                if (!string.IsNullOrWhiteSpace(mfsPath))
                {
                    return;
                }


                var segment = firstSegment.ToLowerInvariant();

                if (segment != "ipfs" && segment != "webui")
                {
                    // Not a match, let other middleware/routes handle this request
                    return;
                }

                if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(context))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    await context.Response.WriteAsync("Not found.");
                    return;
                }

                bool isAuthed = context.User?.Identity?.IsAuthenticated ?? false;

                if (!isAuthed)
                { 
                    //var host = context.Request.Host.Host ?? "";
                   //var (mfsPath, _) = DomainHelpers.FindBestDomainFolderForHost(host, domainsOpt.Value.Domains);

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

                    // If no rest, anchor at the mapped root
                    if (string.IsNullOrWhiteSpace(rest))
                    {
                        var targetUri = RequestHelpers.CombineTargetHttp("ipfs", mappedCid, context, ports.Value.Http);
                        await IpfsGateway.Proxy(context, targetUri, clientFactory);
                        return;
                    }

                    // Normalize the first segment (requested cid or path piece)
                    var firstSeg = rest.Split('/', 2)[0];

                    // NEW: Only allow requests under the mapped CID
                    if (!string.Equals(firstSeg, mappedCid, StringComparison.Ordinal))
                    {
                        // Deny traversal to arbitrary CIDs
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

                    // Allowed: pass through as-is under the mapped CID
                    var targetUriAuthedless = RequestHelpers.CombineTargetHttp("ipfs", rest, context, ports.Value.Http);
                    await IpfsGateway.Proxy(context, targetUriAuthedless, clientFactory);
                    return;
                }

                // Allowed: pass through as-is under the mapped CID
                // Authenticated users: full access as-is, but reinsert CID if missing
                var fallbackCid = RequestHelpers.ExtractCidFromReferer(context.Request);
                var normalizedRest = RequestHelpers.EnsureCidPrefix(rest, fallbackCid);

                var targetUriAuthed = RequestHelpers.CombineTargetHttp("ipfs", normalizedRest, context, ports.Value.Http);
                await IpfsGateway.Proxy(context, targetUriAuthed, clientFactory);
                /*var targetUriAuthed = RequestHelpers.CombineTargetHttp("ipfs", rest, context, ports.Value.Http);
                await IpfsGateway.Proxy(context, targetUriAuthed, clientFactory);*/
            });

            // Preflight
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

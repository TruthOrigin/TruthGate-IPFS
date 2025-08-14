using Microsoft.Extensions.Options;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Endpoints
{
    public static class IpfsEndpoints
    {
        public static IEndpointRouteBuilder MapTruthGateIpfsEndpoints(this IEndpointRouteBuilder app)
        {
            // Single handler that accepts an optional rest segment
            async Task Handler(HttpContext context, string firstSegment, string? rest,
                               IHttpClientFactory clientFactory,
                               IOptions<PortOptions> ports,
                               IOptions<DomainListOptions> domainsOpt)
            {
                var segment = firstSegment.ToLowerInvariant();
                rest ??= string.Empty; // normalize missing catch-all

                if (segment == "ipfs" || segment == "webui")
                {
                    // your handler logic (kept exactly as you had it)
                    // ------------------------------------------------
                    // If you still want the quick test line, keep this:
                    // await context.Response.WriteAsync($"Matched {segment} with rest = {rest}");
                    // return;

                    if (TruthGate_Web.Utils.DomainHelpers.IsMappedDomain(context))
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        await context.Response.WriteAsync("Not found.");
                        return;
                    }

                    bool isAuthed = context.User?.Identity?.IsAuthenticated ?? false;

                    if (!isAuthed)
                    {
                        var host = context.Request.Host.Host ?? "";
                        var (mfsPath, _) = DomainHelpers.FindBestDomainFolderForHost(host, domainsOpt.Value.Domains);

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

                        // Only allow requests under the mapped CID
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

                        // Allowed: pass through as-is under the mapped CID
                        var targetUriAuthedless = RequestHelpers.CombineTargetHttp("ipfs", rest, context, ports.Value.Http);
                        await IpfsGateway.Proxy(context, targetUriAuthedless, clientFactory);
                        return;
                    }

                    // Authenticated users: full access as-is, but reinsert CID if missing
                    var fallbackCid = RequestHelpers.ExtractCidFromReferer(context.Request);
                    var normalizedRest = RequestHelpers.EnsureCidPrefix(rest, fallbackCid);

                    var targetUriAuthed = RequestHelpers.CombineTargetHttp("ipfs", normalizedRest, context, ports.Value.Http);
                    await IpfsGateway.Proxy(context, targetUriAuthed, clientFactory);
                    return;
                }

                // Not ipfs/webui -> 404 for unmapped domains
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync("Not found.");
            }

            // Map both shapes to the same handler:
            // 1) /{firstSegment}                -> rest missing
            // 2) /{firstSegment}/{**rest}       -> rest present
            app.Map("/{firstSegment}", Handler);
            app.Map("/{firstSegment}/{**rest}", Handler);

            // Preflight (OPTIONS) for both shapes as well
            app.MapMethods("/{firstSegment}", new[] { "OPTIONS" }, async context =>
            {
                context.Response.StatusCode = 204;
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "*";
                await context.Response.CompleteAsync();
            });

            app.MapMethods("/{firstSegment}/{**rest}", new[] { "OPTIONS" }, async context =>
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

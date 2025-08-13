using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Middleware
{
    public static class DomainGatewayMiddleware
    {
        // Small result object for one attempt
        private sealed record RunOnceResult(
            bool Handled,           // we produced a response OR delegated to next()
            bool RetryCandidate,    // proxy failed with a status that suggests stale cache (400/404/410)
            string? Cid,            // cid used (if any)
            string? MfsPath         // mfs path used (if any)
        );

        private static async Task<RunOnceResult> RunOnce(HttpContext ctx, Func<Task> next)
        {
            var domainsOpt = ctx.RequestServices.GetRequiredService<IOptions<DomainListOptions>>().Value;
            var env = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();

            var hostToMatch = DomainHelpers.GetEffectiveHost(ctx, env, domainsOpt);
            if (string.IsNullOrWhiteSpace(hostToMatch))
            {
                await next();
                return new RunOnceResult(Handled: true, RetryCandidate: false, Cid: null, MfsPath: null);
            }

            var (mfsPath, _) = DomainHelpers.FindBestDomainFolderForHost(hostToMatch, domainsOpt.Domains);
            if (string.IsNullOrWhiteSpace(mfsPath))
            {
                await next();
                return new RunOnceResult(Handled: true, RetryCandidate: false, Cid: null, MfsPath: null);
            }

            // keep /api and /auth exceptions
            var p = (ctx.Request.Path.Value ?? "").ToLowerInvariant();
            if (p.StartsWith("/api") || p.StartsWith("/auth"))
            {
                await next();
                return new RunOnceResult(Handled: true, RetryCandidate: false, Cid: null, MfsPath: null);
            }

            var clientFactory = ctx.RequestServices.GetRequiredService<IHttpClientFactory>();
            var cache = ctx.RequestServices.GetRequiredService<IMemoryCache>();
            var ports = ctx.RequestServices.GetRequiredService<IOptions<PortOptions>>().Value;

            var ttl = TimeSpan.FromHours(2);

            // Resolve CID (cached)
            var cid = await IpfsGateway.ResolveMfsFolderToCidCachedAsync(mfsPath!, clientFactory, cache, ttl);
            if (string.IsNullOrWhiteSpace(cid))
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                await ctx.Response.WriteAsync("Site not found (no MFS folder).");
                return new RunOnceResult(Handled: true, RetryCandidate: false, Cid: null, MfsPath: null);
            }

            // Locality check (cached)
            if (!await IpfsGateway.IsCidLocalCachedAsync(cid!, clientFactory, cache, ttl))
            {
                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                await ctx.Response.WriteAsync("Site not available locally.");
                return new RunOnceResult(Handled: true, RetryCandidate: false, Cid: cid, MfsPath: mfsPath);
            }

            var rest = ctx.Request.Path.Value?.TrimStart('/') ?? "";
            var hasExt = Path.HasExtension(ctx.Request.Path.Value ?? "");

            // 1) Implicit /index.html only for nav routes (no extension)
            if (!hasExt && RequestHelpers.IsHtmlRequest(ctx.Request) && HttpMethods.IsGet(ctx.Request.Method))
            {
                string canonicalRest = rest;
                if (canonicalRest.EndsWith("/")) canonicalRest = canonicalRest.TrimEnd('/');

                if (!string.IsNullOrEmpty(canonicalRest))
                {
                    var idxCandidate = canonicalRest + "/index.html";
                    var (hasIndex, fixedIndexPath) =
                        await IpfsGateway.PathExistsInIpfsAsync(cid!, idxCandidate, ports.Http, clientFactory, cache, ttl);

                    if (hasIndex)
                    {
                        var indexPath = fixedIndexPath ?? idxCandidate;
                        var idxTarget = $"http://127.0.0.1:{ports.Http}/ipfs/{cid}/{indexPath}{ctx.Request.QueryString}";

                        var ok = await IpfsGateway.Proxy(ctx, idxTarget, clientFactory);
                        // If proxy failed with 400/404/410, mark retry-candidate
                        var sc = ctx.Response.StatusCode;
                        var retry = !ok && (sc == 400 || sc == 404 || sc == 410);
                        return new RunOnceResult(Handled: true, RetryCandidate: retry, Cid: cid, MfsPath: mfsPath);
                    }
                }
            }

            // 2) Does requested path exist?
            var (exists, correctedRest) =
                await IpfsGateway.PathExistsInIpfsAsync(cid!, rest, ports.Http, clientFactory, cache, ttl);

            // 3) SPA fallback to index.html or 200.html
            if (!exists)
            {
                if (!hasExt && RequestHelpers.IsHtmlRequest(ctx.Request) && HttpMethods.IsGet(ctx.Request.Method))
                {
                    foreach (var f in new[] { "index.html", "200.html" })
                    {
                        var (fbExists, fbFixed) =
                            await IpfsGateway.PathExistsInIpfsAsync(cid!, f, ports.Http, clientFactory, cache, ttl);

                        if (fbExists)
                        {
                            var chosen = fbFixed ?? f;
                            var fallbackTarget = $"http://127.0.0.1:{ports.Http}/ipfs/{cid}/{chosen}{ctx.Request.QueryString}";
                            var ok = await IpfsGateway.Proxy(ctx, fallbackTarget, clientFactory);
                            var sc = ctx.Response.StatusCode;
                            var retry = !ok && (sc == 400 || sc == 404 || sc == 410);
                            return new RunOnceResult(Handled: true, RetryCandidate: retry, Cid: cid, MfsPath: mfsPath);
                        }
                    }
                }

                ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                await ctx.Response.WriteAsync("Not found.");
                return new RunOnceResult(Handled: true, RetryCandidate: false, Cid: cid, MfsPath: mfsPath);
            }

            // 4) Normal proxy
            var effectiveRest = correctedRest ?? rest;
            var pathPart = string.IsNullOrEmpty(effectiveRest) ? "" : $"/{effectiveRest.Trim('/')}";
            var target = $"http://127.0.0.1:{ports.Http}/ipfs/{cid}{pathPart}{ctx.Request.QueryString}";

            var success = await IpfsGateway.Proxy(ctx, target, clientFactory);
            var status = ctx.Response.StatusCode;
            var retryCandidate = !success && (status == 400 || status == 404 || status == 410);

            return new RunOnceResult(Handled: true, RetryCandidate: retryCandidate, Cid: cid, MfsPath: mfsPath);
        }

        // Adds the big “mapped domain → IPFS gateway” behavior with one optional retry on stale cache
        public static IApplicationBuilder UseDomainGateway(this IApplicationBuilder app)
        {
            app.Use(async (ctx, next) =>
            {
                // First attempt
                var res = await RunOnce(ctx, next);
                if (!res.RetryCandidate)
                    return;

                // Invalidate + retry once
                if (!string.IsNullOrEmpty(res.Cid)) IpfsCacheIndex.InvalidateCid(res.Cid!);
                if (!string.IsNullOrEmpty(res.MfsPath)) IpfsCacheIndex.InvalidateMfs(res.MfsPath!);

                await RunOnce(ctx, next);
            });

            return app;
        }
    }
}
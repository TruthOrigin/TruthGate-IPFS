using Microsoft.Extensions.Options;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Middleware
{
    public static class NonMappedAuthGuardExtensions
    {
        public static IApplicationBuilder UseNonMappedDomainAuthGuard(this IApplicationBuilder app)
        {
            app.UseWhen(ctx => !DomainHelpers.IsMappedDomain(ctx), secured =>
            {
                secured.Use(async (ctx, next) =>
                {
                    var env = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();
                    var domainsOpt = ctx.RequestServices.GetRequiredService<IOptions<DomainListOptions>>();

                    // If domain is mapped, always bypass
                    var mfsPath = DomainHelpers.GetMappedDomain(ctx, env, domainsOpt.Value);
                    if (!string.IsNullOrWhiteSpace(mfsPath))
                    {
                        ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                    }

                    var path = (ctx.Request.Path.Value ?? "").ToLowerInvariant();

                    // Always bypass /login and /auth
                    if (path.StartsWith("/login") || path.StartsWith("/auth") || path.StartsWith("/api")
                    || path.StartsWith("/_content/mudblazor") || path.StartsWith("/_framework"))
                    {
                        if (ctx.Request.Path.Equals("/login", StringComparison.OrdinalIgnoreCase)
                            && (ctx.User.Identity?.IsAuthenticated ?? false))
                        {
                            ctx.Response.Redirect("/");
                            return;
                        }


                        await next();
                        return;
                    }

#if DEBUG
                    if (path.StartsWith("/.well-known"))
                    {
                        await next();
                        return;
                    }
#endif

                    // If it's a file in wwwroot, bypass
                    if (IsRequestingWwwrootFile(env, path))
                    {
                        await next();
                        return;
                    }

                    

                    // Preflight requests bypass
                    if (HttpMethods.IsOptions(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method))
                    {
                        await next();
                        return;
                    }

                    // Require authentication for everything else
                    var authed = ctx.User?.Identity?.IsAuthenticated ?? false;
                    if (!authed)
                    {
                        if (TruthGate_Web.Utils.RequestHelpers.IsHtmlRequest(ctx.Request))
                        {
                            var dest = ctx.Request.Path + ctx.Request.QueryString;
                            ctx.Response.Redirect("/login?returnUrl=" + Uri.EscapeDataString(dest));
                        }
                        else
                        {
                            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        }
                        return;
                    }

                    await next();
                });
            });

            return app;
        }

        private static string? _resolvedWebRoot; // cache once per process

        public static bool IsRequestingWwwrootFile(IWebHostEnvironment env, string requestPath)
        {
            if (env is null || string.IsNullOrWhiteSpace(requestPath))
                return false;

            // Normalize & guard traversal
            var rel = requestPath.TrimStart('/');
            if (rel.Contains("..")) return false;

            // Fast path: use the file provider if present
            var fp = env.WebRootFileProvider;
            if (fp != null)
            {
                var fi = fp.GetFileInfo(rel);
                if (fi?.Exists == true) return true;
            }

            // Resolve web root once and cache
            if (_resolvedWebRoot == null)
            {
                var webRoot = env.WebRootPath;
                if (string.IsNullOrWhiteSpace(webRoot))
                {
                    var baseDir = AppContext.BaseDirectory;
                    if (!string.IsNullOrEmpty(baseDir))
                    {
                        var fallback = System.IO.Path.Combine(baseDir, "wwwroot");
                        if (Directory.Exists(fallback))
                            webRoot = fallback;
                    }
                }

                _resolvedWebRoot = string.IsNullOrWhiteSpace(webRoot) ? "" : webRoot;
            }

            if (string.IsNullOrEmpty(_resolvedWebRoot))
                return false; // we still don't have a webroot—bail safely

            var full = System.IO.Path.Combine(_resolvedWebRoot, rel.Replace('/', System.IO.Path.DirectorySeparatorChar));
            return File.Exists(full);
        }


    }

}

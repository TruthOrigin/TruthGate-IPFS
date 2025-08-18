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

                    // If domain is mapped, always bypass
                    var mfsPath = DomainHelpers.GetMappedDomain(ctx);
                    if (!string.IsNullOrWhiteSpace(mfsPath))
                    {
                        ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                        return;
                    }

                    var path = (ctx.Request.Path.Value ?? "").ToLowerInvariant();

                    // Always bypass /login and /auth
                    if (path.StartsWith("/login") || path.StartsWith("/auth") || path.StartsWith("/api")
                    || path.StartsWith("/_content") || path.StartsWith("/_framework")
                    || path.StartsWith("/.well-known") || path.StartsWith("/_acme")
                    || path.StartsWith("/manifest.json")
                    )
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

        public static bool IsRequestingWwwrootFile(IWebHostEnvironment env, string requestPath)
        {
            if (env is null || string.IsNullOrEmpty(requestPath))
                return false;

            // Fallback if WebRootPath is null (can happen under some hosting setups)
            var webRoot = env?.WebRootPath;
            if (string.IsNullOrEmpty(webRoot))
            {
                // AppContext.BaseDirectory points at the publish folder at runtime
                var fallback = Path.Combine(AppContext.BaseDirectory, "wwwroot");
                if (Directory.Exists(fallback))
                    webRoot = fallback;
                else
                    return false; // No webroot → treat as not a static file
            }

            // Normalize the request path (/foo -> foo)
            var relative = requestPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);

            // Prevent path traversal
            if (relative.Contains("..")) return false;

            var full = Path.Combine(webRoot, relative);
            return File.Exists(full);
        }

    }

}

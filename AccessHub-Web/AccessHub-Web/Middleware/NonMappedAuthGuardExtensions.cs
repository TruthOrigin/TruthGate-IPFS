using TruthGate_Web.Utils;

namespace TruthGate_Web.Middleware
{
    public static class NonMappedAuthGuardExtensions
    {
        // Wraps your UseWhen guard for non-mapped domains
        public static IApplicationBuilder UseNonMappedDomainAuthGuard(this IApplicationBuilder app)
        {
            app.UseWhen(ctx => !DomainHelpers.IsMappedDomain(ctx), secured =>
            {
                secured.Use(async (ctx, next) =>
                {
                    var path = (ctx.Request.Path.Value ?? "").ToLowerInvariant();
                    if (path.StartsWith("/ipfs") || path.StartsWith("/api"))
                    {
                        await next();
                        return;
                    }

                    if (path.StartsWith("/login")
                        || path.StartsWith("/auth")
                        || path.StartsWith("/_framework")
                        || path.StartsWith("/_content")
                        || path.StartsWith("/_blazor")
                        || path.StartsWith("/css")
                        || path.StartsWith("/js")
                        || path.StartsWith("/lib")
                        || path.StartsWith("/images")
                        || path.StartsWith("/assets")
                        || path.StartsWith("/fonts")
                        || path == "/favicon.ico"
                        || path == "/manifest.webmanifest")
                    {
                        await next();
                        return;
                    }

                    if (HttpMethods.IsOptions(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method))
                    {
                        await next();
                        return;
                    }

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
    }
}

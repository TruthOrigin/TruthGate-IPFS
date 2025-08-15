using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;
using System.Security.Claims;
using TruthGate_Web.Services;

namespace TruthGate_Web.Endpoints
{
    public static class AuthEndpoints
    {
        public static IEndpointRouteBuilder MapTruthGateAuthEndpoints(this IEndpointRouteBuilder app)
        {
            // POST /auth/login
            app.MapPost("/auth/login", async (HttpContext ctx, IConfigService configSvc) =>
            {
                var form = await ctx.Request.ReadFormAsync();
                var usernameRaw = form["username"].ToString() ?? string.Empty;
                var password = form["password"].ToString() ?? string.Empty;
                var returnUrl = form["returnUrl"].ToString();

                var username = usernameRaw.Trim();

                // Pull snapshot of config from your singleton service
                var cfg = configSvc.Get();

                // Case-insensitive lookup
                var user = cfg.Users
                              .FirstOrDefault(u => string.Equals(u.UserName, username, StringComparison.OrdinalIgnoreCase));

                // Verify password hash (stored is hashed, input is plain)
                var ok = user != null && StringHasher.VerifyHash(password, user.PasswordHashed);

                if (!ok)
                {
                    var to = string.IsNullOrWhiteSpace(returnUrl)
                        ? "/login?e=1"
                        : $"/login?e=1&returnUrl={Uri.EscapeDataString(returnUrl)}";
                    return Results.Redirect(to);
                }

                var claims = new List<Claim> { new Claim(ClaimTypes.Name, user!.UserName) };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await ctx.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
                    });

                var safeReturn = (!string.IsNullOrWhiteSpace(returnUrl) && returnUrl.StartsWith("/") && !returnUrl.StartsWith("//"))
                    ? returnUrl
                    : "/";

                return Results.Redirect(safeReturn);
            })
            .AllowAnonymous()
            .DisableAntiforgery();

            // POST /auth/logout
            app.MapPost("/auth/logout", async (HttpContext ctx) =>
            {
                await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return Results.Redirect("/login");
            })
            .RequireAuthorization()
            .DisableAntiforgery();

            return app;
        }
    }
}

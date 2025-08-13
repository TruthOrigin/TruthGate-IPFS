using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;
using System.Security.Claims;

namespace TruthGate_Web.Endpoints
{
    public static class AuthEndpoints
    {
        public static IEndpointRouteBuilder MapTruthGateAuthEndpoints(this IEndpointRouteBuilder app)
        {
            app.MapPost("/auth/login", async (HttpContext ctx, IOptions<SecurityOptions> opt) =>
            {
                var form = await ctx.Request.ReadFormAsync();
                var username = form["username"].ToString();
                var password = form["password"].ToString();
                var returnUrl = form["returnUrl"].ToString();

                var user = opt.Value.Users
                    .FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));

                if (user is null || !RequestHelpers.SafeEquals(user.Password, password))
                {
                    var to = string.IsNullOrWhiteSpace(returnUrl) ? "/login?e=1" : $"/login?e=1&returnUrl={Uri.EscapeDataString(returnUrl)}";
                    return Results.Redirect(to);
                }

                var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Username) };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal,
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

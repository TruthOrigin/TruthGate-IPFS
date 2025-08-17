using Microsoft.AspNetCore.Mvc;
using TruthGate_Web.Configuration;
using TruthGate_Web.Services;

namespace TruthGate_Web.Extensions
{
    public static class WebApplicationExtensions
    {
        public static WebApplication UseStandardErrorPipeline(this WebApplication app)
        {
            var acmePrefix = new PathString("/.well-known/acme-challenge");

            app.MapGet("/.well-known/acme-challenge/{token}",
    ([FromRoute] string token, [FromServices] IAcmeChallengeStore store)
        => Results.Text(store.TryGetContent(token) ?? "", "text/plain"));

            app.MapPost("/_acme/issue/{host}", ([FromRoute] string host, [FromServices] LiveCertProvider live) =>
            {
                live.QueueIssueIfMissing(host.Trim().ToLowerInvariant());
                return Results.Ok(new { queued = host });
            });

            if (app.Environment.IsDevelopment())
            {
                app.UseWebAssemblyDebugging();
            }
            else
            {
                app.UseExceptionHandler("/Error", createScopeForErrors: true);

                // HSTS everywhere except ACME
                app.UseWhen(ctx => !ctx.Request.Path.StartsWithSegments(acmePrefix), branch =>
                {
                    branch.UseHsts();
                });
            }

            // Conditionally apply HTTPS redirection
            app.UseWhen(ctx =>
            {
                // 1) Skip ACME challenges
                if (ctx.Request.Path.StartsWithSegments(acmePrefix))
                    return false;

                // 2) Skip if host is in Config.Domains (to allow LE validation over HTTP)
                var cfg = ctx.RequestServices.GetRequiredService<IConfigService>().Get();
                var host = ctx.Request.Host.Host?.Trim().ToLowerInvariant();
                if (!string.IsNullOrEmpty(host) &&
                    cfg.Domains.Any(d => string.Equals(d.Domain, host, StringComparison.OrdinalIgnoreCase)))
                {
                    return false;
                }

                // otherwise, redirect to HTTPS
                return true;
            },
            branch =>
            {
                branch.UseHttpsRedirection();
            });

            app.UseResponseCompression();

            return app;
        }
    }
}

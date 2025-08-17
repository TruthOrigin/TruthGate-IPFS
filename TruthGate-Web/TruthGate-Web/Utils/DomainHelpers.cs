using Microsoft.Extensions.Options;
using System.Net;
using TruthGate_Web.Models;
using TruthGate_Web.Services;

namespace TruthGate_Web.Utils
{
    public static class DomainHelpers
    {
        /* public static string GetEffectiveHost(HttpContext ctx, IWebHostEnvironment env, DomainListOptions opt)
         {
             // In Development: ONLY emulate when DevEmulateHost is set. Otherwise, disable domain mapping.
             if (env.IsDevelopment())
             {
                 if (!string.IsNullOrWhiteSpace(opt.DevEmulateHost))
                     return opt.DevEmulateHost!.Trim();

                 return ""; // <— crucial: treat as "not a mapped domain" in dev unless explicitly emulating
             }

             // Production: use real host header
             return ctx.Request.Host.Host ?? "";
         }*/
        /// <summary>
        /// Returns the MFS folder for the mapped domain, or null if the current host is not mapped.
        /// The folder is built as "/{SitesRootBasePath}/{domain}" (default SitesRootBasePath = "production/sites").
        /// </summary>
        public static string? GetMappedDomain(HttpContext ctx)
        {
            var configSvc = ctx.RequestServices.GetRequiredService<IConfigService>();
            var configuration = ctx.RequestServices.GetRequiredService<IConfiguration>();
            var env = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();

            var hostToMatch = GetEffectiveHost(ctx);
            if (string.IsNullOrWhiteSpace(hostToMatch))
                return null;

            // If it's an IP address request, skip mapping
            if (IPAddress.TryParse(hostToMatch, out _))
                return null;

            var cfg = configSvc.Get();
            if (cfg?.Domains == null || cfg.Domains.Count == 0)
                return null;

            // Case-insensitive match against EdgeDomain.Domain
            var match = cfg.Domains.FirstOrDefault(d =>
                !string.IsNullOrWhiteSpace(d?.Domain) &&
                string.Equals(d.Domain.Trim(), hostToMatch.Trim(), StringComparison.OrdinalIgnoreCase));

            if (match == null)
                return null;

            var basePath = (configuration["SitesRootBasePath"] ?? "production/sites").Trim().Trim('/');
            // MFS path must start with '/'
            return "/" + basePath + "/" + match.Domain.Trim();
        }

        public static string? GetRedirectUrl(HttpContext ctx)
        {
            var configSvc = ctx.RequestServices.GetRequiredService<IConfigService>();

            var hostToMatch = GetEffectiveHost(ctx);
            if (string.IsNullOrWhiteSpace(hostToMatch))
                return null;

            // If it's an IP address request, skip mapping
            if (IPAddress.TryParse(hostToMatch, out _))
                return null;

            var cfg = configSvc.Get();
            if (cfg?.Domains == null || cfg.Domains.Count == 0)
                return null;

            // Case-insensitive match against EdgeDomain.Domain
            var match = cfg.Domains.FirstOrDefault(d =>
                !string.IsNullOrWhiteSpace(d?.Domain) &&
                string.Equals(d.Domain.Trim(), hostToMatch.Trim(), StringComparison.OrdinalIgnoreCase));

            if (match == null)
                return null;

            return match.RedirectUrl;
        }

        /// <summary>
        /// Returns the effective host for the current request.
        /// - In Development, honors appsettings: DevEmulateHost (if present).
        /// - Also (in Development), allows overrides via ?__host= and X-Dev-Host for convenience.
        /// - Otherwise, uses Request.Host.Host.
        /// </summary>
        public static string GetEffectiveHost(HttpContext ctx)
        {
            var env = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();
            var config = ctx.RequestServices.GetRequiredService<IConfiguration>();

            string host = ctx.Request.Host.Host ?? string.Empty;

            if (env.IsDevelopment())
            {
                var emulate = (config["DevEmulateHost"] ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(emulate))
                    return emulate;

                // Optional dev-only helpers
                var qHost = ctx.Request.Query["__host"].FirstOrDefault();
                var hHost = ctx.Request.Headers["X-Dev-Host"].FirstOrDefault();
                host = qHost ?? hHost ?? host;
            }

            return host;
        }


        /// <summary>
        /// True if current request host is mapped to an EdgeDomain in config.
        /// </summary>
        public static bool IsMappedDomain(HttpContext ctx)
        {
            return !string.IsNullOrWhiteSpace(GetMappedDomain(ctx));
        }
    }
}

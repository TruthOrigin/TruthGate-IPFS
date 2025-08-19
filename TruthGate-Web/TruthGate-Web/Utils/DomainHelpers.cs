using Microsoft.Extensions.Options;
using System.Net;
using TruthGate_Web.Models;
using TruthGate_Web.Services;

namespace TruthGate_Web.Utils
{
    public static class DomainHelpers
    {
        /// <summary>
        /// Returns the MFS folder for the mapped domain, or null if the current host is not mapped.
        /// The folder is built as "/{SitesRootBasePath}/{domain}" (default SitesRootBasePath = "production/sites").
        /// </summary>
        public static string? GetMappedDomain(HttpContext ctx)
        {
            var configSvc = ctx.RequestServices.GetRequiredService<IConfigService>();
            var configuration = ctx.RequestServices.GetRequiredService<IConfiguration>();

            var hostToMatch = GetEffectiveHost(ctx);
            if (string.IsNullOrWhiteSpace(hostToMatch)) return null;

            // If it's an IP address request, skip mapping
            if (IPAddress.TryParse(hostToMatch, out _)) return null;

            var cfg = configSvc.Get();
            if (cfg?.Domains == null || cfg.Domains.Count == 0) return null;

            // 1) Exact domain mapping first
            var direct = cfg.Domains.FirstOrDefault(d =>
                !string.IsNullOrWhiteSpace(d?.Domain) &&
                string.Equals(d.Domain.Trim(), hostToMatch.Trim(), StringComparison.OrdinalIgnoreCase));

            if (direct is not null)
            {
                var basePath = (configuration["SitesRootBasePath"] ?? "production/sites").Trim().Trim('/');
                return "/" + basePath + "/" + direct.Domain.Trim();
            }

            // 2) Wildcard IPNS mapping -> **emulate the domain's SITE folder**, not TGP
            var wc = cfg.IpnsWildCardSubDomain?.WildCardSubDomain?.Trim();
            if (!string.IsNullOrWhiteSpace(wc))
            {
                var maybeSitePath = TryResolveWildcardToSitePath(cfg, hostToMatch, wc, configuration);
                if (!string.IsNullOrWhiteSpace(maybeSitePath))
                    return maybeSitePath;
            }

            return null;
        }

        public static string? GetRedirectUrl(HttpContext ctx)
        {
            var configSvc = ctx.RequestServices.GetRequiredService<IConfigService>();

            var hostToMatch = GetEffectiveHost(ctx);
            if (string.IsNullOrWhiteSpace(hostToMatch)) return null;
            if (IPAddress.TryParse(hostToMatch, out _)) return null;

            var cfg = configSvc.Get();
            if (cfg?.Domains == null || cfg.Domains.Count == 0) return null;

            // Only exact domain matches can have redirects.
            var match = cfg.Domains.FirstOrDefault(d =>
                !string.IsNullOrWhiteSpace(d?.Domain) &&
                string.Equals(d.Domain.Trim(), hostToMatch.Trim(), StringComparison.OrdinalIgnoreCase));

            return match?.RedirectUrl;
        }

        // NEW: wildcard -> site path
        private static string? TryResolveWildcardToSitePath(
            TruthGate_Web.Models.Config cfg,
            string host,
            string wildcardRoot,
            IConfiguration configuration)
        {
            // wildcardRoot like "ipns.example.com"; host like "<peerOrKey>.ipns.example.com"
            if (!host.EndsWith("." + wildcardRoot, StringComparison.OrdinalIgnoreCase))
                return null;

            var leftPart = host[..^(wildcardRoot.Length + 1)];
            if (string.IsNullOrWhiteSpace(leftPart) || leftPart.Contains(' '))
                return null;

            // Use only the leftmost label as the identity
            var firstDot = leftPart.IndexOf('.');
            var keyOrPeer = firstDot >= 0 ? leftPart[..firstDot] : leftPart;
            if (string.IsNullOrWhiteSpace(keyOrPeer)) return null;

            // Find domain bound to this IPNS identity
            var ed = cfg.Domains.FirstOrDefault(d =>
                !string.IsNullOrWhiteSpace(d?.Domain) &&
                (
                    (!string.IsNullOrWhiteSpace(d.IpnsPeerId) && d.IpnsPeerId.Equals(keyOrPeer, StringComparison.OrdinalIgnoreCase)) ||
                    (!string.IsNullOrWhiteSpace(d.IpnsKeyName) && d.IpnsKeyName.Equals(keyOrPeer, StringComparison.OrdinalIgnoreCase))
                ));

            if (ed is null) return null;

            // Build SITE path (not TGP)
            var siteLeaf = string.IsNullOrWhiteSpace(ed.SiteFolderLeaf)
                ? (IpfsGateway.ToSafeLeaf(ed.Domain) ?? ed.Domain.ToLowerInvariant())
                : ed.SiteFolderLeaf;

            var basePath = (configuration["SitesRootBasePath"] ?? "production/sites").Trim().Trim('/');
            return IpfsGateway.NormalizeMfs($"/{basePath}/{siteLeaf}");
        }

        private static string? TryResolveWildcardToTgpPath(TruthGate_Web.Models.Config cfg, string host, string wildcardRoot)
        {
            // wildcardRoot is like "ipns.truthgate.io" (no "*.")
            // expected host is "<keyOrPeer>.ipns.truthgate.io"
            // Require at least one extra label in front:
            if (!host.EndsWith("." + wildcardRoot, StringComparison.OrdinalIgnoreCase))
                return null;

            var leftPart = host[..^(wildcardRoot.Length + 1)]; // strip ".<wildcardRoot>"
            if (string.IsNullOrWhiteSpace(leftPart) || leftPart.Contains(' '))
                return null;

            var keyOrPeer = leftPart; // the leftmost label(s) before the wildcard root — we use the full leftPart
                                      // Normalize to one label (common case "<peerId>.<wildcardRoot>")
                                      // If someone used nested labels, we only take the leftmost as identity:
            var firstDot = keyOrPeer.IndexOf('.');
            if (firstDot >= 0) keyOrPeer = keyOrPeer[..firstDot];

            if (string.IsNullOrWhiteSpace(keyOrPeer)) return null;

            // Find a domain whose IPNS identity matches this left label
            var ed = cfg.Domains.FirstOrDefault(d =>
                !string.IsNullOrWhiteSpace(d?.Domain) &&
                (
                    (!string.IsNullOrWhiteSpace(d.IpnsPeerId) && d.IpnsPeerId.Equals(keyOrPeer, StringComparison.OrdinalIgnoreCase)) ||
                    (!string.IsNullOrWhiteSpace(d.IpnsKeyName) && d.IpnsKeyName.Equals(keyOrPeer, StringComparison.OrdinalIgnoreCase))
                )
            );

            if (ed is null) return null;

            // For wildcard we map to the TGP bundle
            var siteLeaf = string.IsNullOrWhiteSpace(ed.SiteFolderLeaf)
                ? (IpfsGateway.ToSafeLeaf(ed.Domain) ?? ed.Domain.ToLowerInvariant())
                : ed.SiteFolderLeaf;

            var tgpLeaf = string.IsNullOrWhiteSpace(ed.TgpFolderLeaf)
                ? $"tgp-{siteLeaf.Replace('.', '-')}"
                : ed.TgpFolderLeaf;

            return IpfsGateway.NormalizeMfs($"/production/pinned/{tgpLeaf}");
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

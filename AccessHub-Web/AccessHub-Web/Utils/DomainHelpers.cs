using Microsoft.Extensions.Options;
using TruthGate_Web.Models;

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


        public static string GetEffectiveHost(HttpContext ctx, IWebHostEnvironment env, DomainListOptions opt)
        {
            if (env.IsDevelopment() && !string.IsNullOrWhiteSpace(opt.DevEmulateHost))
                return opt.DevEmulateHost!.Trim();

            var host = ctx.Request.Host.Host ?? "";
            if (env.IsDevelopment())
            {
                var qHost = ctx.Request.Query["__host"].FirstOrDefault();
                var hHost = ctx.Request.Headers["X-Dev-Host"].FirstOrDefault();
                host = qHost ?? hHost ?? host;
            }
            return host;
        }

        public static (string? FolderPath, string? Original) FindBestDomainFolderForHost(
            string host,
            IEnumerable<string> configuredDomains)
        {
            var h = host.ToLowerInvariant();
            string? best = null;

            foreach (var entry in configuredDomains)
            {
                if (string.IsNullOrWhiteSpace(entry)) continue;
                var e = entry.Trim().Trim('/').ToLowerInvariant();
                var lastSeg = e.Contains('/') ? e[(e.LastIndexOf('/') + 1)..] : e;
                if (!string.Equals(lastSeg, h, StringComparison.Ordinal)) continue;
                if (best == null || e.Length > best.Length) best = e;
            }

            if (best == null) return (null, null);
            return ("/" + best, best);
        }

        public static bool IsMappedDomain(HttpContext ctx)
        {
            var domainsOpt = ctx.RequestServices.GetRequiredService<IOptions<DomainListOptions>>().Value;
            var env = ctx.RequestServices.GetRequiredService<IWebHostEnvironment>();
            var hostToMatch = GetEffectiveHost(ctx, env, domainsOpt);
            if (string.IsNullOrWhiteSpace(hostToMatch)) return false;
            var (mfsPath, _) = FindBestDomainFolderForHost(hostToMatch, domainsOpt.Domains);
            return !string.IsNullOrWhiteSpace(mfsPath);
        }
    }
}

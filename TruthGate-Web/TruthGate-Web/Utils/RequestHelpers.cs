using System.Security.Cryptography;
using System.Text;

namespace TruthGate_Web.Utils
{
    public static class RequestHelpers
    {
        static bool LooksLikeCid(string seg)
        {
            if (string.IsNullOrWhiteSpace(seg)) return false;
            // very lightweight check: CIDv0 starts with Qm, CIDv1 (base32) starts with baf...
            return seg.StartsWith("Qm", StringComparison.Ordinal)
                || seg.StartsWith("baf", StringComparison.OrdinalIgnoreCase);
        }

        public static string? ExtractCidFromReferer(HttpRequest req)
        {
            // Referer: https://host/ipfs/<cid>/...
            var refUrl = req.Headers.Referer.ToString();
            if (string.IsNullOrEmpty(refUrl)) return null;
            try
            {
                var u = new Uri(refUrl);
                var segs = u.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                var ipfsIdx = Array.FindIndex(segs, s => string.Equals(s, "ipfs", StringComparison.OrdinalIgnoreCase));
                if (ipfsIdx >= 0 && ipfsIdx + 1 < segs.Length && LooksLikeCid(segs[ipfsIdx + 1]))
                    return segs[ipfsIdx + 1];
            }
            catch { /* ignore */ }
            return null;
        }

        public static string EnsureCidPrefix(string rest, string? fallbackCidFromReferer)
        {
            // rest is the part after /ipfs/
            var trimmed = (rest ?? "").TrimStart('/');
            var first = trimmed.Split('/', 2)[0];
            if (LooksLikeCid(first)) return trimmed; // already /<cid>/...

            // If no CID present, but we can infer from Referer, prefix it.
            if (!string.IsNullOrEmpty(fallbackCidFromReferer))
            {
                var remainder = trimmed; // e.g. "static/js/main.js"
                return $"{fallbackCidFromReferer}/{remainder}";
            }

            // No way to infer -> leave as-is (will 400 at gateway, but we prefer explicit 404)
            return trimmed;
        }
        public static bool SafeEquals(string a, string b)
        {
            var ab = Encoding.UTF8.GetBytes(a);
            var bb = Encoding.UTF8.GetBytes(b);
            return ab.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ab, bb);
        }

        public static bool IsHtmlRequest(HttpRequest req)
        {
            var accept = req.Headers.Accept.ToString();
            var path = req.Path.Value ?? "";
            if (accept.Contains("text/html", StringComparison.OrdinalIgnoreCase)) return true;
            if (string.IsNullOrEmpty(Path.GetExtension(path)) && accept.Contains("*/*")) return true;
            return false;
        }

        public static bool IsApiRequest(HttpRequest req)
        {
            var accept = req.Headers.Accept.ToString();
            return !string.IsNullOrEmpty(accept) && !accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);
        }

        public static string CombineTarget(string prefix, string rest, HttpContext ctx)
        {
            var q = ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value : "";
            return $"http://127.0.0.1:5001/{prefix}/{rest}{q}";
        }

        public static string CombineTargetHttp(string prefix, string rest, HttpContext ctx, int httpPort)
        {
            var q = ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value : "";
            return $"http://127.0.0.1:{httpPort}/{prefix}/{rest}{q}";
        }

        /// <summary>
        /// If the incoming request path is missing the IPNS name, try to recover it
        /// from the Referer header, assuming the referer looked like /ipns/&lt;name&gt;/...
        /// </summary>
        public static string? ExtractIpnsFromReferer(HttpRequest request)
        {
            var referer = request.Headers["Referer"].ToString();
            if (string.IsNullOrWhiteSpace(referer)) return null;

            if (!Uri.TryCreate(referer, UriKind.Absolute, out var uri))
                return null;

            var path = uri.AbsolutePath ?? string.Empty;
            // Expect: /ipns/<name>[/...]
            // We only need the first segment after /ipns/
            var trimmed = path.Trim('/');
            if (trimmed.Length == 0) return null;

            var parts = trimmed.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return null;

            if (!parts[0].Equals("ipns", StringComparison.OrdinalIgnoreCase)) return null;
            if (parts.Length < 2) return null;

            var candidate = parts[1].Trim();
            if (string.IsNullOrWhiteSpace(candidate)) return null;

            // Safety: no slashes in the "name" itself
            candidate = candidate.Replace('\\', '/').Trim('/');
            if (candidate.Contains('/') || candidate.Contains("..")) return null;

            return candidate;
        }

        /// <summary>
        /// Ensures the first segment of "rest" is an IPNS name.
        /// If missing, prefixes with the provided fallbackName.
        /// </summary>
        public static string EnsureIpnsPrefix(string rest, string? fallbackName)
        {
            var s = (rest ?? string.Empty);
            var trimmed = s.Trim('/');

            // If empty and we have a fallback, just return "<fallback>"
            if (string.IsNullOrWhiteSpace(trimmed))
                return string.IsNullOrWhiteSpace(fallbackName) ? s : $"{fallbackName}";

            var firstSeg = trimmed.Split('/', 2)[0];

            // If the caller already provided a first segment, keep as-is
            if (!string.IsNullOrWhiteSpace(firstSeg))
                return trimmed; // normalized to no leading slash

            // Otherwise, prefix with fallback if available
            return string.IsNullOrWhiteSpace(fallbackName)
                ? trimmed
                : $"{fallbackName}/{trimmed}";
        }
    }
}

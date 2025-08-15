namespace TruthGate_Web.Utils
{
    public static class IpfsIntrospection
    {
        public static async Task<string?> TryGetWebUiCidAsync(
            string webUiUrl,
            IHttpClientFactory clientFactory,
            CancellationToken ct)
        {
            var client = clientFactory.CreateClient();

            using var req = new HttpRequestMessage(HttpMethod.Head, webUiUrl);
            // Avoid conditional caching so we always get the canonical headers
            req.Headers.TryAddWithoutValidation("Cache-Control", "no-cache");
            req.Headers.TryAddWithoutValidation("Pragma", "no-cache");

            using var res = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!res.IsSuccessStatusCode) return null;

            // 1) Prefer X-Ipfs-Roots (cleanest)
            if (res.Headers.TryGetValues("X-Ipfs-Roots", out var roots))
            {
                var cid = roots.FirstOrDefault()?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(cid)) return cid;
            }

            // 2) Fallback: X-Ipfs-Path: /ipfs/<cid>/...
            if (res.Headers.TryGetValues("X-Ipfs-Path", out var paths))
            {
                var p = paths.FirstOrDefault();
                // Expected form: /ipfs/<cid>/...
                if (!string.IsNullOrWhiteSpace(p))
                {
                    var parts = p.Split('/', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && parts[0].Equals("ipfs", StringComparison.OrdinalIgnoreCase))
                        return parts[1];
                }
            }

            // 3) Last resort: ETag often equals the root CID for immutable assets
            if (res.Headers.ETag is { Tag: { } etag })
            {
                var trimmed = etag.Trim('"');
                if (!string.IsNullOrWhiteSpace(trimmed)) return trimmed;
            }

            return null;
        }
    }

}

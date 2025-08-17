using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Controllers
{
    [ApiController]
    [Route("api/truthgate/v1")]
    [AllowAnonymous]
    public sealed class TruthGateController : ControllerBase
    {
        private readonly IHttpClientFactory _http;

        public TruthGateController(IHttpClientFactory http)
        {
            _http = http;
        }

        // GET /api/truthgate/v1/GetDomainCid
        [HttpGet("GetDomainCid")]
        public async Task<IActionResult> GetDomainCid()
        {
            // derive the domain from the request host
            var host = HttpContext.Request.Host.Host;
            if (string.IsNullOrWhiteSpace(host))
                return BadRequest(new { error = "No host header present in request" });

            var leaf = ToSafeLeaf(host);
            if (leaf is null)
                return BadRequest(new { error = "Invalid host" });

            const string basePath = "/production/sites";
            var pathExact = NormalizeMfs($"{basePath}/{leaf}");
            var pathLower = NormalizeMfs($"{basePath}/{leaf.ToLowerInvariant()}");

            // No-cache stat
            string? cid = await IpfsGateway.ResolveMfsFolderToCidAsync(pathExact, _http);
            string chosenPath = pathExact;

            if (string.IsNullOrWhiteSpace(cid))
            {
                cid = await IpfsGateway.ResolveMfsFolderToCidAsync(pathLower, _http);
                chosenPath = pathLower;
            }

            if (string.IsNullOrWhiteSpace(cid))
                return NotFound(new { host, searched = new[] { pathExact, pathLower }, error = "site not found" });

            // Convert to v0/v1
            var cidv1 = await TryFormatCidAsync(cid!, version: 1, baseEncoding: "base32");
            var cidv0 = await TryFormatCidAsync(cid!, version: 0, baseEncoding: "base58btc");

            var payload = new
            {
                domain = host,
                mfsPath = chosenPath,
                cidOriginal = cid,
                cidv0,
                cidv1
            };

            return Ok(payload);
        }

        // --- helpers ---

        private static string NormalizeMfs(string path)
        {
            path = (path ?? string.Empty).Replace('\\', '/').Trim();
            if (!path.StartsWith("/")) path = "/" + path;
            path = "/" + string.Join("/", path.Split('/', StringSplitOptions.RemoveEmptyEntries));
            return path == "" ? "/" : path;
        }

        private static string? ToSafeLeaf(string input)
        {
            var s = (input ?? string.Empty).Trim();
            s = s.Replace('\\', '/').Trim('/');
            if (s.Length == 0) return null;
            if (s.Contains('/') || s.Contains("..")) return null;
            return s;
        }

        private async Task<string?> TryFormatCidAsync(string cid, int version, string baseEncoding)
        {
            var client = _http.CreateClient();
            var url = $"http://127.0.0.1:5001/api/v0/cid/format?arg={Uri.EscapeDataString(cid)}&v={version}&b={Uri.EscapeDataString(baseEncoding)}";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            using var res = await client.SendAsync(req);
            if (!res.IsSuccessStatusCode) return null;

            var text = await res.Content.ReadAsStringAsync();
            return text.Trim();
        }
    }
}

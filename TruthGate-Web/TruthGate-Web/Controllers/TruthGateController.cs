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
            // derive domain from host header
            var host = HttpContext?.Request?.Host.Host;
            if (string.IsNullOrWhiteSpace(host))
                return BadRequest(new { error = "No host header present in request" });

            var leaf = IpfsGateway.ToSafeLeaf(host);
            if (leaf is null)
                return BadRequest(new { error = "Invalid host" });

            const string basePath = "/production/sites";
            var pathExact = IpfsGateway.NormalizeMfs($"{basePath}/{leaf}");
            var pathLower = IpfsGateway.NormalizeMfs($"{basePath}/{leaf.ToLowerInvariant()}");

            // No-cache stat: try exact then lowercase
            string? cid = await IpfsGateway.ResolveMfsFolderToCidAsync(pathExact, _http);
            var chosenPath = pathExact;

            if (string.IsNullOrWhiteSpace(cid))
            {
                cid = await IpfsGateway.ResolveMfsFolderToCidAsync(pathLower, _http);
                chosenPath = pathLower;
            }

            if (string.IsNullOrWhiteSpace(cid))
                return NotFound(new { host, searched = new[] { pathExact, pathLower }, error = "site not found" });

            // Convert to both v1 (base32) and v0 (base58btc) via proxy-backed formatter
            var cidv1 = await IpfsGateway.FormatCidAsync(cid!, version: 1, baseEncoding: "base32", clientFactory: _http);
            var cidv0 = await IpfsGateway.FormatCidAsync(cid!, version: 0, baseEncoding: "base58btc", clientFactory: _http);

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
    }
}

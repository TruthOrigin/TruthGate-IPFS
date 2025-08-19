using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Globalization;
using System.Text.Json;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models.ControllerResponses;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Controllers
{
    [ApiController]
    [Route("api/truthgate/v1")]
    [AllowAnonymous]
    public sealed class TruthGateController : ControllerBase
    {
        private readonly IHttpClientFactory _http;
        private readonly IApiKeyProvider _keys;
        private readonly IMemoryCache _cache;
        private readonly IConfigService _config;

        public TruthGateController(
         IHttpClientFactory http,
         IApiKeyProvider keys,
         IConfigService config,
         IMemoryCache cache)
        {
            _http = http;
            _keys = keys;
            _config = config;
            _cache = cache;
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
            var cidv1 = await IpfsGateway.FormatCidAsync(cid!, version: 1, baseEncoding: "base32", clientFactory: _http, keys: _keys);
            var cidv0 = await IpfsGateway.FormatCidAsync(cid!, version: 0, baseEncoding: "base58btc", clientFactory: _http, keys: _keys);

            return Ok(new DomainCid()
            {
                Domain = host,
                CidV0 = cidv0,
                CidV1 = cidv1
            });
        }

        [HttpGet("GetDomainIpns")]
        public async Task<IActionResult> GetDomainIpns()
        {
            var host = HttpContext?.Request?.Host.Host;
            if (string.IsNullOrWhiteSpace(host))
                return BadRequest(new { error = "No host header present in request" });

            var domain = NormalizeHost(host);
            if (string.IsNullOrWhiteSpace(domain))
                return BadRequest(new { error = "Invalid host" });

            var cfg = _config.Get();
            var ed = (cfg.Domains ?? new()).FirstOrDefault(d =>
                string.Equals(d.Domain?.Trim(), domain, StringComparison.OrdinalIgnoreCase));

            if (ed is null)
                return NotFound(new { domain, error = "Domain not found in config" });

            // Key info (no implicit creation here)
            var peerId = ed.IpnsPeerId;
            if (string.IsNullOrWhiteSpace(peerId) && !string.IsNullOrWhiteSpace(ed.IpnsKeyName))
                peerId = await TryGetKeyIdAsync(ed.IpnsKeyName!, _http, _keys);

            // Pointer/TGP info (always attempt, with short cache)
            var tgpLeaf = string.IsNullOrWhiteSpace(ed.TgpFolderLeaf)
                            ? $"tgp-{(IpfsGateway.ToSafeLeaf(ed.Domain) ?? ed.Domain).Replace('.', '-')}"
                            : ed.TgpFolderLeaf;

            var tgpFolder = $"/production/pinned/{tgpLeaf}";

            var status = await GetTgpStatusCachedAsync(tgpFolder);

            var info = new DomainIpnsInfo
            {
                Domain = domain,
                IpnsKeyName = ed.IpnsKeyName,
                IpnsPeerId = peerId,
                IpnsPath = string.IsNullOrWhiteSpace(peerId) ? null : $"/ipns/{peerId}",
                TgpFolder = tgpFolder,
                TgpCid = status.TgpCid,
                CurrentCid = status.CurrentCid,
                LastPublishedCid = ed.LastPublishedCid,
                Warning = string.IsNullOrWhiteSpace(peerId)
                    ? "IPNS key not found on this node. Import the backup or create one for this domain."
                    : null
            };

            return Ok(info);
        }

        // ---------- helpers ----------

        private async Task<(string? TgpCid, string? CurrentCid)> GetTgpStatusCachedAsync(string tgpFolder)
        {
            var key = $"tgp:{tgpFolder}";
            if (_cache.TryGetValue<(string?, string?)>(key, out var cached))
                return cached;

            string? tgpCid = null;
            string? current = null;

            // files/stat on folder
            {
                var rest = $"/api/v0/files/stat?arg={Uri.EscapeDataString(IpfsGateway.NormalizeMfs(tgpFolder))}";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
                if (res.IsSuccessStatusCode)
                {
                    var txt = await res.Content.ReadAsStringAsync();
                    try { using var doc = JsonDocument.Parse(txt); tgpCid = doc.RootElement.GetProperty("Hash").GetString(); }
                    catch { /* ignore */ }
                }
            }

            // files/read /tgp.json
            {
                var rest = $"/api/v0/files/read?arg={Uri.EscapeDataString(IpfsGateway.NormalizeMfs($"{tgpFolder}/tgp.json"))}";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
                if (res.IsSuccessStatusCode)
                {
                    var txt = await res.Content.ReadAsStringAsync();
                    try
                    {
                        using var doc = JsonDocument.Parse(txt);
                        var v = doc.RootElement.TryGetProperty("current", out var cur) ? cur.GetString() : null;
                        if (!string.IsNullOrWhiteSpace(v))
                            current = v!.StartsWith("/ipfs/", StringComparison.Ordinal) ? v[6..] : v;
                    }
                    catch { /* ignore */ }
                }
            }

            var tuple = (tgpCid, current);
            _cache.Set(key, tuple, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(45) // short TTL per TGP spec vibe
            });

            return tuple;
        }

        private static async Task<string?> TryGetKeyIdAsync(string keyName, IHttpClientFactory http, IApiKeyProvider keys)
        {
            using var res = await ApiProxyEndpoints.SendProxyApiRequest("/api/v0/key/list", http, keys);
            if (!res.IsSuccessStatusCode) return null;
            var txt = await res.Content.ReadAsStringAsync();
            try
            {
                using var doc = JsonDocument.Parse(txt);
                if (doc.RootElement.TryGetProperty("Keys", out var arr) && arr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var k in arr.EnumerateArray())
                    {
                        var n = k.TryGetProperty("Name", out var np) ? np.GetString() : null;
                        if (string.Equals(n, keyName, StringComparison.OrdinalIgnoreCase))
                            return k.TryGetProperty("Id", out var idp) ? idp.GetString() : null;
                    }
                }
            }
            catch { }
            return null;
        }

        private static string NormalizeHost(string input)
        {
            var s = (input ?? "").Trim().TrimEnd('.');
            try { s = new IdnMapping().GetAscii(s); } catch { return ""; }
            return s.ToLowerInvariant();
        }
    }
}

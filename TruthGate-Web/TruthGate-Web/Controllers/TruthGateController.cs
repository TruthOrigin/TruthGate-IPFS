using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Globalization;
using System.Text.Json;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
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
            if (!TryResolveEffectiveDomain(out var ed, out var effectiveDomain, out var problem))
                return problem!;
            Response.Headers["X-TruthGate-Effective-Domain"] = effectiveDomain!;

            var host = ed!.Domain;
            var leaf = IpfsGateway.ToSafeLeaf(host) ?? host.ToLowerInvariant();

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
            if (!TryResolveEffectiveDomain(out var ed, out var effectiveDomain, out var problem))
                return problem!;
            Response.Headers["X-TruthGate-Effective-Domain"] = effectiveDomain!;

            var domain = ed!.Domain;

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
                //IpnsKeyName = ed.IpnsKeyName,
                IpnsPeerId = peerId,
                //IpnsPath = string.IsNullOrWhiteSpace(peerId) ? null : $"/ipns/{peerId}",
                //TgpFolder = tgpFolder,
                TgpCid = status.TgpCid,
                CurrentCid = status.CurrentCid,
                LastPublishedCid = ed.LastPublishedCid
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

        // --- Host → EdgeDomain resolver --------------------------------------------

        private bool TryResolveEffectiveDomain(
            out EdgeDomain? edge,
            out string? effectiveDomain,
            out IActionResult? problem)
        {
            edge = null;
            effectiveDomain = null;
            problem = null;

            var host = HttpContext?.Request?.Host.Host;
            if (string.IsNullOrWhiteSpace(host))
            {
                problem = BadRequest(new { error = "No host header present in request" });
                return false;
            }

            var cfg = _config.Get();
            var normHost = NormalizeHost(host);
            if (string.IsNullOrWhiteSpace(normHost))
            {
                problem = BadRequest(new { error = "Invalid host" });
                return false;
            }

            // 1) Exact apex match
            var direct = (cfg.Domains ?? new()).FirstOrDefault(d =>
                string.Equals(d.Domain?.Trim(), normHost, StringComparison.OrdinalIgnoreCase));
            if (direct is not null)
            {
                edge = direct;
                effectiveDomain = direct.Domain;
                return true;
            }

            // 2) IPNS wildcard: {left}.ipns.{base}
            var (baseHost, wildcardEnabled) = GetIpnsWildcardBase(); // your existing method
            if (!string.IsNullOrWhiteSpace(baseHost) &&
                (normHost == baseHost || normHost.EndsWith("." + baseHost, StringComparison.Ordinal)))
            {
                var left = LeftLabel(normHost);
                if (!string.IsNullOrWhiteSpace(left))
                {
                    // NOTE: do NOT gate on apex UseSSL — wildcard policy is independent
                    foreach (var d in cfg.Domains ?? Enumerable.Empty<EdgeDomain>())
                    {
                        if (!string.IsNullOrWhiteSpace(d.IpnsPeerId) &&
                            string.Equals(left, d.IpnsPeerId.Trim(), StringComparison.OrdinalIgnoreCase))
                        {
                            edge = d;
                            effectiveDomain = d.Domain;
                            return true;
                        }
                        if (!string.IsNullOrWhiteSpace(d.IpnsKeyName) &&
                            string.Equals(left, d.IpnsKeyName.Trim(), StringComparison.OrdinalIgnoreCase))
                        {
                            edge = d;
                            effectiveDomain = d.Domain;
                            return true;
                        }
                    }
                }
            }

            problem = NotFound(new { host = normHost, error = "Could not map host to a configured domain (apex or IPNS wildcard)" });
            return false;
        }

        private static string? LeftLabel(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return null;
            var i = host.IndexOf('.');
            return i <= 0 ? null : host[..i];
        }
        private (string? baseHost, bool enabled) GetIpnsWildcardBase()
        {
            var cfg = _config.Get();
            var raw = cfg?.IpnsWildCardSubDomain?.WildCardSubDomain;
            var enabled = bool.TryParse(cfg?.IpnsWildCardSubDomain?.UseSSL, out var ok) && ok;
            if (string.IsNullOrWhiteSpace(raw)) return (null, enabled);
            var baseHost = NormalizeHost(raw);
            return (string.IsNullOrWhiteSpace(baseHost) ? null : baseHost, enabled);
        }

    }
}

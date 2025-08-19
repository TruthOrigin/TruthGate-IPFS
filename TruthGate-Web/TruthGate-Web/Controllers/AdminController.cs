using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Controllers
{
    [ApiController]
    [Route("api/truthgate/v1/admin")]
    [ServiceFilter(typeof(AdminApiKeyOnlyFilter))]
    public class AdminController : ControllerBase
    {
        private readonly IConfigService _cfg;
        private readonly IPublishQueue _queue;
        private readonly IHttpClientFactory _http;
        private readonly IApiKeyProvider _keys;

        public AdminController(IConfigService cfg, IPublishQueue q, IHttpClientFactory http, IApiKeyProvider keys)
            => (_cfg, _queue, _http, _keys) = (cfg, q, http, keys);

        // -------- PUBLISH (multipart). Accepts many files with paths.
        [HttpPost("{domain}/publish")]
        [DisableRequestSizeLimit]
        [RequestFormLimits(ValueCountLimit = int.MaxValue, MultipartBodyLengthLimit = long.MaxValue)]
        public async Task<IActionResult> Publish(string domain, CancellationToken ct)
        {
            var cfg = _cfg.Get();
            var ed = (cfg.Domains ?? new()).FirstOrDefault(d => d.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase));
            if (ed is null) return NotFound("Domain not found.");

            if (string.IsNullOrWhiteSpace(ed.SiteFolderLeaf))
                ed.SiteFolderLeaf = IpfsGateway.ToSafeLeaf(ed.Domain) ?? ed.Domain.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(ed.TgpFolderLeaf))
                ed.TgpFolderLeaf = $"tgp-{ed.SiteFolderLeaf.Replace('.', '-')}";

            var form = await Request.ReadFormAsync(ct);
            if (form.Files.Count == 0) return BadRequest("No files.");

            // -------- normalize relative paths from form field names ----------
            static string Clean(string? s)
            {
                var p = (s ?? "").Replace('\\', '/').Trim();
                while (p.StartsWith("./", StringComparison.Ordinal)) p = p[2..];
                p = p.TrimStart('/');
                p = string.Join('/', p.Split('/', StringSplitOptions.RemoveEmptyEntries));
                if (p.Contains("..", StringComparison.Ordinal)) throw new InvalidOperationException("Path traversal not allowed.");
                return string.IsNullOrWhiteSpace(p) ? throw new InvalidOperationException("Bad path.") : p;
            }

            var tempList = new List<(IFormFile f, string rel)>(form.Files.Count);
            foreach (var f in form.Files)
            {
                // We expect the *field name* to carry the relative path; fallback to filename.
                var relRaw = !string.IsNullOrWhiteSpace(f.Name) ? f.Name : f.FileName;
                var rel = Clean(relRaw);
                tempList.Add((f, rel));
            }

            // If every path starts with the same first folder (e.g., "wwwroot"), strip it.
            static string CommonFirstFolderPrefix(IEnumerable<string> rels)
            {
                string? first = null;
                foreach (var r in rels)
                {
                    var idx = r.IndexOf('/');
                    var head = idx < 0 ? r : r[..idx];
                    if (string.IsNullOrEmpty(first)) first = head;
                    else if (!string.Equals(first, head, StringComparison.OrdinalIgnoreCase)) return "";
                }
                return first ?? "";
            }

            var prefix = CommonFirstFolderPrefix(tempList.Select(t => t.rel));
            if (!string.IsNullOrEmpty(prefix))
            {
                // Don’t strip if prefix *is* "index.html"
                if (!prefix.Equals("index.html", StringComparison.OrdinalIgnoreCase))
                {
                    for (int i = 0; i < tempList.Count; i++)
                    {
                        var r = tempList[i].rel;
                        if (r.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase))
                            tempList[i] = (tempList[i].f, r[(prefix.Length + 1)..]);
                    }
                }
            }

            // If we still don’t have root index.html but have X/index.html, strip that X/ from all.
            if (!tempList.Any(t => t.rel.Equals("index.html", StringComparison.OrdinalIgnoreCase)))
            {
                var firstIx = tempList.Select(t => t.rel)
                                      .FirstOrDefault(r => r.EndsWith("/index.html", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrEmpty(firstIx))
                {
                    var baseFolder = firstIx[..firstIx.LastIndexOf('/')];
                    for (int i = 0; i < tempList.Count; i++)
                    {
                        var r = tempList[i].rel;
                        if (r.StartsWith(baseFolder + "/", StringComparison.OrdinalIgnoreCase))
                            tempList[i] = (tempList[i].f, r[(baseFolder.Length + 1)..]);
                    }
                }
            }

            // Final validation: require root index.html
            if (!tempList.Any(t => t.rel.Equals("index.html", StringComparison.OrdinalIgnoreCase)))
                return BadRequest("No index.html detected at site root after normalization.");

            // -------- stream to MFS staging now (avoid carrying streams into the queue) ----------
            var jobId = Guid.NewGuid().ToString("N");
            var stagingRoot = IpfsGateway.NormalizeMfs($"/staging/sites/{ed.SiteFolderLeaf}/{jobId}");
            await IpfsAdmin.FilesMkdirAsync(stagingRoot, _http, _keys, ct);

            foreach (var (f, rel) in tempList)
            {
                var dest = IpfsGateway.NormalizeMfs($"{stagingRoot}/{rel}");
                using var src = f.OpenReadStream();
                var contentType = string.IsNullOrWhiteSpace(f.ContentType) ? "application/octet-stream" : f.ContentType;
                await IpfsAdmin.FilesWriteAsync(dest, src, _http, _keys, contentType, ct);
            }

            // -------- enqueue lightweight publish job that references the staged folder ----------
            var job = new PublishJob(
                Domain: ed.Domain,
                SiteLeaf: ed.SiteFolderLeaf,
                TgpLeaf: ed.TgpFolderLeaf,
                StagingRoot: stagingRoot,
                Note: $"API publish {DateTimeOffset.UtcNow:o}");

            var enqueuedId = await _queue.EnqueueAsync(job);
            return Accepted(new { jobId = enqueuedId, staged = true, files = tempList.Count });
        }

        // -------- BACKUP (returns a JSON file)
        public sealed record DomainBackup(
            string Domain, string SiteFolderLeaf, string TgpFolderLeaf,
            string IpnsKeyName, string IpnsPeerId, string? LastPublishedCid,
            int EncVersion, string SaltB64, string CipherB64);

        [HttpGet("{domain}/backup")]
        public async Task<IActionResult> Backup(string domain, [FromQuery] string passphrase)
        {
            var cfg = _cfg.Get();
            var ed = (cfg.Domains ?? new()).FirstOrDefault(d => d.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase));
            if (ed is null) return NotFound("Domain not found.");
            if (string.IsNullOrWhiteSpace(passphrase)) return BadRequest("Passphrase required.");

            if (string.IsNullOrWhiteSpace(ed.SiteFolderLeaf))
                ed.SiteFolderLeaf = IpfsGateway.ToSafeLeaf(ed.Domain) ?? ed.Domain.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(ed.TgpFolderLeaf))
                ed.TgpFolderLeaf = $"tgp-{ed.SiteFolderLeaf.Replace('.', '-')}";

            var ipnsName = string.IsNullOrWhiteSpace(ed.IpnsKeyName)
                ? $"tg-{IpfsGateway.ToSafeLeaf(ed.Domain)}"
                : ed.IpnsKeyName;

            // Ensure key exists and get Id
            var (_, id) = await IpfsAdmin.EnsureKeyAsync(ipnsName, _http, _keys);

            // Persist to config so UI can show it later
            await _cfg.UpdateAsync(c =>
            {
                var t = (c.Domains ??= new()).FirstOrDefault(x => x.Domain.Equals(ed.Domain, StringComparison.OrdinalIgnoreCase));
                if (t is null) return;
                t.SiteFolderLeaf = ed.SiteFolderLeaf;
                t.TgpFolderLeaf = ed.TgpFolderLeaf;
                t.IpnsKeyName = ipnsName;
                t.IpnsPeerId = id;
            });

            var armored = await IpfsAdmin.KeyExportArmoredAsync(ipnsName, passphrase, _http, _keys);
            var (saltB64, cipherB64) = CryptoBox.Seal(armored, passphrase);

            var backup = new DomainBackup(
                Domain: ed.Domain,
                SiteFolderLeaf: ed.SiteFolderLeaf,
                TgpFolderLeaf: ed.TgpFolderLeaf,
                IpnsKeyName: ipnsName,
                IpnsPeerId: id,
                LastPublishedCid: ed.LastPublishedCid,
                EncVersion: 1, SaltB64: saltB64, CipherB64: cipherB64);

            var json = JsonSerializer.Serialize(backup, new JsonSerializerOptions { WriteIndented = true });
            var bytes = Encoding.UTF8.GetBytes(json);
            return File(bytes, "application/json", $"{ed.SiteFolderLeaf}-truthgate-backup.json");
        }


        // -------- IMPORT (backup JSON)
        [HttpPost("import")]
        public async Task<IActionResult> Import([FromQuery] string passphrase)
        {
            var form = await Request.ReadFormAsync();
            var file = form.Files.FirstOrDefault();
            if (file is null) return BadRequest("Missing backup file.");
            if (string.IsNullOrWhiteSpace(passphrase)) return BadRequest("Passphrase required.");

            using var s = file.OpenReadStream();
            using var sr = new StreamReader(s, Encoding.UTF8);
            var text = await sr.ReadToEndAsync();
            var b = JsonSerializer.Deserialize<DomainBackup>(text) ?? throw new InvalidOperationException("Invalid backup.");

            // Decrypt armored key + import into node keystore under the stored keyname (or keyname+"-import" if collides)
            var armored = CryptoBox.Open(b.SaltB64, b.CipherB64, passphrase);
            var importName = b.IpnsKeyName;

            // If key exists, we can reuse; else import
            var (name, id) = await IpfsAdmin.EnsureKeyAsync(importName, _http, _keys);
            if (!string.Equals(id, b.IpnsPeerId, StringComparison.OrdinalIgnoreCase))
            {
                // Try import with suffix
                importName = importName + "-import";
                (name, id) = await IpfsAdmin.KeyImportArmoredAsync(importName, passphrase, armored, _http, _keys);
            }

            await _cfg.UpdateAsync(cfg =>
            {
                cfg.Domains ??= new List<EdgeDomain>();
                var existing = cfg.Domains.FirstOrDefault(d => d.Domain.Equals(b.Domain, StringComparison.OrdinalIgnoreCase));
                if (existing is null)
                {
                    cfg.Domains.Add(new EdgeDomain
                    {
                        Domain = b.Domain,
                        UseSSL = "true",
                        SiteFolderLeaf = b.SiteFolderLeaf,
                        TgpFolderLeaf = b.TgpFolderLeaf,
                        IpnsKeyName = importName,
                        IpnsPeerId = id,
                        LastPublishedCid = b.LastPublishedCid,
                        IpnsKeyEncVersion = 1,
                        IpnsKeySaltB64 = b.SaltB64,
                        IpnsKeyCipherB64 = b.CipherB64
                    });
                }
                else
                {
                    existing.SiteFolderLeaf = b.SiteFolderLeaf;
                    existing.TgpFolderLeaf = b.TgpFolderLeaf;
                    existing.IpnsKeyName = importName;
                    existing.IpnsPeerId = id;
                    existing.LastPublishedCid = b.LastPublishedCid;
                    existing.IpnsKeyEncVersion = 1;
                    existing.IpnsKeySaltB64 = b.SaltB64;
                    existing.IpnsKeyCipherB64 = b.CipherB64;
                }
            });

            // Optional: restore site folder content if LastPublishedCid exists
            if (!string.IsNullOrWhiteSpace(b.LastPublishedCid))
            {
                var siteTarget = IpfsGateway.NormalizeMfs($"/production/sites/{b.SiteFolderLeaf}");
                // recreate folder from CID (staged swap is overkill here; straight cp is fine)
                await IpfsAdmin.FilesCpFromIpfsAsync(b.LastPublishedCid!, siteTarget, _http, _keys);
                // and pin
                var rest = $"/api/v0/pin/add?arg={Uri.EscapeDataString(b.LastPublishedCid!)}&recursive=true";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
                res.EnsureSuccessStatusCode();
            }

            return Ok(new { imported = b.Domain, key = importName, peerId = id });
        }
    }

}

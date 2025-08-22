using Microsoft.AspNetCore.Components.Forms;
using System.Text.Json;
using System.Text;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Interfaces;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;
using static TruthGate_Web.Components.Pages.Settings.Shared.PublishDialog;

namespace TruthGate_Web.Services
{
    public sealed class TruthGatePublishService : ITruthGatePublishService
    {
        private readonly IConfigService _cfg;
        private readonly IPublishQueue _queue;
        private readonly IHttpClientFactory _http;
        private readonly IApiKeyProvider _keys;

        public TruthGatePublishService(IConfigService cfg, IPublishQueue queue, IHttpClientFactory http, IApiKeyProvider keys)
            => (_cfg, _queue, _http, _keys) = (cfg, queue, http, keys);

        // ---------- helpers (same as your controller logic) ----------
        private static string Clean(string? s)
        {
            var p = (s ?? "").Replace('\\', '/').Trim();
            while (p.StartsWith("./", StringComparison.Ordinal)) p = p[2..];
            p = p.TrimStart('/');

            var parts = p.Split('/', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                if (part == "." || part == "..")
                    throw new InvalidOperationException("Path traversal not allowed.");
            }

            if (parts.Length == 0)
                throw new InvalidOperationException("Bad path.");

            return string.Join('/', parts);
        }


        private static string CommonFirstFolderPrefix(IEnumerable<string> rels)
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

        private async Task<(EdgeDomain Ed, string SiteLeaf, string TgpLeaf)> EnsureDomainLeavesAsync(string domain)
        {
            var cfg = _cfg.Get();
            var ed = (cfg.Domains ?? new()).FirstOrDefault(d => d.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                     ?? throw new InvalidOperationException("Domain not found.");
            if (string.IsNullOrWhiteSpace(ed.SiteFolderLeaf))
                ed.SiteFolderLeaf = IpfsGateway.ToSafeLeaf(ed.Domain) ?? ed.Domain.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(ed.TgpFolderLeaf))
                ed.TgpFolderLeaf = $"tgp-{ed.SiteFolderLeaf.Replace('.', '-')}";
            return (ed, ed.SiteFolderLeaf!, ed.TgpFolderLeaf!);
        }


        public sealed record PublishItem(
            string Rel,
            string ContentType,
            Func<CancellationToken, Task<Stream>> OpenAsync
        );

        public async Task<(string JobId, int FileCount)> PublishFromFormAsync(
            string domain,
            IFormCollection form,
            CancellationToken ct)
        {
            if (form?.Files is null || form.Files.Count == 0)
                throw new InvalidOperationException("No files.");

            var items = FromForm(form.Files);
            return await PublishCoreAsync(domain, items, note: "API publish", ct);
        }

        public async Task<(string JobId, int FileCount)> PublishFromBrowserFilesAsync(
            string domain,
            IEnumerable<(IBrowserFile File, string RelPath)> files,
            CancellationToken ct)
        {
            if (files is null) throw new InvalidOperationException("No files.");

            var items = FromBrowserFiles(files);
            if (items.Count == 0)
                throw new InvalidOperationException("No files.");

            return await PublishCoreAsync(domain, items, note: "Direct publish", ct);
        }

        // ----------------------------------------------------------
        // Adapters (source-specific translation only)
        // ----------------------------------------------------------

        private List<PublishItem> FromForm(IFormFileCollection files)
        {
            var list = new List<(IFormFile f, string rel)>(files.Count);

            foreach (var f in files)
            {
                var relRaw = !string.IsNullOrWhiteSpace(f.FileName) ? f.FileName : f.Name;
                var rel = Clean(relRaw).Replace('\\', '/').TrimStart('/');
                list.Add((f, rel));
            }

            // Turn into PublishItem with sync-open wrapper (IFormFile has no async OpenReadStream)
            return list.Select(t =>
            {
                var contentType = string.IsNullOrWhiteSpace(t.f.ContentType) ? "application/octet-stream" : t.f.ContentType;
                return new PublishItem(
                    Rel: t.rel,
                    ContentType: contentType,
                    OpenAsync: _ => Task.FromResult<Stream>(t.f.OpenReadStream()) // best available
                );
            }).ToList();
        }

        private List<PublishItem> FromBrowserFiles(IEnumerable<(IBrowserFile File, string RelPath)> files)
        {
            var list = files
                .Where(n => n.File is not null && n.File.Size > 0)
                .Select(n =>
                {
                    var rel = Clean(n.RelPath ?? string.Empty).Replace('\\', '/').TrimStart('/');
                    return (f: n.File, rel);
                })
                .ToList();

            return list.Select(t =>
            {
                // Prefer async JS open when available
                Func<CancellationToken, Task<Stream>> openAsync =
                    t.f is JsBrowserFile jsf
                        ? (ct2) => jsf.OpenReadStreamAsync(long.MaxValue, ct2)
                        : (ct2) => Task.FromResult<Stream>(t.f.OpenReadStream(long.MaxValue, ct2));

                var contentType = string.IsNullOrWhiteSpace(t.f.ContentType) ? "application/octet-stream" : t.f.ContentType;

                return new PublishItem(
                    Rel: t.rel,
                    ContentType: contentType,
                    OpenAsync: openAsync
                );
            }).ToList();
        }

        // ----------------------------------------------------------
        // One pipeline to rule them all
        // ----------------------------------------------------------

        private async Task<(string JobId, int FileCount)> PublishCoreAsync(
            string domain,
            List<PublishItem> items,
            string note,
            CancellationToken ct)
        {
            if (items.Count == 0)
                throw new InvalidOperationException("No files.");

            var (ed, siteLeaf, tgpLeaf) = await EnsureDomainLeavesAsync(domain);

            // 1) Normalize relative paths (strip common folder, ensure root index.html)
            NormalizeRelativesInPlace(items);

            if (!items.Any(t => t.Rel.Equals("index.html", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("No index.html detected at site root after normalization.");

            // 2) Stage to MFS
            var jobId = Guid.NewGuid().ToString("N");
            var stagingRoot = IpfsGateway.NormalizeMfs($"/staging/sites/{siteLeaf}/{jobId}");
            await IpfsAdmin.FilesMkdirAsync(stagingRoot, _http, _keys, ct);

            foreach (var it in items)
            {
                var dest = IpfsGateway.NormalizeMfs($"{stagingRoot}/{it.Rel}");
                try
                {
                    await using var src = await it.OpenAsync(ct);
                    await IpfsAdmin.FilesWriteAsync(dest, src, _http, _keys, it.ContentType, ct);
                }
                catch (InvalidOperationException ex)
                {
                    // Preserve original rel for debugging; OpenAsync keeps source-specific behavior encapsulated
                    throw new InvalidOperationException($"Path traversal not allowed for '{it.Rel}'. {ex.Message}");
                }
            }

            // 3) Enqueue publish job
            var job = new PublishJob(
                Domain: ed.Domain,
                SiteLeaf: siteLeaf,
                TgpLeaf: tgpLeaf,
                StagingRoot: stagingRoot,
                Note: $"{note} {DateTimeOffset.UtcNow:o}");

            var enqueuedId = await _queue.EnqueueAsync(job);
            return (enqueuedId, items.Count);
        }

        // ----------------------------------------------------------
        // Normalization helpers (shared, deterministic)
        // ----------------------------------------------------------

        private void NormalizeRelativesInPlace(List<PublishItem> items)
        {
            // Strip common first folder
            var prefix = CommonFirstFolderPrefix(items.Select(t => t.Rel));
            if (!string.IsNullOrEmpty(prefix) && !prefix.Equals("index.html", StringComparison.OrdinalIgnoreCase))
            {
                for (int i = 0; i < items.Count; i++)
                {
                    var r = items[i].Rel;
                    if (r.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase))
                        items[i] = items[i] with { Rel = r[(prefix.Length + 1)..] };
                }
            }

            // If still no root index.html, strip X/ where X/index.html exists
            if (!items.Any(t => t.Rel.Equals("index.html", StringComparison.OrdinalIgnoreCase)))
            {
                var firstIx = items.Select(t => t.Rel)
                                   .FirstOrDefault(r => r.EndsWith("/index.html", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrEmpty(firstIx))
                {
                    var baseFolder = firstIx[..firstIx.LastIndexOf('/')];
                    for (int i = 0; i < items.Count; i++)
                    {
                        var r = items[i].Rel;
                        if (r.StartsWith(baseFolder + "/", StringComparison.OrdinalIgnoreCase))
                            items[i] = items[i] with { Rel = r[(baseFolder.Length + 1)..] };
                    }
                }
            }
        }




        // ---------- Backup / Export ----------
        public async Task<(byte[] Bytes, string FileName)> ExportBackupAsync(string domain, string passphrase, CancellationToken ct)
        {
            var cfg = _cfg.Get();
            var ed = (cfg.Domains ?? new()).FirstOrDefault(d => d.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                     ?? throw new InvalidOperationException("Domain not found.");
            if (string.IsNullOrWhiteSpace(passphrase)) throw new InvalidOperationException("Passphrase required.");

            if (string.IsNullOrWhiteSpace(ed.SiteFolderLeaf))
                ed.SiteFolderLeaf = IpfsGateway.ToSafeLeaf(ed.Domain) ?? ed.Domain.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(ed.TgpFolderLeaf))
                ed.TgpFolderLeaf = $"tgp-{ed.SiteFolderLeaf.Replace('.', '-')}";

            var ipnsName = string.IsNullOrWhiteSpace(ed.IpnsKeyName)
                ? $"tg-{IpfsGateway.ToSafeLeaf(ed.Domain)}"
                : ed.IpnsKeyName;

            var (_, id) = await IpfsAdmin.EnsureKeyAsync(ipnsName, _http, _keys);

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
            var fileName = $"{ed.SiteFolderLeaf}-truthgate-backup.json";
            return (bytes, fileName);
        }

        // ---------- Import ----------
        public async Task<(string ImportedDomain, string KeyName, string PeerId)> ImportBackupAsync(Stream backupJson, string passphrase, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(passphrase)) throw new InvalidOperationException("Passphrase required.");

            using var sr = new StreamReader(backupJson, Encoding.UTF8, leaveOpen: true);
            var text = await sr.ReadToEndAsync();
            var b = JsonSerializer.Deserialize<DomainBackup>(text) ?? throw new InvalidOperationException("Invalid backup.");

            var armored = CryptoBox.Open(b.SaltB64, b.CipherB64, passphrase);
            var importName = b.IpnsKeyName;

            var (name, id) = await IpfsAdmin.EnsureKeyAsync(importName, _http, _keys);
            if (!string.Equals(id, b.IpnsPeerId, StringComparison.OrdinalIgnoreCase))
            {
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

            if (!string.IsNullOrWhiteSpace(b.LastPublishedCid))
            {
                var siteTarget = IpfsGateway.NormalizeMfs($"/production/sites/{b.SiteFolderLeaf}");
                await IpfsAdmin.FilesCpFromIpfsAsync(b.LastPublishedCid!, siteTarget, _http, _keys);
                var rest = $"/api/v0/pin/add?arg={Uri.EscapeDataString(b.LastPublishedCid!)}&recursive=true";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
                res.EnsureSuccessStatusCode();
            }

            return (b.Domain, importName, id);
        }

        // ----- domain backup record (copied) -----
        public sealed record DomainBackup(
            string Domain, string SiteFolderLeaf, string TgpFolderLeaf,
            string IpnsKeyName, string IpnsPeerId, string? LastPublishedCid,
            int EncVersion, string SaltB64, string CipherB64);
    }
}

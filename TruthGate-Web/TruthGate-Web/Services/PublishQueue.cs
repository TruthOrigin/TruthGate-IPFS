using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text;
using System.Threading.Channels;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Services
{
    public class PublishQueue : BackgroundService, IPublishQueue, IPublishRunner
    {
        private readonly Channel<(string jobId, PublishJob job)> _ch =
            Channel.CreateUnbounded<(string, PublishJob)>(new UnboundedChannelOptions { SingleReader = true });

        private readonly IHttpClientFactory _http;
        private readonly IApiKeyProvider _keys;
        private readonly IConfigService _config;
        private readonly ILogger<PublishQueue> _log;

        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.OrdinalIgnoreCase);

        public PublishQueue(IHttpClientFactory http, IApiKeyProvider keys, IConfigService cfg, ILogger<PublishQueue> log)
            => (_http, _keys, _config, _log) = (http, keys, cfg, log);

        public ValueTask<string> EnqueueAsync(PublishJob job)
        {
            var id = Guid.NewGuid().ToString("n");
            _ch.Writer.TryWrite((id, job));
            return ValueTask.FromResult(id);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach (var (jobId, job) in _ch.Reader.ReadAllAsync(stoppingToken))
            {
                var gate = _locks.GetOrAdd(job.Domain, _ => new SemaphoreSlim(1, 1));
                await gate.WaitAsync(stoppingToken);
                try
                {
                    await RunOne(job, stoppingToken);
                    _log.LogInformation("Publish {JobId} for {Domain} completed", jobId, job.Domain);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Publish {JobId} for {Domain} failed", jobId, job.Domain);
                }
                finally { gate.Release(); }
            }
        }

        private async Task RunOne(PublishJob job, CancellationToken ct)
        {
            var siteParent = "/production/sites";
            var siteLeaf = job.SiteLeaf;
            var siteTarget = IpfsGateway.NormalizeMfs($"{siteParent}/{siteLeaf}");
            var siteStage = job.StagingRoot; // supplied by controller

            // 0) Guardrails: staging exists & has index.html at root
            if (!await MfsExistsAsync(siteStage))
                throw new InvalidOperationException($"Staging root not found: {siteStage}");

            if (!await MfsExistsAsync($"{siteStage}/index.html"))
                throw new InvalidOperationException("No index.html found at staging root. Refusing to publish.");

            // 1) Ensure parent exists
            _ = await IpfsGateway.EnsureMfsFolderExistsAsync(siteParent, _http);

            // 2) Compute new site CID from staged folder + pin
            var newSiteCid = await IpfsAdmin.FilesStatHashAsync(siteStage, _http, _keys, ct)
                ?? throw new InvalidOperationException("files/stat failed for staging.");
            await PinRecursiveAsync(newSiteCid, ct);

            // 3) Swap: rm old, mv stage to target (fallback cp+rm)
            await RemoveIfExists(siteTarget, ct);
            var moved = await TryMoveAsync(siteStage, siteTarget, ct);
            if (!moved)
            {
                await CpAsync(siteStage, siteTarget, ct);
                await RemoveIfExists(siteStage, ct);
            }

            // 4) Re-stat target and pin (cheap if same DAG root)
            var finalSiteCid = await IpfsAdmin.FilesStatHashAsync(siteTarget, _http, _keys, ct) ?? newSiteCid;
            await PinRecursiveAsync(finalSiteCid, ct);

            // 5) Write TGP bundle under /production/pinned/{tgpLeaf}
            var tgpFolder = IpfsGateway.NormalizeMfs($"/production/pinned/{job.TgpLeaf}");
            _ = await IpfsGateway.EnsureMfsFolderExistsAsync(tgpFolder, _http);

            // tgp.json
            var tgpJson = TgpTemplates.TgpJson(finalSiteCid);
            await using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(tgpJson)))
                await IpfsAdmin.FilesWriteAsync($"{tgpFolder}/tgp.json", ms, _http, _keys, "application/json", ct);

            // Ensure per-domain key exists (default name based on DOMAIN)
            var cfgSnapshot = _config.Get();
            var edSnapshot = (cfgSnapshot.Domains ?? new()).First(d => d.Domain.Equals(job.Domain, StringComparison.OrdinalIgnoreCase));


            // index.html: pass override base URL (IPNS wildcard if configured, else the domain)
            var overrideBaseUrl = BuildTgpOverrideBaseUrl(edSnapshot, ipnsPeerId: edSnapshot.IpnsPeerId);
            var indexHtml = TgpTemplates.IndexHtml(overrideBaseUrl);
            await using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(indexHtml)))
                await IpfsAdmin.FilesWriteAsync($"{tgpFolder}/index.html", ms, _http, _keys, "text/html", ct);


            // legal.md    (NOTE: media type without charset to avoid FormatException)
            var legal = TgpTemplates.LegalMd(job.Domain);
            await using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(legal)))
                await IpfsAdmin.FilesWriteAsync($"{tgpFolder}/legal.md", ms, _http, _keys, "text/markdown", ct);

            // 6) Pin TGP folder & publish IPNS using the domain’s key
            var tgpCid = await IpfsAdmin.FilesStatHashAsync(tgpFolder, _http, _keys, ct)
                ?? throw new InvalidOperationException("TGP folder stat failed.");
            await PinRecursiveAsync(tgpCid, ct);

           
            var ipnsName = string.IsNullOrWhiteSpace(edSnapshot.IpnsKeyName)
                ? $"tg-{IpfsGateway.ToSafeLeaf(edSnapshot.Domain)}"
                : edSnapshot.IpnsKeyName;

            var (name, id) = await IpfsAdmin.EnsureKeyAsync(ipnsName, _http, _keys);

            // Publish pointer to the TGP bundle
            await IpfsAdmin.NamePublishAsync(name, tgpCid, _http, _keys);

            await EnsureIpnsKeyFileAndRepublishIfNeededAsync(
    siteTarget,
    tgpFolder,
    name,
    id, 
    ct);

            // 7) Persist metadata (real UpdateAsync mutation)
            await _config.UpdateAsync(cfg =>
            {
                var list = cfg.Domains ??= new List<EdgeDomain>();
                var ed = list.FirstOrDefault(d => d.Domain.Equals(job.Domain, StringComparison.OrdinalIgnoreCase));
                if (ed is null) return;

                ed.SiteFolderLeaf = job.SiteLeaf;
                ed.TgpFolderLeaf = job.TgpLeaf;
                ed.IpnsKeyName = ipnsName;
                ed.IpnsPeerId = id;
                ed.LastPublishedCid = finalSiteCid;
                ed.LastPublishedAt = DateTimeOffset.UtcNow;
            });

            // 8) Best-effort cleanup of any old .staging.* under /production/sites (legacy)
            await CleanupOldStaging(siteParent, olderThanMinutes: 20, ct);

            // ---- helpers ----
            async Task<bool> MfsExistsAsync(string mfsPath)
            {
                var rest = $"/api/v0/files/stat?arg={Uri.EscapeDataString(IpfsGateway.NormalizeMfs(mfsPath))}";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys, ct: ct);
                return res.IsSuccessStatusCode;
            }

            async Task RemoveIfExists(string mfsPath, CancellationToken ct2)
            {
                var rest = $"/api/v0/files/rm?arg={Uri.EscapeDataString(mfsPath)}&recursive=true";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys, ct: ct2);
                // ignore status; it may not exist
            }

            async Task<bool> TryMoveAsync(string from, string to, CancellationToken ct2)
            {
                var rest = $"/api/v0/files/mv?arg={Uri.EscapeDataString(from)}&arg={Uri.EscapeDataString(to)}&parents=true";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys, ct: ct2);
                return res.IsSuccessStatusCode;
            }

            async Task CpAsync(string from, string to, CancellationToken ct2)
            {
                var rest = $"/api/v0/files/cp?arg={Uri.EscapeDataString(from)}&arg={Uri.EscapeDataString(to)}";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys, ct: ct2);
                res.EnsureSuccessStatusCode();
            }

            async Task PinRecursiveAsync(string cid, CancellationToken ct2)
            {
                var rest = $"/api/v0/pin/add?arg={Uri.EscapeDataString(cid)}&recursive=true";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys, ct: ct2);
                res.EnsureSuccessStatusCode();
            }

            async Task CleanupOldStaging(string parent, int olderThanMinutes, CancellationToken ct2)
            {
                var ls = $"/api/v0/files/ls?arg={Uri.EscapeDataString(parent)}&long=true";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(ls, _http, _keys, ct: ct2);
                if (!res.IsSuccessStatusCode) return;

                var root = await ReadJsonAsync(res);
                if (root is null || !root.Value.TryGetProperty("Entries", out var arr)) return;

                foreach (var e in arr.EnumerateArray())
                {
                    var name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
                    if (name.Contains(".staging.", StringComparison.OrdinalIgnoreCase))
                    {
                        var full = IpfsGateway.NormalizeMfs($"{parent}/{name}");
                        var parts = name.Split(".staging.");
                        if (parts.Length == 2 &&
                            DateTimeOffset.TryParseExact(parts[1], "yyyyMMddHHmmssfff",
                                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var stamp))
                        {
                            if ((DateTimeOffset.UtcNow - stamp).TotalMinutes > olderThanMinutes)
                                await RemoveIfExists(full, ct2);
                        }
                    }
                }
            }

            async Task<string?> TryReadIpnsKeyAsync(string keyMfsPath, CancellationToken ct2)
            {
                // files/read returns 200 only if file exists
                var rest = $"/api/v0/files/read?arg={Uri.EscapeDataString(IpfsGateway.NormalizeMfs(keyMfsPath))}";
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys, ct: ct2);
                if (!res.IsSuccessStatusCode) return null;

                var txt = await res.Content.ReadAsStringAsync();

                // Try JSON first: { "IpnsKey": "k51q..." }
                try
                {
                    var obj = JsonSerializer.Deserialize<IpnsSiteKey>(txt);
                    if (!string.IsNullOrWhiteSpace(obj?.IpnsKey))
                        return obj!.IpnsKey.Trim();
                }
                catch { /* ignore and fall back */ }

                // Fallback: treat content as plain text value
                return txt.Trim().Trim('"');
            }

            async Task UnpinRecursiveIfPossibleAsync(string cid, CancellationToken ct2)
            {
                if (string.IsNullOrWhiteSpace(cid)) return;
                try
                {
                    var rest = $"/api/v0/pin/rm?arg={Uri.EscapeDataString(cid)}&recursive=true";
                    using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys, ct: ct2);
                    // ok if it wasn't pinned; we don't throw on non-success
                }
                catch
                {
                    // best-effort
                }
            }

            async Task EnsureIpnsKeyFileAndRepublishIfNeededAsync(
                string siteFolderMfs,               // e.g. /production/sites/{leaf}
                string tgpFolderMfs,                // e.g. /production/pinned/{tgpLeaf}
                string ipnsKeyNameForPublish,       // 'name' from EnsureKeyAsync
                string currentPeerId,               // 'id' from EnsureKeyAsync
                CancellationToken ct2)
            {
                var keyPath = $"{siteFolderMfs}/ipns-key.json";

                var existing = await TryReadIpnsKeyAsync(keyPath, ct2);
                if (string.Equals(existing, currentPeerId, StringComparison.OrdinalIgnoreCase))
                    return; // all good

                // Need to add/overwrite ipns-key.json, so: unpin current site CID, write, re-pin, and update TGP + IPNS.

                var oldSiteCid = await IpfsAdmin.FilesStatHashAsync(siteFolderMfs, _http, _keys, ct2);
                if (!string.IsNullOrWhiteSpace(oldSiteCid))
                    await UnpinRecursiveIfPossibleAsync(oldSiteCid!, ct2);

                var payload = JsonSerializer.Serialize(new IpnsSiteKey { IpnsKey = currentPeerId });
                await using (var msKey = new MemoryStream(Encoding.UTF8.GetBytes(payload)))
                    await IpfsAdmin.FilesWriteAsync(keyPath, msKey, _http, _keys, "application/json", ct2);

                // new site CID after adding the file
                var newSiteCid = await IpfsAdmin.FilesStatHashAsync(siteFolderMfs, _http, _keys, ct2)
                    ?? throw new InvalidOperationException("files/stat failed after writing ipns-key.json.");

                await PinRecursiveAsync(newSiteCid, ct2);

                // Rewrite TGP's tgp.json to reference the NEW site CID, pin, and republish IPNS.
                var newTgpJson = TgpTemplates.TgpJson(newSiteCid);
                await using (var msTgp = new MemoryStream(Encoding.UTF8.GetBytes(newTgpJson)))
                    await IpfsAdmin.FilesWriteAsync($"{tgpFolderMfs}/tgp.json", msTgp, _http, _keys, "application/json", ct2);

                var updatedTgpCid = await IpfsAdmin.FilesStatHashAsync(tgpFolderMfs, _http, _keys, ct2)
                    ?? throw new InvalidOperationException("TGP folder stat failed after ipns-key write.");
                await PinRecursiveAsync(updatedTgpCid, ct2);

                // Republish IPNS to point to updated TGP
                await IpfsAdmin.NamePublishAsync(ipnsKeyNameForPublish, updatedTgpCid, _http, _keys);
            }

            static async Task<JsonElement?> ReadJsonAsync(HttpResponseMessage res)
            {
                var txt = await res.Content.ReadAsStringAsync();
                try { using var doc = JsonDocument.Parse(txt); return doc.RootElement.Clone(); } catch { return null; }
            }
        }

        private string BuildTgpOverrideBaseUrl(EdgeDomain ed, string? ipnsPeerId)
        {
            // Pull a fresh snapshot to read current wildcard setting safely
            var cfg = _config.Get();
            var wc = cfg?.IpnsWildCardSubDomain;

            // Utility: normalize scheme flags like "true"/"false"
            static bool Boolish(string? s) => bool.TryParse((s ?? "").Trim(), out var b) && b;

            try
            {
                // If wildcard is configured, prefer it
                var wildcardHost = wc?.WildCardSubDomain?.Trim();
                if (!string.IsNullOrWhiteSpace(wildcardHost))
                {
                    // we expect the saved value WITHOUT "*."
                    // form: <label>.<wildcardHost>
                    // label preference: PeerId -> KeyName -> fallback to keyname derived from domain
                    var label =
                        !string.IsNullOrWhiteSpace(ipnsPeerId) ? ipnsPeerId! :
                        (!string.IsNullOrWhiteSpace(ed.IpnsKeyName) ? ed.IpnsKeyName! :
                         $"tg-{IpfsGateway.ToSafeLeaf(ed.Domain)}");

                    // ensure no leading dot on the wildcard host
                    var host = $"{label}.{wildcardHost.TrimStart('.')}";

                    var scheme = Boolish(wc?.UseSSL) ? "https" : "http";
                    return $"{scheme}://{host}";
                }

                // Otherwise, fall back to the primary domain
                {
                    var scheme = Boolish(ed.UseSSL) ? "https" : "http";
                    var host = (ed.Domain ?? string.Empty).Trim();
                    return $"{scheme}://{host}";
                }
            }
            catch
            {
                // Last-resort fallback: domain with https (sensible default)
                var host = (ed.Domain ?? string.Empty).Trim();
                var scheme = Boolish(ed.UseSSL) ? "https" : "http";
                return $"{scheme}://{host}";
            }
        }

    }

}

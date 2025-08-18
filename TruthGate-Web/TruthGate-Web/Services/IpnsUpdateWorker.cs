using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;
using System.Text.RegularExpressions;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Services
{
    public interface IIpnsUpdateService
    {
        /// <summary>Runs the updater for a single IPNS name now (sequential with the worker's internal lock).</summary>
        Task RunOnceForAsync(string name, CancellationToken ct = default);

        /// <summary>Runs the updater for all IPNS entries now (sequential run).</summary>
        Task RunOnceAllAsync(CancellationToken ct = default);

        /// <summary>Applies retroactive KeepOld policy for the given name (e.g., after toggling).</summary>
        Task EnsureKeepOldPolicyAsync(string name, CancellationToken ct = default);
    }
    public sealed class IpnsUpdateWorker : BackgroundService, IIpnsUpdateService
    {
        private readonly IHttpClientFactory _http;
        private readonly IConfigService _config;
        private readonly IMemoryCache _cache;
        private readonly ILogger<IpnsUpdateWorker> _log;

        private static readonly Regex VersionRx = new(@"-v(?<n>\d+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private const string ManagedRoot = "/production/pinned";
        private const string StagingRoot = "/production/.staging/ipns";

        private readonly SemaphoreSlim _runLock = new(1, 1);

        private readonly IApiKeyProvider _keys;

        public IpnsUpdateWorker(IHttpClientFactory http, IConfigService config, 
            IMemoryCache cache, ILogger<IpnsUpdateWorker> log, IApiKeyProvider keys)
        {
            _http = http;
            _config = config;
            _cache = cache;
            _log = log;
            _keys = keys;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Crash-safe: cleanup orphaned staging at start
            try { await CleanupStagingAsync(stoppingToken); } catch (Exception ex) { _log.LogWarning(ex, "Staging cleanup failed."); }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await RunInternalAsync(all: true, specificName: null, stoppingToken);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "IPNS auto-update pass failed.");
                }

                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(30), stoppingToken);
                }
                catch (TaskCanceledException) { }
            }
        }

        public Task RunOnceForAsync(string name, CancellationToken ct = default)
            => RunInternalAsync(all: false, specificName: name, ct);

        public Task RunOnceAllAsync(CancellationToken ct = default)
            => RunInternalAsync(all: true, specificName: null, ct);

        public async Task EnsureKeepOldPolicyAsync(string name, CancellationToken ct = default)
        {
            await _runLock.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var entry = cfg.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase));
                if (entry is null) return;

                if (!entry.KeepOldCidPinned)
                    await RemoveAllButLatestAsync(entry.Name, ct);
            }
            finally { _runLock.Release(); }
        }

        private async Task RunInternalAsync(bool all, string? specificName, CancellationToken ct)
        {
            await _runLock.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var entries = (cfg.IpnsKeys ?? new List<IpnsKey>()).ToList();

                if (!all)
                    entries = entries.Where(k => string.Equals(k.Name, specificName, StringComparison.OrdinalIgnoreCase)).ToList();

                // Process serially (explicit requirement: “one at a time”)
                foreach (var e in entries)
                {
                    if (!e.AutoUpdateToPin && all)
                    {
                        // Still enforce retroactive KeepOld false (cleanup) even if AutoUpdate is off
                        if (!e.KeepOldCidPinned) await RemoveAllButLatestAsync(e.Name, ct);
                        continue;
                    }

                    try
                    {
                        var key = CanonicalizeIpnsKey(e.Key);
                        var latestCid = await ResolveIpnsAsync(key, ct);

                        if (string.IsNullOrWhiteSpace(latestCid))
                            continue;

                        // If CurrentCID matches latest, apply retro keep-old cleanup and skip
                        if (string.Equals(latestCid, e.CurrentCID, StringComparison.OrdinalIgnoreCase))
                        {
                            if (!e.KeepOldCidPinned) await RemoveAllButLatestAsync(e.Name, ct);
                            continue;
                        }

                        // New version
                        var nextVersion = await ComputeNextVersionAsync(e.Name, ct);
                        var targetFolder = $"{ManagedRoot}/{e.Name}-v{nextVersion:000}";
                        var staged = $"{StagingRoot}/{e.Name}/{Guid.NewGuid():N}";

                        // Stage → pin → provide → promote → clean
                        await EnsureFolderAsync($"{StagingRoot}/{e.Name}", ct);
                        await FilesCpFromIpfsAsync(latestCid, staged, ct);
                        await PinAddRecursiveAsync(latestCid, ct);
                        _ = TryProvideAsync(latestCid, ct); // fire-and-forget best-effort

                        await EnsureFolderAsync(ManagedRoot, ct);
                        await FilesMvAsync(staged, targetFolder, ct);

                        // Update config (CurrentCID)
                        await _config.UpdateAsync(config =>
                        {
                            var t = config.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, e.Name, StringComparison.OrdinalIgnoreCase));
                            if (t is not null) t.CurrentCID = latestCid;
                        });

                        // Retroactive cleanup if KeepOldCidPinned == false
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Failed updating IPNS '{Name}'.", e.Name);
                    }
                }

                // Final: opportunistic cleanup of stale staging (older than 2h)
                try { await CleanupStagingAsync(ct); } catch { /* ignore */ }
            }
            finally
            {
                _runLock.Release();
            }
        }

        // -----------------------
        // Helpers (IPFS proxy)
        // -----------------------
        private static string CanonicalizeIpnsKey(string key)
        {
            var s = (key ?? "").Trim();
            if (s.StartsWith("/ipns/", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(6);
            return s;
        }

        private async Task<string> ResolveIpnsAsync(string ipnsKey, CancellationToken ct)
        {
            var rest = $"/api/v0/name/resolve?arg={Uri.EscapeDataString($"/ipns/{ipnsKey}")}&recursive=false&nocache=false";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"name/resolve failed ({(int)res.StatusCode})");

            var el = await ReadLastJsonAsync(res);
            var path = el?.GetProperty("Path").GetString();
            if (string.IsNullOrWhiteSpace(path) || !path.StartsWith("/ipfs/", StringComparison.Ordinal))
                throw new InvalidOperationException("IPNS resolution did not return /ipfs/<cid>.");
            return path.Substring("/ipfs/".Length);
        }

        private async Task FilesCpFromIpfsAsync(string cid, string destPath, CancellationToken ct)
        {
            var from = $"/ipfs/{cid}";
            var rest = $"/api/v0/files/cp?arg={Uri.EscapeDataString(from)}&arg={Uri.EscapeDataString(destPath)}&parents=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"files/cp failed → {destPath} ({(int)res.StatusCode})");
        }

        private async Task FilesRmRecursiveAsync(string mfsPath, CancellationToken ct)
        {
            mfsPath = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/rm?arg={Uri.EscapeDataString(mfsPath)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode)
                throw new InvalidOperationException($"files/rm failed '{mfsPath}' ({(int)res.StatusCode})");
        }

        private async Task FilesMvAsync(string from, string to, CancellationToken ct)
        {
            var rest = $"/api/v0/files/mv?arg={Uri.EscapeDataString(from)}&arg={Uri.EscapeDataString(to)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode)
                throw new InvalidOperationException($"files/mv failed '{from}' → '{to}' ({(int)res.StatusCode})");
        }

        private async Task EnsureFolderAsync(string mfsPath, CancellationToken ct)
        {
            await IpfsGateway.EnsureMfsFolderExistsAsync(mfsPath, _http);
            // Warm cache optionally
            _ = await IpfsGateway.GetCidForMfsPathAsync(mfsPath, _http, _cache, TimeSpan.FromHours(1), IpfsGateway.CacheMode.Refresh);
        }

        private async Task PinAddRecursiveAsync(string cid, CancellationToken ct)
        {
            var rest = $"/api/v0/pin/add?arg={Uri.EscapeDataString(cid)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"pin/add failed ({(int)res.StatusCode})");
        }

        private async Task PinRmRecursiveAsync(string cid, CancellationToken ct)
        {
            var rest = $"/api/v0/pin/rm?arg={Uri.EscapeDataString(cid)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"pin/rm failed ({(int)res.StatusCode})");
        }

        private async Task<JsonElement?> ReadLastJsonAsync(HttpResponseMessage res)
        {
            var text = await res.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(text)) return null;

            try { using var doc = JsonDocument.Parse(text); return doc.RootElement.Clone(); }
            catch { }

            foreach (var line in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Reverse())
            {
                var t = line.Trim();
                if (!t.StartsWith("{") || !t.EndsWith("}")) continue;
                try { using var doc = JsonDocument.Parse(t); return doc.RootElement.Clone(); } catch { }
            }
            return null;
        }

        private async Task<int> ComputeNextVersionAsync(string name, CancellationToken ct)
        {
            var children = await ListMfsChildrenAsync(ManagedRoot, ct);
            var prefix = $"{name}-v";
            var max = 0;
            foreach (var k in children.Keys)
            {
                if (!k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                var m = VersionRx.Match(k);
                if (m.Success && int.TryParse(m.Groups["n"].Value, out var n))
                    max = Math.Max(max, n);
            }
            return max + 1;
        }

        private async Task RemoveAllButLatestAsync(string name, CancellationToken ct)
        {
            var children = await ListMfsChildrenAsync(ManagedRoot, ct);
            var prefix = $"{name}-v";
            var versions = new List<(int n, string path, string cid)>();
            foreach (var kv in children)
            {
                if (!kv.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                var m = VersionRx.Match(kv.Key);
                if (!m.Success || !int.TryParse(m.Groups["n"].Value, out var n)) continue;
                versions.Add((n, kv.Value.Path, kv.Value.Cid));
            }
            if (versions.Count <= 1) return;

            var latest = versions.OrderByDescending(v => v.n).First();
            foreach (var v in versions.Where(v => v.n != latest.n))
            {
                try
                {
                    await FilesRmRecursiveAsync(v.path, ct);
                    await PinRmRecursiveAsync(v.cid, ct);
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to remove old version {Name}-v{Version}.", name, v.n);
                }
            }
        }

        private async Task CleanupStagingAsync(CancellationToken ct)
        {
            // Simple heuristic: delete everything under /production/.staging/ipns older than ~2h
            // (MFS has no timestamps; we just brute remove entire staging branch if present; safe because staging is only ours.)
            try
            {
                // If staging exists, nuke and recreate — safest crash recovery
                await FilesRmRecursiveAsync(StagingRoot, ct);
            }
            catch { /* ignore if missing */ }
            try
            {
                await EnsureFolderAsync(StagingRoot, ct);
            }
            catch { /* ignore */ }
        }

        private async Task<Dictionary<string, (string Cid, string Path)>> ListMfsChildrenAsync(string parent, CancellationToken ct)
        {
            parent = IpfsGateway.NormalizeMfs(parent);
            var rest = $"/api/v0/files/ls?arg={Uri.EscapeDataString(parent)}&long=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            var dict = new Dictionary<string, (string Cid, string Path)>(StringComparer.OrdinalIgnoreCase);
            if (!res.IsSuccessStatusCode) return dict;

            var el = await ReadLastJsonAsync(res);
            if (el is null) return dict;
            if (el.Value.TryGetProperty("Entries", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in arr.EnumerateArray())
                {
                    var name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
                    var cid = e.TryGetProperty("Hash", out var h) ? h.GetString() ?? "" : "";
                    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(cid)) continue;
                    var path = IpfsGateway.NormalizeMfs($"{parent}/{name}");
                    dict[name] = (cid, path);
                }
            }
            return dict;
        }

        private async Task TryProvideAsync(string cid, CancellationToken ct)
        {
            try
            {
                // Best-effort DHT provide (not all Kubo versions expose this; ignore failures)
                var rest = $"/api/v0/routing/provide?arg={Uri.EscapeDataString(cid)}";
                using var _ = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            }
            catch { /* ignore */ }
        }
    }
}

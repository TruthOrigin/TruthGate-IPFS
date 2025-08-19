using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Utils;

namespace TruthGate_Web.Services
{
    public sealed class IpnsUpdateOptions
    {
        /// <summary>Max number of IPNS entries processed in parallel (different keys).</summary>
        public int MaxConcurrency { get; set; } = 4;

        /// <summary>Minimum time between scheduled runs for the same key. Manual runs ignore this.</summary>
        public TimeSpan ScheduledPerKeyCooldown { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>Main scheduler wake interval. Concurrency happens inside each pass.</summary>
        public TimeSpan SchedulerInterval { get; set; } = TimeSpan.FromMinutes(30);
    }

    public interface IIpnsUpdateService
    {
        /// <summary>Runs the updater for a single IPNS name now (runs concurrently with others, but serialized for this key).</summary>
        Task RunOnceForAsync(string name, CancellationToken ct = default);

        /// <summary>Runs the updater for all IPNS entries now (up to MaxConcurrency in parallel).</summary>
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
        private readonly IpnsUpdateOptions _opts;
        private readonly IApiKeyProvider _keys;

        private static readonly Regex VersionRx = new(@"-v(?<n>\d+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private const string ManagedRoot = "/production/pinned";
        private const string StagingRoot = "/production/.staging/ipns";
        private const string TgpMetaFile = ".tgp-meta.json"; // lives in each version folder

        // concurrency
        private readonly SemaphoreSlim _globalSlots;
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _perKeyLocks = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _lastScheduledRun = new(StringComparer.OrdinalIgnoreCase);
        private readonly SemaphoreSlim _runAllOnce = new(1, 1);

        public IpnsUpdateWorker(
            IHttpClientFactory http,
            IConfigService config,
            IMemoryCache cache,
            ILogger<IpnsUpdateWorker> log,
            IApiKeyProvider keys,
            IOptions<IpnsUpdateOptions> opts)
        {
            _http = http;
            _config = config;
            _cache = cache;
            _log = log;
            _keys = keys;
            _opts = opts?.Value ?? new IpnsUpdateOptions();

            if (_opts.MaxConcurrency < 1) _opts.MaxConcurrency = 1;
            if (_opts.SchedulerInterval <= TimeSpan.Zero) _opts.SchedulerInterval = TimeSpan.FromMinutes(30);
            if (_opts.ScheduledPerKeyCooldown <= TimeSpan.Zero) _opts.ScheduledPerKeyCooldown = TimeSpan.FromMinutes(10);

            _globalSlots = new SemaphoreSlim(_opts.MaxConcurrency, _opts.MaxConcurrency);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try { await CleanupStagingAsync(stoppingToken); } catch (Exception ex) { _log.LogWarning(ex, "Staging cleanup failed on startup."); }

            while (!stoppingToken.IsCancellationRequested)
            {
                try { await RunScheduledPassAsync(stoppingToken); }
                catch (OperationCanceledException) { }
                catch (Exception ex) { _log.LogError(ex, "IPNS scheduled pass failed."); }

                try { await Task.Delay(_opts.SchedulerInterval, stoppingToken); }
                catch (TaskCanceledException) { }
            }
        }

        private async Task RunScheduledPassAsync(CancellationToken ct)
        {
            await _runAllOnce.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var entries = (cfg.IpnsKeys ?? new List<IpnsKey>()).ToList();
                if (entries.Count == 0) { try { await CleanupStagingAsync(ct); } catch { } return; }

                var now = DateTimeOffset.UtcNow;
                var toProcess = new List<IpnsKey>();

                foreach (var e in entries)
                {
                    // Always enforce pruning policy even when AutoUpdate is off
                    if (!e.KeepOldCidPinned)
                        _ = EnsureKeepOldPolicyAsync(e.Name, ct);

                    if (!e.AutoUpdateToPin) continue;

                    if (_lastScheduledRun.TryGetValue(e.Name, out var last)
                        && now - last < _opts.ScheduledPerKeyCooldown)
                        continue;

                    toProcess.Add(e);
                    _lastScheduledRun[e.Name] = now;
                }

                if (toProcess.Count == 0) { try { await CleanupStagingAsync(ct); } catch { } return; }

                var tasks = toProcess.Select(k => ProcessOneAsync(k.Name, forceResolve: false, ct));
                await Task.WhenAll(tasks);

                try { await CleanupStagingAsync(ct); } catch { }
            }
            finally
            {
                _runAllOnce.Release();
            }
        }

        public async Task RunOnceForAsync(string name, CancellationToken ct = default)
        {
            await ProcessOneAsync(name, forceResolve: true, ct);
        }

        public async Task RunOnceAllAsync(CancellationToken ct = default)
        {
            await _runAllOnce.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var names = (cfg.IpnsKeys ?? new List<IpnsKey>()).Select(k => k.Name).ToList();
                var tasks = names.Select(n => ProcessOneAsync(n, forceResolve: true, ct));
                await Task.WhenAll(tasks);

                try { await CleanupStagingAsync(ct); } catch { }
            }
            finally
            {
                _runAllOnce.Release();
            }
        }

        public async Task EnsureKeepOldPolicyAsync(string name, CancellationToken ct = default)
        {
            var keyLock = GetKeyLock(name);
            await keyLock.WaitAsync(ct);
            try
            {
                var cfg = _config.Get();
                var entry = cfg.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase));
                if (entry is null) return;

                if (!entry.KeepOldCidPinned)
                    await RemoveAllButLatestAsync(entry.Name, ct);
            }
            finally { keyLock.Release(); }
        }

        // -------- core per-key pipeline (now with TGP) --------
        private async Task ProcessOneAsync(string name, bool forceResolve, CancellationToken ct)
        {
            await _globalSlots.WaitAsync(ct);
            try
            {
                var keyLock = GetKeyLock(name);
                await keyLock.WaitAsync(ct);
                try
                {
                    var cfg = _config.Get();
                    var e = cfg.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, name, StringComparison.OrdinalIgnoreCase));
                    if (e is null) return;

                    if (!forceResolve && !e.AutoUpdateToPin)
                    {
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        return;
                    }

                    var ipnsKey = CanonicalizeIpnsKey(e.Key);

                    string pointerCid;
                    try
                    {
                        pointerCid = await ResolveIpnsAsync(ipnsKey, ct);
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "IPNS resolve failed for '{Name}'.", e.Name);
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        return;
                    }
                    if (string.IsNullOrWhiteSpace(pointerCid))
                    {
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        return;
                    }

                    // Check TGP: see if /tgp.json exists under the pointer root and extract target CID
                    string? tgpTargetCid = await TryReadTgpTargetCidAsync(pointerCid, ct);

                    // Short-circuit: if pointerCid hasn't changed and either there's no TGP target
                    // or the target hasn't changed meaningfully for our policy, we may just enforce pruning.
                    if (string.Equals(pointerCid, e.CurrentCID, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!e.KeepOldCidPinned)
                            await RemoveAllButLatestAsync(e.Name, ct);
                        // Note: we don't store target CID in config; pruning logic reads sidecar per version.
                        return;
                    }

                    // New version detected
                    var nextVersion = await ComputeNextVersionAsync(e.Name, ct);
                    var versionFolder = $"{ManagedRoot}/{e.Name}-v{nextVersion:000}";
                    var staged = $"{StagingRoot}/{e.Name}/{Guid.NewGuid():N}";

                    // Stage to pin (pointer) to provide to promote
                    await EnsureFolderAsync($"{StagingRoot}/{e.Name}", ct);
                    await FilesCpFromIpfsAsync(pointerCid, staged, ct);
                    await PinAddRecursiveAsync(pointerCid, ct);
                    _ = TryProvideAsync(pointerCid, ct);

                    // If TGP target exists: pin+provide it too (no extra copy to MFS to avoid space blowup)
                    if (!string.IsNullOrWhiteSpace(tgpTargetCid))
                    {
                        try
                        {
                            await PinAddRecursiveAsync(tgpTargetCid!, ct);
                            _ = TryProvideAsync(tgpTargetCid!, ct);
                        }
                        catch (Exception ex)
                        {
                            _log.LogWarning(ex, "Pin/provide of TGP target CID failed for '{Name}'. Target={TargetCid}", e.Name, tgpTargetCid);
                        }
                    }

                    await EnsureFolderAsync(ManagedRoot, ct);
                    await FilesMvAsync(staged, versionFolder, ct);

                    // Write TGP sidecar so pruning knows which extra CIDs to unpin later
                    var meta = new TgpMeta
                    {
                        Kind = "tgp-meta",
                        PointerCid = pointerCid,
                        TargetCid = tgpTargetCid
                    };
                    await FilesWriteTextAsync($"{versionFolder}/{TgpMetaFile}", JsonSerializer.Serialize(meta), ct);

                    // Update config with the *pointer* as CurrentCID (UI already expects this)
                    await _config.UpdateAsync(config =>
                    {
                        var t = config.IpnsKeys?.FirstOrDefault(k => string.Equals(k.Name, e.Name, StringComparison.OrdinalIgnoreCase));
                        if (t is not null) t.CurrentCID = pointerCid;
                    });

                    // Retroactive cleanup if desired
                    if (!e.KeepOldCidPinned)
                        await RemoveAllButLatestAsync(e.Name, ct);
                }
                finally { keyLock.Release(); }
            }
            finally { _globalSlots.Release(); }
        }

        private SemaphoreSlim GetKeyLock(string name)
            => _perKeyLocks.GetOrAdd(name ?? string.Empty, _ => new SemaphoreSlim(1, 1));

        // ---------- TGP helpers ----------
        private sealed class TgpMeta
        {
            public string Kind { get; set; } = "tgp-meta";
            public string? PointerCid { get; set; }
            public string? TargetCid { get; set; }
        }

        private async Task<string?> TryReadTgpTargetCidAsync(string pointerCid, CancellationToken ct)
        {
            try
            {
                // Try to read /tgp.json out of the pointer root
                var tgpJson = await CatIpfsTextAsync($"{pointerCid}/tgp.json", ct);
                if (string.IsNullOrWhiteSpace(tgpJson)) return null;

                using var doc = JsonDocument.Parse(tgpJson);
                var root = doc.RootElement;

                // v1 requires tgp:1 and current
                if (!root.TryGetProperty("tgp", out var tgpVal) || tgpVal.ValueKind != JsonValueKind.Number || tgpVal.GetInt32() != 1)
                    return null;
                if (!root.TryGetProperty("current", out var cur) || cur.ValueKind != JsonValueKind.String)
                    return null;

                var s = cur.GetString() ?? "";
                if (string.IsNullOrWhiteSpace(s)) return null;

                // Normalize to bare CID
                if (s.StartsWith("/ipfs/", StringComparison.Ordinal))
                    s = s.Substring(6);
                return s;
            }
            catch
            {
                return null; // treat as non-TGP if anything fails
            }
        }

        private async Task<string?> CatIpfsTextAsync(string pathOrCidRelative, CancellationToken ct)
        {
            // Support both "<cid>/tgp.json" and "/ipfs/<cid>/tgp.json" shapes; always call /api/v0/cat with /ipfs/
            var p = pathOrCidRelative;
            if (!p.StartsWith("/ipfs/", StringComparison.Ordinal))
                p = "/ipfs/" + p.TrimStart('/');
            var rest = $"/api/v0/cat?arg={Uri.EscapeDataString(p)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) return null;
            return await res.Content.ReadAsStringAsync(ct);
        }

        // ---------- IPFS/MFS helpers ----------
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
            if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"files/cp failed to {destPath} ({(int)res.StatusCode})");
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
                throw new InvalidOperationException($"files/mv failed '{from}' to '{to}' ({(int)res.StatusCode})");
        }

 
        private async Task<string?> FilesReadAllTextAsync(string path, CancellationToken ct)
        {
            var rest = $"/api/v0/files/read?arg={Uri.EscapeDataString(path)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            if (!res.IsSuccessStatusCode) return null;
            return await res.Content.ReadAsStringAsync(ct);
        }

        private async Task EnsureFolderAsync(string mfsPath, CancellationToken ct)
        {
            await IpfsGateway.EnsureMfsFolderExistsAsync(mfsPath, _http);
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
        private async Task FilesWriteTextAsync(string mfsPath, string text, CancellationToken ct)
        {
            // /api/v0/files/write?arg=<path>&create=true&parents=true&truncate=true
            var path = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/write?arg={Uri.EscapeDataString(path)}&create=true&parents=true&truncate=true";

            // For text you can use text/plain; IPFS doesn't care, but it's nicer.
            using var content = new StringContent(text, Encoding.UTF8, "text/plain");

            using var res = await ApiProxyEndpoints.SendProxyApiRequest(
                rest, _http, _keys, content: content, method: "POST", ct: ct);

            if (!res.IsSuccessStatusCode)
                throw new InvalidOperationException($"files/write failed '{path}' ({(int)res.StatusCode})");
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
                    // Read sidecar to learn any extra CIDs (TGP target) to unpin
                    string? metaJson = await FilesReadAllTextAsync($"{v.path}/{TgpMetaFile}", ct);
                    string? tgpTarget = null;
                    if (!string.IsNullOrWhiteSpace(metaJson))
                    {
                        try
                        {
                            var m = JsonSerializer.Deserialize<TgpMeta>(metaJson);
                            if (m?.TargetCid is string s && !string.IsNullOrWhiteSpace(s))
                                tgpTarget = s.Trim();
                        }
                        catch { /* ignore */ }
                    }

                    // Remove folder then unpin both pointer and (if present) target
                    await FilesRmRecursiveAsync(v.path, ct);
                    await PinRmRecursiveAsync(v.cid, ct);
                    if (!string.IsNullOrWhiteSpace(tgpTarget))
                    {
                        try { await PinRmRecursiveAsync(tgpTarget!, ct); }
                        catch (Exception ex) { _log.LogWarning(ex, "Failed to unpin TGP target for {Name}-v{Version}", name, v.n); }
                    }
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to remove old version {Name}-v{Version}.", name, v.n);
                }
            }
        }

        private async Task CleanupStagingAsync(CancellationToken ct)
        {
            try { await FilesRmRecursiveAsync(StagingRoot, ct); } catch { }
            try { await EnsureFolderAsync(StagingRoot, ct); } catch { }
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
                var rest = $"/api/v0/routing/provide?arg={Uri.EscapeDataString(cid)}";
                using var _ = await ApiProxyEndpoints.SendProxyApiRequest(rest, _http, _keys);
            }
            catch { /* ignore */ }
        }
    }
}

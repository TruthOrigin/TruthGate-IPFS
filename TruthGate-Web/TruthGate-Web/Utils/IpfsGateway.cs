using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using System.Reflection.Metadata;
using System.Text.Json;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Services;

namespace TruthGate_Web.Utils
{
    public static class IpfsGateway
    {
        // ----- Cache keys -----
        private static string LsCacheKey(string cid, string dirCanonicalLower) => $"ls:{cid}:{dirCanonicalLower}";
        private static string ResolveCacheKey(string cid, string inputLower) => $"resolve:{cid}:{inputLower}";
        private static string ExistsCacheKey(string cid, string corrected) => $"exists:{cid}:{corrected}";
        private static string DomainCidCacheKey(string mfsPath) => $"cid:{mfsPath}";
        private static string LocalityCacheKey(string cid) => $"local:{cid}";


        public enum CacheMode
        {
            UseCache,  // read & write cache (today's behavior)
            Bypass,    // do not read cache and do not write cache
            Refresh    // do not read cache; write fresh results
        }

        private static MemoryCacheEntryOptions Tag(
            MemoryCacheEntryOptions opts, string? cid = null, string? mfsPath = null)
        {
            if (!string.IsNullOrWhiteSpace(cid))
                opts.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid));
            if (!string.IsNullOrWhiteSpace(mfsPath))
                opts.AddExpirationToken(IpfsCacheIndex.GetMfsToken(mfsPath));

            // Optional: a global token lets you nuke *everything* instantly.
            opts.AddExpirationToken(IpfsCacheIndex.GetGlobalToken());
            return opts;
        }

        public static string NormalizeMfs(string path)
        {
            path = (path ?? "").Trim();
            if (string.IsNullOrEmpty(path)) return "/";
            if (!path.StartsWith("/")) path = "/" + path;
            // Collapse duplicate slashes, strip trailing except root
            path = "/" + string.Join("/", path.Split('/', StringSplitOptions.RemoveEmptyEntries));
            return path == "" ? "/" : path;
        }

        /// <summary>
        /// Validates a single-leaf name (no slashes, no traversal). Returns cleaned leaf or null.
        /// </summary>
        public static string? ToSafeLeaf(string input)
        {
            var s = (input ?? string.Empty).Trim();
            s = s.Replace('\\', '/').Trim('/');
            if (s.Length == 0) return null;
            if (s.Contains('/') || s.Contains("..")) return null;
            return s;
        }

        /// <summary>
        /// Resolve an /ipns/&lt;name&gt; to a root CID using the node API via your proxy pipeline.
        /// No caching by design (IPNS can change; you asked to keep it fresh).
        /// Returns <c>null</c> if resolve fails or the result is not an /ipfs/&lt;cid&gt; path.
        /// </summary>
        public static async Task<string?> ResolveIpnsToCidAsync(
            string ipnsName,
            IHttpClientFactory clientFactory,
            IApiKeyProvider keys)
        {
            // Sanitize: single-leaf only (no slashes/traversal)
            var safe = ToSafeLeaf(ipnsName);
            if (safe is null) return null;

            // Build REST path for your proxy pipeline (not a full URL)
            // /api/v0/resolve?arg=/ipns/<name>&recursive=true
            // (recursive=true lets IPNS/DNSLink chase whatever it needs to reach the current record)
            var arg = $"/ipns/{safe}";
            var rest = $"/api/v0/resolve?arg={Uri.EscapeDataString(arg)}&recursive=true";

            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, clientFactory, keys);
            if (!res.IsSuccessStatusCode) return null;

            var payload = await res.Content.ReadAsStringAsync();

            // The HTTP API may return:
            //   1) JSON: {"Path":"/ipfs/<cid>[...optional subpath]"}
            //   2) Plain text: "/ipfs/<cid>[...optional subpath]\n"
            // We’ll accept both, then extract the leading CID.
            string? path = null;

            // Try JSON first
            try
            {
                using var doc = JsonDocument.Parse(payload);
                if (doc.RootElement.TryGetProperty("Path", out var pathProp))
                {
                    path = pathProp.GetString();
                }
            }
            catch
            {
                // Not JSON; fall back to plaintext
            }

            if (string.IsNullOrWhiteSpace(path))
                path = payload.Trim();

            if (string.IsNullOrWhiteSpace(path)) return null;

            // Expect something like "/ipfs/<cid>" or "/ipfs/<cid>/sub/path"
            // Extract the CID (the first segment after /ipfs/)
            if (!path.StartsWith("/ipfs/", StringComparison.OrdinalIgnoreCase))
                return null;

            var after = path.Substring("/ipfs/".Length).Trim('/');
            var firstSeg = after.Split('/', 2)[0];

            // Basic sanity: ensure it looks like a CID (we'll accept and let downstream validate further)
            // If you want to be stricter, you can add a CID regex or call /cid/format.
            return string.IsNullOrWhiteSpace(firstSeg) ? null : firstSeg;
        }

        /// <summary>
        /// Formats a CID via /api/v0/cid/format using the TruthGate proxy pipeline.
        /// Returns null if conversion isn’t possible (e.g., v0 constraints) or the node rejects it.
        /// </summary>
        public static async Task<string?> FormatCidAsync(
            string cid,
            int version,
            string baseEncoding,
            IHttpClientFactory clientFactory, IApiKeyProvider keys)
        {
            // Build the IPFS API REST (not a full URL!) that your proxy will forward.
            // Example: /api/v0/cid/format?arg=<cid>&v=1&b=base32
            var rest = $"/api/v0/cid/format?arg={Uri.EscapeDataString(cid)}&v={version}&b={Uri.EscapeDataString(baseEncoding)}";

            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, clientFactory, keys);
            if (!res.IsSuccessStatusCode) return null;

            var text = await res.Content.ReadAsStringAsync();
            return text.Trim(); // ipfs typically includes a trailing newline
        }

        private static async Task<Dictionary<string, string>?> ListDirMapAsync(
    string cid, string dirCanonical, IHttpClientFactory factory, IMemoryCache cache, TimeSpan ttl,
    CacheMode mode = CacheMode.UseCache)
        {
            var key = LsCacheKey(cid, (dirCanonical ?? "").Trim('/').ToLowerInvariant());
            if (mode == CacheMode.UseCache && cache.TryGetValue(key, out Dictionary<string, string>? cached))
                return cached;

            var client = factory.CreateClient();
            var arg = string.IsNullOrWhiteSpace(dirCanonical) ? cid : $"{cid}/{dirCanonical.Trim('/')}";
            var url = $"http://127.0.0.1:5001/api/v0/ls?arg={Uri.EscapeDataString(arg)}";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            using var res = await client.SendAsync(req);
            if (!res.IsSuccessStatusCode) return null;

            using var s = await res.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(s);

            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (doc.RootElement.TryGetProperty("Objects", out var objs) && objs.GetArrayLength() > 0)
            {
                foreach (var link in objs[0].GetProperty("Links").EnumerateArray())
                {
                    var name = link.GetProperty("Name").GetString() ?? "";
                    if (!string.IsNullOrEmpty(name))
                        dict[name.ToLowerInvariant()] = name; // lower -> actual
                }
            }

            if (mode != CacheMode.Bypass)
            {
                cache.Set(key, dict, Tag(
                    new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid));
            }

            return dict;
        }




        // ----- Directory listing cache -----
        private static async Task<Dictionary<string, string>?> ListDirMapCachedAsync(
            string cid, string dirCanonical, IHttpClientFactory factory, IMemoryCache cache, TimeSpan ttl)
        {
            var key = LsCacheKey(cid, (dirCanonical ?? "").Trim('/').ToLowerInvariant());
            if (cache.TryGetValue(key, out Dictionary<string, string>? cached)) return cached;

            var client = factory.CreateClient();
            var arg = string.IsNullOrWhiteSpace(dirCanonical) ? cid : $"{cid}/{dirCanonical.Trim('/')}";
            var url = $"http://127.0.0.1:5001/api/v0/ls?arg={Uri.EscapeDataString(arg)}";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            using var res = await client.SendAsync(req);
            if (!res.IsSuccessStatusCode) return null;

            using var s = await res.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(s);

            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (doc.RootElement.TryGetProperty("Objects", out var objs) && objs.GetArrayLength() > 0)
            {
                foreach (var link in objs[0].GetProperty("Links").EnumerateArray())
                {
                    var name = link.GetProperty("Name").GetString() ?? "";
                    if (!string.IsNullOrEmpty(name))
                        dict[name.ToLowerInvariant()] = name; // lower -> actual
                }
            }

            cache.Set(key, dict, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

            return dict;
        }

        // ----- Path resolution (case-insensitive) -----
        public static async Task<string?> ResolvePathCaseInsensitiveAsync(
    string cid, string rest, IHttpClientFactory factory, IMemoryCache cache, TimeSpan ttl,
    CacheMode mode = CacheMode.UseCache)
        {
            var decoded = Uri.UnescapeDataString(rest ?? "");
            var path = decoded.Trim('/');
            if (string.IsNullOrEmpty(path)) return ""; // root

            var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var resolved = new List<string>(segments.Length);
            var currentDir = "";

            for (int i = 0; i < segments.Length; i++)
            {
                var seg = segments[i];
                var map = await ListDirMapAsync(cid, currentDir, factory, cache, ttl, mode);
                if (map is null) return null;
                if (!map.TryGetValue(seg.ToLowerInvariant(), out var actual)) return null;

                resolved.Add(actual);
                currentDir = string.Join('/', resolved);
            }

            return string.Join('/', resolved);
        }


        public static async Task<bool> PathExistsHeadAsync(
            string cid, string rest, int gatewayPort, IHttpClientFactory factory)
        {
            var client = factory.CreateClient();
            var canonical = (rest ?? string.Empty).Trim('/');
            var headUrl = string.IsNullOrEmpty(canonical)
                ? $"http://127.0.0.1:{gatewayPort}/ipfs/{cid}"
                : $"http://127.0.0.1:{gatewayPort}/ipfs/{cid}/{canonical}";

            using var req = new HttpRequestMessage(HttpMethod.Head, headUrl);
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);
            return resp.IsSuccessStatusCode;
        }

        public static Task<(bool exists, string? correctedPath)> PathExistsInIpfsAsync(
    string cid,
    string rest,
    int gatewayPort,
    IHttpClientFactory factory,
    IMemoryCache cache,
    TimeSpan ttl)
        {
            return PathExistsInIpfsAsync(
                cid, rest, gatewayPort, factory, cache, ttl, CacheMode.UseCache);
        }


        // Returns: (exists, correctedPath)
        public static async Task<(bool exists, string? correctedPath)> PathExistsInIpfsAsync(
    string cid,
    string rest,
    int gatewayPort,
    IHttpClientFactory factory,
    IMemoryCache cache,
    TimeSpan ttl,
    CacheMode mode)
        {
            string? correctedPath = null;

            var input = (rest ?? string.Empty).Trim('/');
            var inputLower = input.ToLowerInvariant();
            if (string.IsNullOrEmpty(input)) return (true, "");

            // ✅ use variables, not expression-bodied locals
            var canReadCache = (mode == CacheMode.UseCache);
            var canWriteCache = (mode != CacheMode.Bypass);

            // 1) Cached resolved path?
            if (canReadCache && cache.TryGetValue<string>(ResolveCacheKey(cid, inputLower), out var cachedResolved))
            {
                correctedPath = cachedResolved;

                if (cache.TryGetValue<bool>(ExistsCacheKey(cid, cachedResolved), out var existsCached))
                    return (existsCached, correctedPath);

                var existsHead = await PathExistsHeadAsync(cid, cachedResolved, gatewayPort, factory);
                if (canWriteCache)
                {
                    cache.Set(
                        ExistsCacheKey(cid, cachedResolved),
                        existsHead,
                        Tag(new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid)
                    );
                }
                return (existsHead, correctedPath);
            }

            // 2) Fast HEAD as-is
            if (await PathExistsHeadAsync(cid, input, gatewayPort, factory))
            {
                correctedPath = input;

                if (canWriteCache)
                {
                    cache.Set(
                        ResolveCacheKey(cid, inputLower),
                        correctedPath,
                        Tag(new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid)
                    );

                    cache.Set(
                        ExistsCacheKey(cid, correctedPath),
                        true,
                        Tag(new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid)
                    );
                }
                return (true, correctedPath);
            }

            // 3) Slow: case-insensitive walk
            var resolved = await ResolvePathCaseInsensitiveAsync(cid, input, factory, cache, ttl, mode);
            if (resolved is null)
            {
                if (canWriteCache)
                {
                    cache.Set(
                        ResolveCacheKey(cid, inputLower),
                        "",
                        Tag(new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid)
                    );
                }
                return (false, null);
            }

            var ok = await PathExistsHeadAsync(cid, resolved, gatewayPort, factory);
            correctedPath = ok ? resolved : null;

            if (canWriteCache)
            {
                cache.Set(
                    ResolveCacheKey(cid, inputLower),
                    correctedPath ?? "",
                    Tag(new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid)
                );

                cache.Set(
                    ExistsCacheKey(cid, resolved),
                    ok,
                    Tag(new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid)
                );
            }

            return (ok, correctedPath);
        }

        public static async Task<string?> GetCidForMfsPathAsync(
    string mfsFolderPath, IHttpClientFactory factory, IMemoryCache cache, TimeSpan ttl,
    CacheMode mode = CacheMode.UseCache)
        {
            mfsFolderPath = NormalizeMfs(mfsFolderPath);

            if (mode == CacheMode.UseCache)
                return await ResolveMfsFolderToCidCachedAsync(mfsFolderPath, factory, cache, ttl);

            // Bypass/Refresh -> hit the node directly
            var cid = await ResolveMfsFolderToCidAsync(mfsFolderPath, factory);

            if (mode == CacheMode.Refresh && !string.IsNullOrWhiteSpace(cid))
            {
                cache.Set(DomainCidCacheKey(mfsFolderPath), cid!,
                    Tag(new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl }, cid: cid, mfsPath: mfsFolderPath));
            }

            return cid;
        }

        private static IEnumerable<string> EnumerateMfsAncestors(string mfsPath, bool includeSelf = true)
        {
            var p = NormalizeMfs(mfsPath);
            if (includeSelf) yield return p;

            while (p != "/")
            {
                var lastSlash = p.LastIndexOf('/');
                p = lastSlash <= 0 ? "/" : p.Substring(0, lastSlash);
                yield return p;
            }
        }

        public static void InvalidateMfsCascade(string mfsPath)
        {
            foreach (var a in EnumerateMfsAncestors(mfsPath, includeSelf: true))
                IpfsCacheIndex.InvalidateMfs(a);
        }


        public static async Task<string> EnsureMfsFolderExistsAsync(
    string mfsFolderPath, IHttpClientFactory factory, bool aggressiveGlobalInvalidate = false)
        {
            mfsFolderPath = NormalizeMfs(mfsFolderPath);
            var existing = await ResolveMfsFolderToCidAsync(mfsFolderPath, factory);
            if (!string.IsNullOrWhiteSpace(existing)) return existing!;

            var client = factory.CreateClient();
            var mkUrl = $"http://127.0.0.1:5001/api/v0/files/mkdir?arg={Uri.EscapeDataString(mfsFolderPath)}&parents=true";

            using (var mkReq = new HttpRequestMessage(HttpMethod.Post, mkUrl))
            using (var mkRes = await client.SendAsync(mkReq))
            {
                if (!mkRes.IsSuccessStatusCode)
                    throw new InvalidOperationException($"mkdir failed for '{mfsFolderPath}' ({(int)mkRes.StatusCode})");
            }

            var after = await ResolveMfsFolderToCidAsync(mfsFolderPath, factory);
            if (string.IsNullOrWhiteSpace(after))
                throw new InvalidOperationException($"mkdir succeeded but stat failed for '{mfsFolderPath}'");

            // Targeted: invalidate MFStoCID for this path and all parents (so new CIDs will be fetched)
            InvalidateMfsCascade(mfsFolderPath);

            // (optional) go-nuclear if you want: blow everything
            if (aggressiveGlobalInvalidate) IpfsCacheIndex.InvalidateAll();

            return after!;
        }


        // Convenience for “create by names” under a base path, return end CID.
        public static Task<string> EnsureMfsFolderPathAsync(
            string baseFolder, IEnumerable<string> names, IHttpClientFactory factory)
        {
            baseFolder = NormalizeMfs(baseFolder);
            var tail = string.Join("/", (names ?? Array.Empty<string>())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim('/')));
            var full = NormalizeMfs(baseFolder.TrimEnd('/') + "/" + tail);
            return EnsureMfsFolderExistsAsync(full, factory);
        }

        public static async Task<string> RenameMfsLeafAsync(
     string currentPath, string newLeafName, IHttpClientFactory factory, bool overwriteIfExists = false,
     bool aggressiveGlobalInvalidate = false)
        {
            currentPath = NormalizeMfs(currentPath);
            newLeafName = (newLeafName ?? "").Trim();
            if (string.IsNullOrWhiteSpace(newLeafName))
                throw new ArgumentException("New leaf name is required.", nameof(newLeafName));

            var srcCid = await ResolveMfsFolderToCidAsync(currentPath, factory);
            if (string.IsNullOrWhiteSpace(srcCid))
                throw new FileNotFoundException($"MFS path not found: {currentPath}");

            var slash = currentPath.LastIndexOf('/');
            var parent = slash <= 0 ? "/" : currentPath.Substring(0, slash);
            var dest = NormalizeMfs((parent.EndsWith("/") ? parent : parent + "/") + newLeafName);

            var client = factory.CreateClient();

            if (overwriteIfExists)
            {
                var rmUrl = $"http://127.0.0.1:5001/api/v0/files/rm?arg={Uri.EscapeDataString(dest)}&recursive=true";
                using var rmReq = new HttpRequestMessage(HttpMethod.Post, rmUrl);
                using var rmRes = await client.SendAsync(rmReq);
                // ignore non-2xx; dest might not exist
            }

            var mvUrl = $"http://127.0.0.1:5001/api/v0/files/mv?arg={Uri.EscapeDataString(currentPath)}&arg={Uri.EscapeDataString(dest)}&parents=true";
            using (var mvReq = new HttpRequestMessage(HttpMethod.Post, mvUrl))
            using (var mvRes = await client.SendAsync(mvReq))
            {
                if (!mvRes.IsSuccessStatusCode)
                    throw new IOException($"Rename failed: {currentPath} -> {dest} ({(int)mvRes.StatusCode})");
            }

            var newCid = await ResolveMfsFolderToCidAsync(dest, factory);
            if (string.IsNullOrWhiteSpace(newCid))
                throw new IOException($"Rename succeeded but stat failed for destination: {dest}");

            // Targeted: invalidate MFS maps for source path, dest path, and their parents
            InvalidateMfsCascade(currentPath);
            InvalidateMfsCascade(dest);

            // Optionally nuke everything
            if (aggressiveGlobalInvalidate) IpfsCacheIndex.InvalidateAll();

            return newCid!;
        }



        // ----- MFS folder to root CID (with cache), and local presence checks -----
        public static async Task<string?> ResolveMfsFolderToCidCachedAsync(
            string mfsFolderPath, IHttpClientFactory factory, IMemoryCache cache, TimeSpan ttl)
        {
            if (cache.TryGetValue<string>(DomainCidCacheKey(mfsFolderPath), out var cached))
                return cached;

            var cid = await ResolveMfsFolderToCidAsync(mfsFolderPath, factory);
            if (!string.IsNullOrWhiteSpace(cid))
            {
                cache.Set(DomainCidCacheKey(mfsFolderPath), cid!,
                    new MemoryCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = ttl
                    }.AddExpirationToken(IpfsCacheIndex.GetMfsToken(mfsFolderPath)) // tag by MFS path
                     .AddExpirationToken(IpfsCacheIndex.GetCidToken(cid!)));       // and by CID for good measure
            }
            return cid;
        }

        public static async Task<bool> IsCidLocalCachedAsync(
            string cid, IHttpClientFactory factory, IMemoryCache cache, TimeSpan ttl)
        {
            if (cache.TryGetValue<bool>(LocalityCacheKey(cid), out var cached))
                return cached;

            var isLocal = await IsCidLocalAsync(cid, factory);
            cache.Set(LocalityCacheKey(cid), isLocal,
                new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

            return isLocal;
        }

        public static async Task<string?> ResolveMfsFolderToCidAsync(
            string mfsFolderPath, IHttpClientFactory factory)
        {
            var client = factory.CreateClient();
            var url = $"http://127.0.0.1:5001/api/v0/files/stat?arg={Uri.EscapeDataString(mfsFolderPath)}";

            using var req = new HttpRequestMessage(HttpMethod.Post, url);
            using var res = await client.SendAsync(req);
            if (!res.IsSuccessStatusCode) return null;

            using var s = await res.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(s);
            if (doc.RootElement.TryGetProperty("Hash", out var hashProp))
                return hashProp.GetString();

            return null;
        }

        public static async Task<bool> IsCidLocalAsync(string cid, IHttpClientFactory factory)
        {
            var client = factory.CreateClient();

            // 1) Prefer: pinned check
            {
                var url = $"http://127.0.0.1:5001/api/v0/pin/ls?arg={Uri.EscapeDataString(cid)}";
                using var req = new HttpRequestMessage(HttpMethod.Post, url);
                using var res = await client.SendAsync(req);
                if (res.IsSuccessStatusCode) return true;
            }

            // 2) Fallback: root block present?
            {
                var url = $"http://127.0.0.1:5001/api/v0/block/stat?arg={Uri.EscapeDataString(cid)}";
                using var req = new HttpRequestMessage(HttpMethod.Post, url);
                using var res = await client.SendAsync(req);
                if (res.IsSuccessStatusCode) return true;
            }

            return false;
        }

        // ----- Proxy -----
        public static async Task<bool> Proxy(
    HttpContext context,
    string targetUri,
    IHttpClientFactory clientFactory,
    bool rewriteIndexForCid = false,
    string? basePrefix = null, bool isStaticUrl = true) // e.g. "/ipfs/<cid>/" or "/ipns/<name>/"
        {
            var method = context.Request.Method;
            var client = clientFactory.CreateClient();

            // Build outbound request
            HttpContent? content = null;
            if (!HttpMethods.IsGet(method) && !HttpMethods.IsHead(method))
            {
                content = (context.Request.ContentLength is null or 0)
                    ? new StringContent("")
                    : new StreamContent(context.Request.Body);
            }

            var forwardRequest = new HttpRequestMessage(new HttpMethod(method), targetUri)
            {
                Content = content
            };

            // Copy headers minus conditionals ...
            static bool IsConditionalHeader(string key) =>
                key.Equals("If-None-Match", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("If-Modified-Since", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("If-Match", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("If-Unmodified-Since", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("If-Range", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Cache-Control", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Pragma", StringComparison.OrdinalIgnoreCase);

            foreach (var header in context.Request.Headers)
            {
                if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                if (IsConditionalHeader(header.Key)) continue;
                if (!forwardRequest.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                    forwardRequest.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
            client.Timeout = TimeSpan.FromHours(2);
            using var responseMessage = await client.SendAsync(
                forwardRequest,
                HttpCompletionOption.ResponseHeadersRead,
                context.RequestAborted);

            context.Response.StatusCode = (int)responseMessage.StatusCode;

            // Copy response headers first (we may override later)
            foreach (var header in responseMessage.Headers)
                context.Response.Headers[header.Key] = header.Value.ToArray();
            foreach (var header in responseMessage.Content.Headers)
                context.Response.Headers[header.Key] = header.Value.ToArray();


            // CACHE POLICY
            var reqPath = context.Request.Path.Value ?? string.Empty;
            var ct = context.Response.ContentType ?? responseMessage.Content.Headers.ContentType?.ToString() ?? "";
            var file = reqPath.AsSpan(); 

            bool IsHtmlShell() =>
                ct.Contains("text/html", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith("/index.html", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith("\\index.html", StringComparison.OrdinalIgnoreCase);

            bool IsDescriptor() =>
                reqPath.EndsWith("app.webmanifest", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith("manifest.json", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith("blazor.boot.json", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith("service-worker-assets.js", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith("asset-manifest.json", StringComparison.OrdinalIgnoreCase) ||      // CRA
                reqPath.EndsWith("vite-manifest.json", StringComparison.OrdinalIgnoreCase) ||       // Vite
                reqPath.Contains("/_next/", StringComparison.OrdinalIgnoreCase) && reqPath.EndsWith("build-manifest.json", StringComparison.OrdinalIgnoreCase); // Next.js

            bool IsServiceWorker() =>
                reqPath.EndsWith("service-worker.js", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith("sw.js", StringComparison.OrdinalIgnoreCase);

            bool IsWasmOrDll() =>
                reqPath.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase) ||
                reqPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);

            bool IsUpdateCritical() => IsHtmlShell() || IsDescriptor() || IsServiceWorker();

            // Helper: overwrite Cache-Control cleanly
            void SetCache(string value)
            {
                context.Response.Headers["Cache-Control"] = value;
                context.Response.Headers.Remove("Pragma");
            }

            // Apply the rules:
            if (IsUpdateCritical() || IsWasmOrDll())
            {
                SetCache("no-cache, must-revalidate");
            }
            else if (isStaticUrl)
            {
                SetCache("public, max-age=86400, must-revalidate");
            }

            // Hop-by-hop cleanup
            context.Response.Headers.Remove("transfer-encoding");
            context.Response.Headers.Remove("Connection");
            context.Response.Headers.Remove("Keep-Alive");
            context.Response.Headers.Remove("Proxy-Authenticate");
            context.Response.Headers.Remove("Proxy-Authorization");
            context.Response.Headers.Remove("TE");
            context.Response.Headers.Remove("Trailer");
            context.Response.Headers.Remove("Upgrade");

            // CORS
            context.Response.Headers["Access-Control-Allow-Origin"] = "*";
            context.Response.Headers["Access-Control-Allow-Headers"] = "*";
            context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";

            // Location rewrite (your existing code)
            if (context.Response.Headers.TryGetValue("Location", out var locations) && locations.Count > 0)
            {
                if (Uri.TryCreate(locations[0], UriKind.Absolute, out var locUri))
                {
                    if ((locUri.Host.Equals("127.0.0.1") || locUri.Host.Equals("localhost")) && locUri.IsAbsoluteUri)
                    {
                        var builder = new UriBuilder
                        {
                            Scheme = context.Request.Scheme,
                            Host = context.Request.Host.Host,
                            Port = context.Request.Host.Port ?? -1,
                            Path = locUri.AbsolutePath,
                            Query = locUri.Query
                        };
                        context.Response.Headers["Location"] = builder.Uri.ToString();
                    }
                }
            }

            var isOk = (int)responseMessage.StatusCode < 400;

            if (responseMessage.StatusCode == System.Net.HttpStatusCode.NotModified ||
                HttpMethods.IsHead(method))
            {
                await context.Response.CompleteAsync();
                return isOk;
            }

            // --- Conditional HTML index rewriting ---
            var contentType = responseMessage.Content.Headers.ContentType?.MediaType ?? "";
            var isHtml = contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase);

            if (rewriteIndexForCid && isHtml && !string.IsNullOrWhiteSpace(basePrefix))
            {
                var html = await responseMessage.Content.ReadAsStringAsync(context.RequestAborted);

                // Insert <base> for everything else
                if (!html.Contains("<base", StringComparison.OrdinalIgnoreCase))
                    html = InjectAfterHead(html, $"<base href=\"{basePrefix}\" />");

                // 1) Rewrite root-relative attributes to include the base, EXCEPT .json/.js (we'll handle those next)
                html = RewriteRootRelativeAttributesButSkipJsonJs(html, basePrefix);

                // 2) For any .json or .js in href/src/action, force ABSOLUTE-ROOT path and append tgcid + ts.
                html = AppendQueryForJsonJsKeepOrigin(html, basePrefix);

                // 3) Early cleanup (SW + caches + IndexedDB) BEFORE anything else runs
                html = InjectBeforeHeadEnd(html, ServiceWorkerAndStorageCleanupScript());

                // 4) Runtime patch for fetch/XHR/WS and 127.0.0.1 block (aware of ?tgcid)
                html = InjectBeforeBodyEnd(html, RuntimePrefixScript(basePrefix));

                var bytes = System.Text.Encoding.UTF8.GetBytes(html);
                context.Response.Headers["Content-Length"] = bytes.Length.ToString();
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.Body.WriteAsync(bytes, 0, bytes.Length, context.RequestAborted);
                return isOk;
            }


            // Default: stream body through untouched
            await responseMessage.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
            return isOk;
        }

        // --- Small HTML helpers (no external deps) ---

        static string InjectAfterHead(string html, string inject)
        {
            var idx = html.IndexOf("<head", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return html; // no head tag, skip
            var close = html.IndexOf(">", idx);
            if (close < 0) return html;
            return html.Insert(close + 1, "\n" + inject + "\n");
        }

        static string InjectBeforeBodyEnd(string html, string inject)
        {
            var idx = html.LastIndexOf("</body", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return html + inject; // no closing body tag, just append
            return html.Insert(idx, "\n" + inject + "\n");
        }

        // Replace href="/..." | src="/..." | action="/..." with the CID/IPNS prefix.
        // Avoid double-prefixing /ipfs/ or /ipns/.
        static string RewriteRootRelativeAttributes(string html, string prefix)
        {
            // very targeted and safe-ish replacements without pulling a full HTML parser
            // patterns: href="/x", src="/x", action="/x"
            string[] attrs = { "href", "src", "action" };
            foreach (var attr in attrs)
            {
                // attr="/..."
                html = System.Text.RegularExpressions.Regex.Replace(
                    html,
                    $@"(?i)\b{attr}\s*=\s*""/(?!ipfs/|ipns/)([^""]*)""",
                    $"{attr}=\"{prefix}$1\"");

                // attr='/...'
                html = System.Text.RegularExpressions.Regex.Replace(
                    html,
                    $@"(?i)\b{attr}\s*=\s*'/(?!ipfs/|ipns/)([^']*)'",
                    $"{attr}='{prefix}$1'");
            }
            return html;
        }

        static string InjectBeforeHeadEnd(string html, string inject)
        {
            var idx = html.LastIndexOf("</head", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return inject + html; // no <head>, prepend
            return html.Insert(idx, "\n" + inject + "\n");
        }

        // Rewrite href/src/action that start with "/" BUT SKIP .json/.js
        static string RewriteRootRelativeAttributesButSkipJsonJs(string html, string prefix)
        {
            string[] attrs = { "href", "src", "action" };
            foreach (var attr in attrs)
            {
                // double-quoted
                html = System.Text.RegularExpressions.Regex.Replace(
                    html,
                    $@"(?ix)
               \b{attr}\s*=\s*""/(?!ipfs/|ipns/)([^""]+?)""   # root-relative
               (?![^""]*\.(?:json|js)"" )                    # but not ending with .json or .js
            ",
                    m => {
                        var url = m.Groups[1].Value; // without leading slash
                        return $"{attr}=\"{prefix}{url}\"";
                    });

                // single-quoted
                html = System.Text.RegularExpressions.Regex.Replace(
                    html,
                    $@"(?ix)
               \b{attr}\s*=\s*'/(?!ipfs/|ipns/)([^']+?)'      # root-relative
               (?![^']*\.(?:json|js)' )                       # but not ending with .json or .js
            ",
                    m => {
                        var url = m.Groups[1].Value;
                        return $"{attr}='{prefix}{url}'";
                    });
            }
            return html;
        }

        // For any href/src/action that points to *.json or *.js,
        // leave it same-origin (force absolute-root) and append ?tgcid=<cid>&ts=<unix>
        // Use this instead of the previous AppendQueryForJsonJsKeepOrigin
        // unchanged signature, just ensure it ALWAYS outputs "/<path>?...":
        static string AppendQueryForJsonJsKeepOrigin(string html, string basePrefix)
        {
            var (qKey, qVal) = ExtractIdKeyAndValueFromBase(basePrefix);
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

            string AddOrAppendPreservingQuery(string url)
            {
                var u = (url ?? "").Trim();

                // leave absolute http(s) alone
                if (u.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    u.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    return url;

                // *** Force absolute-root, collapsing "./" and extra "/" ***
                u = "/" + u.TrimStart('.', '/');

                // split, merge query, add tgcid/tgipns + ts
                string path, query;
                var qIdx = u.IndexOf('?', StringComparison.Ordinal);
                if (qIdx >= 0) { path = u[..qIdx]; query = u[(qIdx + 1)..]; }
                else { path = u; query = string.Empty; }

                var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (!string.IsNullOrEmpty(query))
                {
                    foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var k = part; var v = "";
                        var i = part.IndexOf('=');
                        if (i >= 0) { k = part[..i]; v = part[(i + 1)..]; }
                        dict[Uri.UnescapeDataString(k)] = Uri.UnescapeDataString(v);
                    }
                }
                dict[qKey] = qVal;
                dict["ts"] = ts;

                var rebuilt = string.Join("&", dict.Select(kv =>
                    string.IsNullOrEmpty(kv.Value) ? Uri.EscapeDataString(kv.Key)
                                                   : $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

                return $"{path}?{rebuilt}";
            }

            string[] attrs = { "href", "src", "action" };
            foreach (var attr in attrs)
            {
                // double-quoted
                html = System.Text.RegularExpressions.Regex.Replace(
                    html,
                    $@"(?ix)\b{attr}\s*=\s*""([^""]*\.(?:json|js|webmanifest)(?:\?[^""]*)?)""",
                    m => $"{attr}=\"{AddOrAppendPreservingQuery(m.Groups[1].Value)}\"");

                // single-quoted
                html = System.Text.RegularExpressions.Regex.Replace(
                    html,
                    $@"(?ix)\b{attr}\s*=\s*'([^']*\.(?:json|js|webmanifest)(?:\?[^']*)?)'",
                    m => $"{attr}='{AddOrAppendPreservingQuery(m.Groups[1].Value)}'");
            }
            return html;
        }



        // Decide query key + value based on /ipfs/<cid>/ vs /ipns/<name>/
        static (string key, string value) ExtractIdKeyAndValueFromBase(string basePrefix)
        {
            var parts = basePrefix.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                if (parts[0].Equals("ipfs", StringComparison.OrdinalIgnoreCase))
                    return ("tgcid", parts[1]);
                if (parts[0].Equals("ipns", StringComparison.OrdinalIgnoreCase))
                    return ("tgipns", parts[1]);
            }
            return ("tgcid", ""); // fallback (shouldn’t happen if basePrefix is correct)
        }

        static string ServiceWorkerAndStorageCleanupScript() => @"
<script>
(function() {
  // Unregister all service workers ASAP
  if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
    navigator.serviceWorker.getRegistrations().then(function(regs) {
      regs.forEach(function(r){ r.unregister().catch(()=>{}); });
    }).catch(()=>{});
  }

  // Clear Cache Storage
  if (window.caches && caches.keys) {
    caches.keys().then(function(keys){
      return Promise.all(keys.map(function(k){ return caches.delete(k); }));
    }).catch(()=>{});
  }

  // Nuke IndexedDB databases (best-effort)
  try {
    if (indexedDB.databases) {
      indexedDB.databases().then(function(list){
        (list || []).forEach(function(db){
          if (db && db.name) { try { indexedDB.deleteDatabase(db.name); } catch(e){} }
        });
      }).catch(()=>{});
    }
  } catch(e) { /* older browsers */ }
})();
</script>";


        static string RuntimePrefixScript(string basePrefix)
        {
            return $@"
<script>
(function() {{
  var BASE = {System.Text.Json.JsonSerializer.Serialize(basePrefix)};

  function isBlockedLocal(u) {{
    return typeof u === 'string' &&
           (u.startsWith('http://127.0.0.1:5001') || u.startsWith('https://127.0.0.1:5001') ||
            u.startsWith('http://localhost:5001') || u.startsWith('https://localhost:5001'));
  }}

  function isJsonJs(u) {{
    return /\\.(json|js)(\\?|$)/i.test(u);
  }}

  function hasTgcid(u) {{
    return /[?&]tgcid=/.test(u);
  }}

  function qualify(u) {{
  try {{
    if (!u || typeof u !== 'string') return u;

    if (isBlockedLocal(u)) throw new Error('Blocked request to local node');

    // Absolute http(s): leave alone
    if (u.startsWith('http://') || u.startsWith('https://')) return u;

    // JSON/JS (and URLs already carrying tgcid/tgipns):
    // - If already root-absolute, return as-is.
    // - If relative (e.g., ""./manifest.json""), force to ""/manifest.json""
    if (isJsonJs(u) || hasTgcid(u)) {{
      if (u.startsWith('/')) return u;
      return '/' + u.replace(/^[./]+/, '');
    }}

    // Already ipfs/ipns to leave
    if (u.startsWith('/ipfs/') || u.startsWith('/ipns/')) return u;

    // Non JSON/JS: route under BASE
    if (u.startsWith('/')) return BASE + u.substring(1);
    return BASE + u;
  }} catch (e) {{
    console.warn(e.message || e, u);
    return '';
  }}
}}


  // fetch
  var _fetch = window.fetch;
  window.fetch = function(input, init) {{
    try {{
      if (typeof input === 'string') {{
        input = qualify(input);
        if (!input) return Promise.reject('Blocked request');
      }} else if (input && input.url) {{
        var newUrl = qualify(input.url);
        if (!newUrl) return Promise.reject('Blocked request');
        input = new Request(newUrl, input);
      }}
    }} catch (e) {{ return Promise.reject(e); }}
    return _fetch(input, init);
  }};

  // XHR
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {{
    var newUrl = qualify(url);
    if (!newUrl) throw new Error('Blocked XHR request');
    return _open.call(this, method, newUrl, async, user, pass);
  }};

  // WebSocket
  var _WS = window.WebSocket;
  window.WebSocket = function(url, protocols) {{
    if (isBlockedLocal(url)) throw new Error('Blocked WebSocket to local node');
    var q = qualify(url);
    if (!q) throw new Error('Blocked WebSocket request');
    if (q.startsWith('http')) q = q.replace(/^http(s?):/i, 'ws$1:');
    return new _WS(q, protocols);
  }};

  // Anchor clicks (respect ?tgcid URLs and block localhost)
  document.addEventListener('click', function(ev) {{
    var a = ev.target.closest && ev.target.closest('a[href]');
    if (!a) return;
    var href = a.getAttribute('href');
    if (!href) return;

    if (isBlockedLocal(href)) {{
      ev.preventDefault();
      console.warn('Blocked navigation to local node:', href);
      return;
    }}

    // Absolute external stays
    if (href.startsWith('http://') || href.startsWith('https://')) return;

    // JSON/JS or ?tgcid : leave as-is (root-absolute expected)
    if (/\\.(json|js)(\\?|$)/i.test(href) || /[?&]tgcid=/.test(href)) return;

    if (href.startsWith('/') || !href.startsWith('#')) {{
      ev.preventDefault();
      var dest = qualify(href);
      if (dest) window.location.assign(dest);
    }}
  }}, true);

}})();
</script>";
        }




    }

}

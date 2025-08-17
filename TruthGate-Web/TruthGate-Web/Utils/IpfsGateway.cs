using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using System.Text.Json;
using TruthGate_Web.Endpoints;

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
        /// Formats a CID via /api/v0/cid/format using the TruthGate proxy pipeline.
        /// Returns null if conversion isn’t possible (e.g., v0 constraints) or the node rejects it.
        /// </summary>
        public static async Task<string?> FormatCidAsync(
            string cid,
            int version,
            string baseEncoding,
            IHttpClientFactory clientFactory)
        {
            // Build the IPFS API REST (not a full URL!) that your proxy will forward.
            // Example: /api/v0/cid/format?arg=<cid>&v=1&b=base32
            var rest = $"/api/v0/cid/format?arg={Uri.EscapeDataString(cid)}&v={version}&b={Uri.EscapeDataString(baseEncoding)}";

            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, clientFactory);
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

        private static void InvalidateMfsCascade(string mfsPath)
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

            // Targeted: invalidate MFS→CID for this path and all parents (so new CIDs will be fetched)
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



        // ----- MFS folder → root CID (with cache), and local presence checks -----
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
        public static async Task<bool> Proxy(HttpContext context, string targetUri, IHttpClientFactory clientFactory)
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

    // Copy headers, but strip conditionals that trigger 304s (especially for /webui)
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
        {
            forwardRequest.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
        }
    }

    // Send
    using var responseMessage = await client.SendAsync(
        forwardRequest,
        HttpCompletionOption.ResponseHeadersRead,
        context.RequestAborted);

    // Set status
    context.Response.StatusCode = (int)responseMessage.StatusCode;

    // Copy response headers (rewrite Location if it points to localhost:5001 etc.)
    foreach (var header in responseMessage.Headers)
        context.Response.Headers[header.Key] = header.Value.ToArray();
    foreach (var header in responseMessage.Content.Headers)
        context.Response.Headers[header.Key] = header.Value.ToArray();

    // Hop-by-hop headers: remove what can break Kestrel
    context.Response.Headers.Remove("transfer-encoding");
    context.Response.Headers.Remove("Connection");
    context.Response.Headers.Remove("Keep-Alive");
    context.Response.Headers.Remove("Proxy-Authenticate");
    context.Response.Headers.Remove("Proxy-Authorization");
    context.Response.Headers.Remove("TE");
    context.Response.Headers.Remove("Trailer");
    context.Response.Headers.Remove("Upgrade");

    // CORS (if desired)
    context.Response.Headers["Access-Control-Allow-Origin"] = "*";
    context.Response.Headers["Access-Control-Allow-Headers"] = "*";
    context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";

    // --- Location rewrite ---
    if (context.Response.Headers.TryGetValue("Location", out var locations) && locations.Count > 0)
    {
        // If node redirected to http://127.0.0.1:5001/..., rewrite to our origin with same path+query
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

    // Consider 2xx **and** 3xx responses as "proxy success"
    var isOk = (int)responseMessage.StatusCode < 400;

    // Never write a body for 304/HEAD
    if (responseMessage.StatusCode == System.Net.HttpStatusCode.NotModified ||
        HttpMethods.IsHead(method))
    {
        await context.Response.CompleteAsync();
        return isOk;
    }

    // Stream body
    await responseMessage.Content.CopyToAsync(context.Response.Body);
    return isOk;
}

    }

}

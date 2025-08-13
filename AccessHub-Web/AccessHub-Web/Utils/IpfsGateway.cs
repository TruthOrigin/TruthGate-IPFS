using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;
using System.Text.Json;

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
            string cid, string rest, IHttpClientFactory factory, IMemoryCache cache, TimeSpan ttl)
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
                var map = await ListDirMapCachedAsync(cid, currentDir, factory, cache, ttl);
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

        // Returns: (exists, correctedPath)
        public static async Task<(bool exists, string? correctedPath)> PathExistsInIpfsAsync(
            string cid,
            string rest,
            int gatewayPort,
            IHttpClientFactory factory,
            IMemoryCache cache,
            TimeSpan ttl)
        {
            string? correctedPath = null;

            var input = (rest ?? string.Empty).Trim('/');
            var inputLower = input.ToLowerInvariant();
            if (string.IsNullOrEmpty(input)) return (true, "");

            // 1) Cached resolved path?
            if (cache.TryGetValue<string>(ResolveCacheKey(cid, inputLower), out var cachedResolved))
            {
                correctedPath = cachedResolved;
                if (cache.TryGetValue<bool>(ExistsCacheKey(cid, cachedResolved), out var existsCached))
                    return (existsCached, correctedPath);

                var existsHead = await PathExistsHeadAsync(cid, cachedResolved, gatewayPort, factory);
                cache.Set(ExistsCacheKey(cid, cachedResolved), existsHead, new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

                return (existsHead, correctedPath);
            }

            // 2) Fast HEAD as-is
            if (await PathExistsHeadAsync(cid, input, gatewayPort, factory))
            {
                correctedPath = input;

                cache.Set(ResolveCacheKey(cid, inputLower), correctedPath, new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

                cache.Set(ExistsCacheKey(cid, correctedPath), true, new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

                return (true, correctedPath);
            }

            // 3) Slow: case-insensitive walk
            var resolved = await ResolvePathCaseInsensitiveAsync(cid, input, factory, cache, ttl);
            if (resolved is null)
            {
                cache.Set(ResolveCacheKey(cid, inputLower), "", new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = ttl
                }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

                return (false, null);
            }

            var ok = await PathExistsHeadAsync(cid, resolved, gatewayPort, factory);
            correctedPath = ok ? resolved : null;

            cache.Set(ResolveCacheKey(cid, inputLower), correctedPath ?? "", new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

            cache.Set(ExistsCacheKey(cid, resolved), ok, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            }.AddExpirationToken(IpfsCacheIndex.GetCidToken(cid)));

            return (ok, correctedPath);
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

            HttpContent? content = null;
            if (method != "GET" && method != "HEAD")
            {
                content = (context.Request.ContentLength is null or 0)
                    ? new StringContent("")
                    : new StreamContent(context.Request.Body);
            }

            var forwardRequest = new HttpRequestMessage(new HttpMethod(method), targetUri)
            {
                Content = content
            };

            foreach (var header in context.Request.Headers)
            {
                if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                if (!forwardRequest.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                {
                    forwardRequest.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }

            var responseMessage = await client.SendAsync(
                forwardRequest,
                HttpCompletionOption.ResponseHeadersRead,
                context.RequestAborted);

            context.Response.StatusCode = (int)responseMessage.StatusCode;

            // Treat non-success (and explicit 404/410) as a proxy failure signal (caller may invalidate + retry)
            if (!responseMessage.IsSuccessStatusCode
                || responseMessage.StatusCode == System.Net.HttpStatusCode.NotFound
                || responseMessage.StatusCode == System.Net.HttpStatusCode.Gone)
            {
                return false;
            }

            foreach (var header in responseMessage.Headers)
                context.Response.Headers[header.Key] = header.Value.ToArray();
            foreach (var header in responseMessage.Content.Headers)
                context.Response.Headers[header.Key] = header.Value.ToArray();

            context.Response.Headers["Access-Control-Allow-Origin"] = "*";
            context.Response.Headers["Access-Control-Allow-Headers"] = "*";
            context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
            context.Response.Headers.Remove("transfer-encoding");

            await responseMessage.Content.CopyToAsync(context.Response.Body);

            return true;
        }
    }

}

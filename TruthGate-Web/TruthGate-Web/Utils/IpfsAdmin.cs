using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Services;

namespace TruthGate_Web.Utils
{
    public static class IpfsAdmin // lives near IpfsGateway
    {
        // Create key if missing. type=ed25519.
        public static async Task<(string Name, string Id)> EnsureKeyAsync(
            string keyName, IHttpClientFactory http, IApiKeyProvider keys)
        {
            // /api/v0/key/list — if exists, return
            using (var list = await ApiProxyEndpoints.SendProxyApiRequest("/api/v0/key/list", http, keys))
            {
                var json = await list.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("Keys", out var arr) && arr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var k in arr.EnumerateArray())
                    {
                        if (string.Equals(k.GetProperty("Name").GetString(), keyName, StringComparison.OrdinalIgnoreCase))
                            return (keyName, k.GetProperty("Id").GetString() ?? "");
                    }
                }
            }

            // /api/v0/key/gen?arg=<name>&type=ed25519
            var gen = $"/api/v0/key/gen?arg={Uri.EscapeDataString(keyName)}&type=ed25519";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(gen, http, keys);
            res.EnsureSuccessStatusCode();
            var js = await res.Content.ReadAsStringAsync();
            using var doc2 = JsonDocument.Parse(js);
            return (doc2.RootElement.GetProperty("Name").GetString()!, doc2.RootElement.GetProperty("Id").GetString()!);
        }

        // Export/import private key (we store armored form encrypted in config backup).
        public static async Task<string> KeyExportArmoredAsync(
            string keyName, string password, IHttpClientFactory http, IApiKeyProvider keys)
        {
            var rest = $"/api/v0/key/export?arg={Uri.EscapeDataString(keyName)}&password={Uri.EscapeDataString(password)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys);
            res.EnsureSuccessStatusCode();
            return await res.Content.ReadAsStringAsync(); // PEM-like armored text
        }

        public static async Task<(string Name, string Id)> KeyImportArmoredAsync(
            string keyName, string password, string armored, IHttpClientFactory http, IApiKeyProvider keys)
        {
            // multipart: key=<file>, arg=<newName>, password=...
            var content = new MultipartFormDataContent();
            content.Add(new StringContent(armored), "key"); // many nodes also accept file; this form works in practice
            var rest = $"/api/v0/key/import?arg={Uri.EscapeDataString(keyName)}&password={Uri.EscapeDataString(password)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, content);
            res.EnsureSuccessStatusCode();
            var js = await res.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(js);
            return (doc.RootElement.GetProperty("Name").GetString()!, doc.RootElement.GetProperty("Id").GetString()!);
        }
        public static async Task FilesRmIfExistsAsync(
       string mfsPath,
       IHttpClientFactory http,
       IApiKeyProvider keys,
       CancellationToken ct = default)
        {
            var norm = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/rm?arg={Uri.EscapeDataString(norm)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            // ignore non-2xx: it simply didn't exist
        }

        public static async Task EnsureMfsFolderExistsAsync(
            string mfsPath,
            IHttpClientFactory http,
            IApiKeyProvider keys,
            CancellationToken ct = default)
        {
            var norm = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/mkdir?arg={Uri.EscapeDataString(norm)}&parents=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            // Treat "already exists" as success.
            if (!res.IsSuccessStatusCode)
            {
                var body = await res.Content.ReadAsStringAsync(ct);
                if (!body.Contains("file already exists", StringComparison.OrdinalIgnoreCase))
                    res.EnsureSuccessStatusCode();
            }
        }

        // Write bytes to MFS (create+parents+truncate). Mirrors your style.
        private static MediaTypeHeaderValue BuildContentType(string? contentType)
        {
            // Accept things like "text/html; charset=utf-8" or just "text/html"
            if (!string.IsNullOrWhiteSpace(contentType))
            {
                if (MediaTypeHeaderValue.TryParse(contentType, out var parsed))
                    return parsed;

                // Fallback: take just the media type portion before ';'
                var leaf = contentType.Split(';')[0].Trim();
                if (!string.IsNullOrWhiteSpace(leaf))
                {
                    try { return new MediaTypeHeaderValue(leaf); } catch { /* ignore */ }
                }
            }
            return new MediaTypeHeaderValue("application/octet-stream");
        }

        public static async Task FilesWriteAsync(
            string mfsPath,
            Stream data,
            IHttpClientFactory http,
            IApiKeyProvider keys,
            string? contentType = "application/octet-stream",
            CancellationToken ct = default)
        {
            var path = IpfsGateway.NormalizeMfs(mfsPath);

            // Ensure parent exists
            var lastSlash = path.LastIndexOf('/');
            var parent = lastSlash > 0 ? path[..lastSlash] : "/";
            await FilesMkdirAsync(parent, http, keys, ct, parents: true);

            // Replace existing file to avoid truncate edge cases
            await FilesRmIfExistsAsync(path, http, keys, ct);

            var rest = $"/api/v0/files/write?arg={Uri.EscapeDataString(path)}&create=true&parents=true";

            using var form = new MultipartFormDataContent();
            using var filePart = new StreamContent(data);
            filePart.Headers.ContentType = BuildContentType(contentType);

            var leaf = System.IO.Path.GetFileName(path);
            form.Add(filePart, "data", string.IsNullOrEmpty(leaf) ? "blob" : leaf);

            using var res = await ApiProxyEndpoints.SendProxyApiRequest(
                rest, http, keys, content: form, method: "POST", ct: ct);

            if (!res.IsSuccessStatusCode)
            {
                var body = await res.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException($"files/write failed '{path}' ({(int)res.StatusCode}) — {body}");
            }
        }


        public static async Task FilesCpFromIpfsAsync(string cid, string destMfs, IHttpClientFactory http, IApiKeyProvider keys)
        {
            var from = $"/ipfs/{cid}";
            var rest = $"/api/v0/files/cp?arg={Uri.EscapeDataString(from)}&arg={Uri.EscapeDataString(destMfs)}&parents=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys);
            res.EnsureSuccessStatusCode();
        }

        public static async Task<string?> FilesStatHashAsync(
      string mfsPath,
      IHttpClientFactory http,
      IApiKeyProvider keys,
      CancellationToken ct = default)
        {
            var norm = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/stat?arg={Uri.EscapeDataString(norm)}";

            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, ct: ct);
            if (!res.IsSuccessStatusCode) return null;

            await using var s = await res.Content.ReadAsStreamAsync(ct);
            using var doc = await JsonDocument.ParseAsync(s, cancellationToken: ct);

            return doc.RootElement.TryGetProperty("Hash", out var hashEl)
                ? hashEl.GetString()
                : null;
        }


        public static async Task NamePublishAsync(string keyName, string targetCid, IHttpClientFactory http, IApiKeyProvider keys)
        {
            // publish /ipfs/<cid> using the named key
            var rest = $"/api/v0/name/publish?arg={Uri.EscapeDataString($"/ipfs/{targetCid}")}&key={Uri.EscapeDataString(keyName)}&allow-offline=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys);
            res.EnsureSuccessStatusCode();
        }

        // Create an MFS directory. Parents=true by default.
        public static async Task FilesMkdirAsync(
       string mfsPath,
       IHttpClientFactory http,
       IApiKeyProvider keys,
       CancellationToken ct = default,
       bool parents = true)
        {
            var norm = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/mkdir?arg={Uri.EscapeDataString(norm)}&parents={(parents ? "true" : "false")}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            if (!res.IsSuccessStatusCode)
            {
                var body = await res.Content.ReadAsStringAsync(ct);
                if (res.StatusCode != HttpStatusCode.Conflict &&
                    !body.Contains("file already exists", StringComparison.OrdinalIgnoreCase))
                    res.EnsureSuccessStatusCode();
            }
        }


    }

}

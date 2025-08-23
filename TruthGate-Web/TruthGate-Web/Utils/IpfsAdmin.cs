using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Services;

namespace TruthGate_Web.Utils
{
    public static class IpfsAdmin // lives near IpfsGateway
    {
        // Centralized cache invalidation hooks
        public static void InvalidateMfsPath(string mfsPath) => IpfsGateway.InvalidateMfsCascade(mfsPath);
        public static void InvalidateCid(string cid) => IpfsCacheIndex.InvalidateCid(cid);

        // Remove folder/file recursively and bust caches
        public static async Task FilesRmTreeAsync(
            string mfsPath, IHttpClientFactory http, IApiKeyProvider keys, CancellationToken ct = default)
        {
            var norm = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/rm?arg={Uri.EscapeDataString(norm)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            // ignore non-2xx; path may not exist
            InvalidateMfsPath(norm);
        }

        // Safe mkdir + invalidate
        public static async Task FilesMkdirAsync(
            string mfsPath, IHttpClientFactory http, IApiKeyProvider keys, CancellationToken ct = default)
        {
            var norm = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/mkdir?arg={Uri.EscapeDataString(norm)}&parents=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            if (!res.IsSuccessStatusCode)
            {
                var body = await res.Content.ReadAsStringAsync(ct);
                if (!body.Contains("file already exists", StringComparison.OrdinalIgnoreCase))
                    res.EnsureSuccessStatusCode();
            }
            InvalidateMfsPath(norm);
        }

        // Move + invalidate both ends
        public static async Task FilesMvAsync(
            string from, string to, IHttpClientFactory http, IApiKeyProvider keys, CancellationToken ct = default)
        {
            var normFrom = IpfsGateway.NormalizeMfs(from);
            var normTo = IpfsGateway.NormalizeMfs(to);
            var rest = $"/api/v0/files/mv?arg={Uri.EscapeDataString(normFrom)}&arg={Uri.EscapeDataString(normTo)}&parents=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            res.EnsureSuccessStatusCode();
            InvalidateMfsPath(normFrom);
            InvalidateMfsPath(normTo);
        }

        // CP (MFStoMFS) + invalidate dest
        public static async Task FilesCpAsync(
            string from, string to, IHttpClientFactory http, IApiKeyProvider keys, CancellationToken ct = default)
        {
            var normFrom = IpfsGateway.NormalizeMfs(from);
            var normTo = IpfsGateway.NormalizeMfs(to);
            var rest = $"/api/v0/files/cp?arg={Uri.EscapeDataString(normFrom)}&arg={Uri.EscapeDataString(normTo)}&parents=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            res.EnsureSuccessStatusCode();
            InvalidateMfsPath(normTo);
        }

        // Pin/unpin wrappers (bust CID cache)
        public static async Task PinAddRecursiveAsync(string cid, IHttpClientFactory http, IApiKeyProvider keys, CancellationToken ct = default)
        {
            var rest = $"/api/v0/pin/add?arg={Uri.EscapeDataString(cid)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, ct: ct);
            res.EnsureSuccessStatusCode();
            InvalidateCid(cid);
        }

        public static async Task PinRmRecursiveIfAsync(string cid, IHttpClientFactory http, IApiKeyProvider keys, CancellationToken ct = default)
        {
            var rest = $"/api/v0/pin/rm?arg={Uri.EscapeDataString(cid)}&recursive=true";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, ct: ct);
            // ignore errors; still invalidate
            InvalidateCid(cid);
        }

        // Key removal (best-effort)
        public static async Task KeyRemoveIfExistsAsync(
            string keyName, IHttpClientFactory http, IApiKeyProvider keys, CancellationToken ct = default)
        {
            var rest = $"/api/v0/key/rm?arg={Uri.EscapeDataString(keyName)}";
            using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, method: "POST", ct: ct);
            // Some nodes 404 if missing — that's fine.
        }

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
    string keyName, string passphrase, IHttpClientFactory http, IApiKeyProvider keys,
    string? ipfsPath = null, string ipfsExe = "ipfs", CancellationToken ct = default)
        {
            // 1) Try RPC (will 404 on vanilla Kubo)
            var rest = $"/api/v0/key/export?arg={Uri.EscapeDataString(keyName)}&password={Uri.EscapeDataString(passphrase)}";
            using (var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys))
            {
                if (res.IsSuccessStatusCode)
                    return await res.Content.ReadAsStringAsync();

                // If it’s anything other than 404, surface it (bad key name, auth, etc.)
                if (res.StatusCode != System.Net.HttpStatusCode.NotFound)
                {
                    var body = await res.Content.ReadAsStringAsync();
                    throw new InvalidOperationException($"key/export failed: {(int)res.StatusCode} {body}");
                }
            }

            // 2) Fallback: use CLI export (cleartext PKCS#8 PEM), then higher-level code can seal it.
            //    We write to a temp file because older Kubo doesn't support stdout for export.
            var tmp = Path.Combine(Path.GetTempPath(), $"tg-key-{Guid.NewGuid():N}.pem");
            try
            {
                var args = $"key export {EscapeArg(keyName)} -f pem-pkcs8-cleartext -o {EscapeArg(tmp)}";
                var psi = new System.Diagnostics.ProcessStartInfo(ipfsExe, args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                if (!string.IsNullOrWhiteSpace(ipfsPath))
                    psi.Environment["IPFS_PATH"] = ipfsPath;

                using var p = System.Diagnostics.Process.Start(psi)!;
                var stderr = await p.StandardError.ReadToEndAsync();
                var stdout = await p.StandardOutput.ReadToEndAsync();
                await p.WaitForExitAsync(ct);

                if (p.ExitCode != 0)
                    throw new InvalidOperationException($"ipfs key export failed (exit {p.ExitCode}): {stderr}\n{stdout}");

                // Read the PEM we just exported
                return await File.ReadAllTextAsync(tmp, ct);
            }
            finally
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* best effort */ }
            }

            static string EscapeArg(string s)
                => s.Any(ch => char.IsWhiteSpace(ch) || ch is '"' or '\'')
                   ? $"\"{s.Replace("\"", "\\\"")}\"" : s;
        }


        public static async Task<(string Name, string Id)> KeyImportArmoredAsync(
    string keyName, string password, string armored,
    IHttpClientFactory http, IApiKeyProvider keys,
    string? ipfsPath = null, string ipfsExe = "ipfs",
    CancellationToken ct = default)
        {
            // --- 1) Try RPC with correct format and multipart ---
            var rest = $"/api/v0/key/import?arg={Uri.EscapeDataString(keyName)}" +
                       $"&password={Uri.EscapeDataString(password)}" +
                       $"&format=pem-pkcs8-cleartext";

            using (var content = new MultipartFormDataContent())
            {
                // send as a file part with a filename; many servers care
                var bytes = Encoding.UTF8.GetBytes(armored);
                var file = new ByteArrayContent(bytes);
                file.Headers.ContentType = new MediaTypeHeaderValue("application/x-pem-file");
                content.Add(file, "key", "key.pem"); // field name 'key' matches Kubo’s expectation

                using var res = await ApiProxyEndpoints.SendProxyApiRequest(rest, http, keys, content);
                if (res.IsSuccessStatusCode)
                {
                    var js = await res.Content.ReadAsStringAsync(ct);
                    using var doc = JsonDocument.Parse(js);
                    return (doc.RootElement.GetProperty("Name").GetString()!,
                            doc.RootElement.GetProperty("Id").GetString()!);
                }

                // If endpoint isn’t there, or clearly not supported, fall back to CLI.
                // Surface other errors (bad password, malformed PEM, etc.) unless you prefer to always fall back.
                if (res.StatusCode != HttpStatusCode.NotFound)
                {
                    var body = await res.Content.ReadAsStringAsync(ct);
                    // A common failure is "failed to decode private key" when format is wrong — we set it above.
                    throw new InvalidOperationException($"key/import failed: {(int)res.StatusCode} {body}");
                }
            }

            // --- 2) Fallback: CLI `ipfs key import -f pem-pkcs8-cleartext <name> <file>` ---
            var tmp = Path.Combine(Path.GetTempPath(), $"tg-key-{Guid.NewGuid():N}.pem");
            try
            {
                await File.WriteAllTextAsync(tmp, armored, ct);

                var args = $"key import {EscapeArg(keyName)} -f pem-pkcs8-cleartext {EscapeArg(tmp)}";
                var psi = new ProcessStartInfo(ipfsExe, args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                if (!string.IsNullOrWhiteSpace(ipfsPath))
                    psi.Environment["IPFS_PATH"] = ipfsPath;

                using var p = Process.Start(psi)!;
                var stderr = await p.StandardError.ReadToEndAsync();
                var stdout = await p.StandardOutput.ReadToEndAsync();
                await p.WaitForExitAsync(ct);

                if (p.ExitCode != 0)
                    throw new InvalidOperationException($"ipfs key import failed (exit {p.ExitCode}): {stderr}\n{stdout}");

                // CLI doesn’t echo JSON; resolve imported key’s peer ID:
                // `ipfs key list -l` prints "<peerId> <name>"
                var whoArgs = "key list -l";
                var who = new ProcessStartInfo(ipfsExe, whoArgs)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                if (!string.IsNullOrWhiteSpace(ipfsPath))
                    who.Environment["IPFS_PATH"] = ipfsPath;

                using var p2 = Process.Start(who)!;
                var out2 = await p2.StandardOutput.ReadToEndAsync();
                await p2.WaitForExitAsync(ct);

                // Find the line with our key name
                var line = out2.Split('\n')
                               .FirstOrDefault(l => l.TrimEnd()
                                                     .EndsWith($" {keyName}", StringComparison.Ordinal));
                var id = line?.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()
                         ?? throw new InvalidOperationException("Imported key, but could not resolve PeerId.");
                return (keyName, id);
            }
            finally
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }

            static string EscapeArg(string s)
                => s.Any(ch => char.IsWhiteSpace(ch) || ch is '"' or '\'')
                   ? $"\"{s.Replace("\"", "\\\"")}\"" : s;
        }

        public static async Task FilesRmIfExistsAsync(
    string mfsPath,
    IHttpClientFactory http,
    IApiKeyProvider keys,
    bool recursive = false,
    CancellationToken ct = default)
        {
            var norm = IpfsGateway.NormalizeMfs(mfsPath);
            var rest = $"/api/v0/files/rm?arg={Uri.EscapeDataString(norm)}";
            if (recursive) rest += "&recursive=true";

            using var res = await ApiProxyEndpoints.SendProxyApiRequest(
                rest, http, keys, method: "POST", ct: ct);

            // Intentionally ignore non-2xx to “didn’t exist” / partial cleanup situations
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
            await FilesRmIfExistsAsync(path, http, keys, recursive: false, ct);

            var rest = $"/api/v0/files/write?arg={Uri.EscapeDataString(path)}&create=true&parents=true";

            // Wrap to avoid disposing the caller's stream
            var nonDisposing = new NonDisposingStream(data);
            var filePart = new StreamContent(nonDisposing);
            filePart.Headers.ContentType = BuildContentType(contentType);

            var form = new MultipartFormDataContent();
            var leaf = System.IO.Path.GetFileName(path);
            form.Add(filePart, "data", string.IsNullOrEmpty(leaf) ? "blob" : leaf);

            try
            {
                using var res = await ApiProxyEndpoints.SendProxyApiRequest(
                    rest, http, keys, content: form, method: "POST", ct: ct);

                if (!res.IsSuccessStatusCode)
                {
                    var body = await res.Content.ReadAsStringAsync(ct);
                    throw new InvalidOperationException($"files/write failed '{path}' ({(int)res.StatusCode}) — {body}");
                }
            }
            finally
            {
                // Dispose the HttpContent wrappers, but NOT the caller's stream
                form.Dispose();       // disposes filePart and nonDisposing (which is a no-op)
                filePart.Dispose();   // redundant, but explicit is fine
                                      // do NOT dispose 'data' here
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

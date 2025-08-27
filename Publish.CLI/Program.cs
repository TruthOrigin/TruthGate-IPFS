using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Web; // for URL decoding via HttpUtility

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var opts = Options.Parse(args);
            if (opts.ShowHelp)
            {
                Console.WriteLine(Options.HelpText);
                return 0;
            }

            opts.ValidateOrThrow();

            // Canonicalize the root once (absolute, normalized, trailing sep)
            var rootCanonical = ToCanonicalDir(opts.Root);

            var url = $"https://{opts.UserIp}/api/truthgate/v1/admin/{opts.Domain}/publish";
            Console.WriteLine($"→ Endpoint: {url}");
            Console.WriteLine($"→ Root:     {rootCanonical}");
            Console.WriteLine($"→ Files:    scanning…");

            long totalBytes = 0;
            long safeCount = 0;
            long skipped = 0;

            foreach (var p in Directory.EnumerateFiles(rootCanonical, "*", SearchOption.AllDirectories))
            {
                if (TryMakeSafeRelative(rootCanonical, p, out _, out var reason))
                {
                    try { totalBytes += new FileInfo(p).Length; safeCount++; } catch { /* unreadable file */ }
                }
                else
                {
                    skipped++;
                    if (opts.Verbose) Console.WriteLine($"   ! Skipping (scan) {p} (reason: {reason})");
                }
            }

            Console.WriteLine($"→ Found {safeCount:n0} safe files; total size ≈ {FormatBytes(totalBytes)}");
            if (skipped > 0)
                Console.WriteLine($"→ Skipped {skipped:n0} file(s) due to unsafe relative paths.");

            // Re-enumerate for actual sending
            var files = Directory.EnumerateFiles(rootCanonical, "*", SearchOption.AllDirectories);

            var host = ExtractHost(url);
            var isIpV4 = IsIpv4Literal(host);

            // Optional: if your server expects a particular SNI host (cert/site selection), let the user pass it.
            // You could add a flag like --sniHost and plumb it into Options.
            string? sniHost = null; // e.g. opts.SniHost; keep null if you don’t need it.

            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
                MaxConnectionsPerServer = 8,

                // Super important: do NOT go through system proxy when calling a raw IP.
                UseProxy = false,
                Proxy = null,

                SslOptions = new SslClientAuthenticationOptions
                {
                    // If you need to override SNI host (server selects site/cert by name even when you connect by IP)
                    TargetHost = sniHost ?? host,
                    RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                        opts.Insecure || errors == SslPolicyErrors.None
                }
            };

            // If the user gave an IPv4 literal, wire a direct IPv4 connect (no name resolution/proxy magic).
            if (isIpV4)
            {
                handler.ConnectCallback = async (context, cancellationToken) =>
                {
                    var dest = context.DnsEndPoint;   // host/port from the request URI
                                                      // Parse exactly the IPv4 given in the URL; if this fails, we never should’ve thought it was IPv4.
                    if (!System.Net.IPAddress.TryParse(dest.Host, out var ip) ||
                        ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        throw new IOException($"Invalid IPv4 literal: {dest.Host}");
                    }

                    var socket = new System.Net.Sockets.Socket(
                        System.Net.Sockets.AddressFamily.InterNetwork,
                        System.Net.Sockets.SocketType.Stream,
                        System.Net.Sockets.ProtocolType.Tcp);

                    try
                    {
                        socket.NoDelay = true;
                        using var reg = cancellationToken.Register(() => { try { socket.Dispose(); } catch { } });
                        await socket.ConnectAsync(new System.Net.IPEndPoint(ip, dest.Port), cancellationToken).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                };
            }

            var client = new HttpClient(handler)
            {
                Timeout = Timeout.InfiniteTimeSpan
            };

            // If you want to avoid any HTTP/2/ALPN surprises:
            client.DefaultRequestVersion = HttpVersion.Version11;

            // Expect: 100-continue sometimes hurts rather than helps on some stacks; feel free to keep/remove.
            client.DefaultRequestHeaders.ExpectContinue = true;
            client.DefaultRequestHeaders.Add("X-API-Key", opts.ApiKey);

            client.DefaultRequestHeaders.ExpectContinue = true;

            var batchSize = opts.BatchSize <= 0 ? int.MaxValue : opts.BatchSize;
            var batch = new List<string>(Math.Min(batchSize, 8192));
            long sentBytes = 0;
            int batchIndex = 0;

            foreach (var path in files)
            {
                if (!TryMakeSafeRelative(rootCanonical, path, out _, out var why))
                {
                    if (opts.Verbose) Console.WriteLine($"   ! Skipping {path} (reason: {why})");
                    continue;
                }

                batch.Add(path);
                if (batch.Count >= batchSize)
                {
                    batchIndex++;
                    UploadBatch(batch, batchIndex, url, opts, client, rootCanonical, ref sentBytes);
                    batch.Clear();
                }
            }
            if (batch.Count > 0)
            {
                batchIndex++;
                UploadBatch(batch, batchIndex, url, opts, client, rootCanonical, ref sentBytes);
            }

            Console.WriteLine("✔ Done.");
            return 0;
        }
        catch (Options.BadOptions ex)
        {
            Console.Error.WriteLine("❌ " + ex.Message);
            Console.WriteLine();
            Console.WriteLine(Options.HelpText);
            return 2;
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine("❌ HTTP error: " + ex.Message);
            return 3;
        }
        catch (TaskCanceledException)
        {
            Console.Error.WriteLine("❌ Upload canceled or timed out.");
            return 4;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("❌ Unexpected error: " + ex);
            return 1;
        }
    }

    static void UploadBatch(
    List<string> batch,
    int batchIndex,
    string url,
    Options opts,
    HttpClient client,
    string rootCanonical,
    ref long sentBytes)
    {
        Console.WriteLine($"→ Preparing batch {batchIndex:n0} with {batch.Count:n0} files…");

        using var multipart = new MultipartFormDataContent();

        foreach (var fullPath in batch)
        {
            // Compute a SAFE relative path and refuse traversal
            if (!TryMakeSafeRelative(rootCanonical, fullPath, out var rel, out var why))
            {
                Console.WriteLine($"   ! Skipping {fullPath} (reason: {why})");
                continue;
            }

            // Stream the file
            var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                                    bufferSize: 1024 * 128,
                                    options: FileOptions.Asynchronous | FileOptions.SequentialScan);

            var streamContent = new StreamContent(fs);
            streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

            // ✅ Let MultipartFormDataContent set a single, correct Content-Disposition header
            //    (this avoids the “invalid Content-Disposition … filename, filename*” error)
            multipart.Add(streamContent, "files[]", rel);

            if (opts.Verbose)
                Console.WriteLine($"   + {rel}");
        }

        Console.WriteLine($"→ Uploading batch {batchIndex:n0} …");
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = multipart };
        using var resp = client.Send(req, HttpCompletionOption.ResponseHeadersRead);

        if (!resp.IsSuccessStatusCode)
        {
            string body = SafeReadString(resp);
            throw new HttpRequestException($"Server responded {((int)resp.StatusCode)} {resp.ReasonPhrase}. Body: {Truncate(body, 800)}");
        }

        long batchBytes = 0;
        foreach (var p in batch)
        {
            try { batchBytes += new FileInfo(p).Length; } catch { }
        }
        sentBytes += batchBytes;
        Console.WriteLine($"✔ Batch {batchIndex:n0} OK (approx sent: {FormatBytes(batchBytes)}; total: {FormatBytes(sentBytes)})");
    }



    // ---------------------- Safety & encoding helpers -------------------------

    // Canonical absolute dir path, normalized and ending with a directory separator
    static string ToCanonicalDir(string path)
    {
        var full = Path.GetFullPath(path);
        full = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return full + Path.DirectorySeparatorChar;
    }

    // Safer, stricter relative-path maker.
    //  - Ensures file is under rootCanonical
    //  - Normalizes separators
    //  - Rejects traversal segments ".", ".."
    //  - Also rejects *after percent-decoding* (e.g., "%2e%2e")
    //  - Rejects control chars and colon ":" in any segment (good hygiene)
    static bool TryMakeSafeRelative(string rootCanonical, string fullFilePath, out string safeRel, out string reason)
    {
        safeRel = "";
        reason = "";

        string full;
        try
        {
            full = Path.GetFullPath(fullFilePath);
        }
        catch (Exception ex)
        {
            reason = "bad-fullpath:" + ex.GetType().Name;
            return false;
        }

        if (!full.StartsWith(rootCanonical, StringComparison.OrdinalIgnoreCase))
        {
            reason = "outside-root";
            return false;
        }

        var rel = full.Substring(rootCanonical.Length);

        // Normalize to forward slashes & collapse multiple '/' to single
        rel = rel.Replace('\\', '/');
        while (rel.Contains("//", StringComparison.Ordinal)) rel = rel.Replace("//", "/");

        // Split + sanitize each segment
        var parts = rel.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            reason = "empty-rel";
            return false;
        }

        var clean = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            if (!IsSegmentSafe(part, out reason))
                return false;
            clean.Add(part);
        }

        // Rejoin
        safeRel = string.Join('/', clean);
        if (string.IsNullOrWhiteSpace(safeRel))
        {
            reason = "empty-rel2";
            return false;
        }
        return true;
    }

    // per-segment safety checks
    static bool IsSegmentSafe(string segment, out string reason)
    {
        reason = "";

        if (string.IsNullOrWhiteSpace(segment))
        {
            reason = "blank-segment";
            return false;
        }

        // Decode percent-encoding to catch sneaky %2e%2e, %2F, etc.
        string decoded = PercentDecodeLoose(segment);

        // Normalize dots
        if (segment == "." || segment == ".." || decoded == "." || decoded == "..")
        {
            reason = "dot-or-dotdot";
            return false;
        }

        // Control chars or colon are suspicious for file names in virtual FS
        foreach (char c in decoded)
        {
            if (char.IsControl(c) || c == ':' || c == '\\')
            {
                reason = $"bad-char:{(int)c:x2}";
                return false;
            }
        }

        // No leading/trailing spaces that could confuse downstream normalization
        if (decoded != decoded.Trim())
        {
            reason = "space-edge";
            return false;
        }

        // Prevent Unicode confusables for dots (e.g., U+2024 ONE DOT LEADER) from forming ".."
        // Collapse full-width & compatibility forms for a very basic guard:
        var nf = decoded.Normalize(NormalizationForm.FormKC);
        if (nf == "." || nf == "..")
        {
            reason = "unicode-dotdot";
            return false;
        }

        return true;
    }

    // Percent-decode but never throw; if malformed, return the original.
    static string PercentDecodeLoose(string s)
    {
        try
        {
            // Use System.Web for robust decoding; if unavailable, fall back
            return HttpUtility.UrlDecode(s) ?? s;
        }
        catch { return s; }
    }

    // RFC 5987 filename*:  filename*=UTF-8''<pct-encoded>
    static string Encode5987(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var sb = new StringBuilder(bytes.Length * 3);
        foreach (var b in bytes)
        {
            // attr-char set (RFC 5987) — keep alnum and a few safe marks; encode others
            if ((b >= 0x30 && b <= 0x39) || // 0-9
                (b >= 0x41 && b <= 0x5A) || // A-Z
                (b >= 0x61 && b <= 0x7A) || // a-z
                b == 0x2D || b == 0x2E || b == 0x5F || b == 0x7E) // - . _ ~
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('%').Append(b.ToString("X2"));
            }
        }
        return "UTF-8''" + sb.ToString();
    }

    // -------------------------------------------------------------------------

    static string SafeReadString(HttpResponseMessage resp)
    {
        try { return resp.Content.ReadAsStringAsync().GetAwaiter().GetResult(); }
        catch { return ""; }
    }

    static string QuoteForHeader(string s)
    {
        var q = s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        return $"\"{q}\"";
    }

    static string Truncate(string s, int max)
        => string.IsNullOrEmpty(s) || s.Length <= max ? s : s.Substring(0, max) + "…";

    static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double val = bytes;
        int i = 0;
        while (val >= 1024 && i < units.Length - 1) { val /= 1024; i++; }
        return $"{val:0.##} {units[i]}";
    }

    sealed class Options
    {
        public string ApiKey { get; init; } = "";
        public string Domain { get; init; } = "";
        public string UserIp { get; init; } = "";
        public string Root { get; init; } = "";
        public bool Insecure { get; init; }
        public bool Verbose { get; init; }
        public int BatchSize { get; init; } = 0;
        public int TimeoutSeconds { get; init; } = 60 * 60 * 168;
        public bool ShowHelp { get; init; }

        public static string HelpText =>
            """
            truthgate-publish — stream big multipart uploads, curl-style, cross-platform

            REQUIRED:
              --apiKey <str>        API key value for X-API-Key header
              --domain <str>        Domain segment used in the path (e.g., mysite.com)
              --userIp <str>        Host/IP of the target (e.g., 1.2.3.4)
              --root <path>         Root folder to scan recursively

            OPTIONAL:
              --insecure            Skip TLS certificate validation (like curl -k)
              --batchSize <int>     Files per request (default 0). Use 0 for one giant request.
              --timeoutSeconds <n>  Whole-request timeout (default 604,800)
              --verbose             Print each file's relative name
              -h | --help           Show this help

            NOTES:
              • Files with traversal-like names (incl. percent-encoded ..) are skipped for safety.
              • Use --verbose to see which files were skipped and why.

            EXAMPLE:
              truthgate-publish --apiKey "KEY" --domain "example.com" --userIp "10.0.0.5" --root "/var/www/site" --insecure --batchSize 0
            """;

        public static Options Parse(string[] args)
        {
            if (args.Length == 0) return new Options { ShowHelp = true };

            string? apiKey = null, domain = null, userIp = null, root = null;
            bool insecure = false, verbose = false, showHelp = false;
            int batchSize = 0, timeout = 604800;

            for (int i = 0; i < args.Length; i++)
            {
                var a = args[i];
                switch (a)
                {
                    case "-h":
                    case "--help": showHelp = true; break;

                    case "--apiKey": apiKey = Next(args, ref i, a); break;
                    case "--domain": domain = Next(args, ref i, a); break;
                    case "--userIp": userIp = Next(args, ref i, a); break;
                    case "--root": root = Next(args, ref i, a); break;

                    case "--insecure": insecure = true; break;
                    case "--verbose": verbose = true; break;

                    case "--batchSize":
                        batchSize = int.Parse(Next(args, ref i, a));
                        break;

                    case "--timeoutSeconds":
                        timeout = int.Parse(Next(args, ref i, a));
                        break;

                    default:
                        throw new BadOptions($"Unknown argument: {a}");
                }
            }

            return new Options
            {
                ApiKey = apiKey ?? "",
                Domain = domain ?? "",
                UserIp = userIp ?? "",
                Root = root ?? "",
                Insecure = insecure,
                Verbose = verbose,
                BatchSize = batchSize,
                TimeoutSeconds = timeout,
                ShowHelp = showHelp
            };

            static string Next(string[] args, ref int i, string flag)
            {
                if (i + 1 >= args.Length) throw new BadOptions($"Missing value for {flag}");
                return args[++i];
            }
        }

        public void ValidateOrThrow()
        {
            if (string.IsNullOrWhiteSpace(ApiKey)) throw new BadOptions("Missing --apiKey.");
            if (string.IsNullOrWhiteSpace(Domain)) throw new BadOptions("Missing --domain.");
            if (string.IsNullOrWhiteSpace(UserIp)) throw new BadOptions("Missing --userIp.");
            if (string.IsNullOrWhiteSpace(Root)) throw new BadOptions("Missing --root.");
            if (!Directory.Exists(Root)) throw new BadOptions($"Root does not exist: {Root}");
            if (BatchSize < 0) throw new BadOptions("--batchSize must be >= 0");
            if (TimeoutSeconds <= 0) throw new BadOptions("--timeoutSeconds must be > 0");
        }

        public sealed class BadOptions(string message) : Exception(message);
    }

    static bool IsIpv4Literal(string host)
    => System.Net.IPAddress.TryParse(host, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

    static string ExtractHost(string httpsUrl)
    {
        var u = new Uri(httpsUrl);
        return u.Host;
    }

}
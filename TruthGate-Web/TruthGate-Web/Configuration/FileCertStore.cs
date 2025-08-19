using System.Security.Cryptography.X509Certificates;

namespace TruthGate_Web.Configuration
{
    public interface ICertificateStore
    {
        Task<X509Certificate2?> LoadAsync(string host, CancellationToken ct);
        Task SaveAsync(string host, X509Certificate2 cert, CancellationToken ct);
    }

    public sealed class FileCertStore : ICertificateStore
    {
        private readonly string _dir;
        private readonly bool _staging;

        public FileCertStore(string dir, bool staging = false)
        {
            _dir = dir;
            _staging = staging;
        }

        private static string SafeFileNameForKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) key = "unknown";
            // Normalize host-ish things. If someone ever passes "*.example.com", make it readable.
            var safe = key.Trim()
                          .Replace("*.", "_wildcard_.")
                          .Replace(":", "_")
                          .Replace("/", "_")
                          .Replace("\\", "_");

            foreach (var c in Path.GetInvalidFileNameChars())
                safe = safe.Replace(c, '_');

            return safe.ToLowerInvariant();
        }

        private string PathFor(string hostOrKey)
        {
            var safe = SafeFileNameForKey(hostOrKey);
            return Path.Combine(_dir, $"{safe}{(_staging ? ".staging" : "")}.pfx");
        }

        public async Task<X509Certificate2?> LoadAsync(string host, CancellationToken ct)
        {
            Directory.CreateDirectory(_dir);

            var path = PathFor(host);
            if (!File.Exists(path))
            {
                if (_staging)
                {
                    return null; // no prod fallback in staging
                }
                else
                {
                    // legacy prod fallback (unsuffixed)
                    var legacy = Path.Combine(_dir, $"{SafeFileNameForKey(host)}.pfx");
                    if (!File.Exists(legacy)) return null;
                    path = legacy;
                }
            }

            var bytes = await File.ReadAllBytesAsync(path, ct);
            return X509CertificateLoader.LoadPkcs12(bytes, ReadOnlySpan<char>.Empty);
        }

        public async Task SaveAsync(string host, X509Certificate2 cert, CancellationToken ct)
        {
            Directory.CreateDirectory(_dir);
            var path = PathFor(host);
            var bytes = cert.Export(X509ContentType.Pkcs12);
            await File.WriteAllBytesAsync(path, bytes, ct);
        }
    }
}

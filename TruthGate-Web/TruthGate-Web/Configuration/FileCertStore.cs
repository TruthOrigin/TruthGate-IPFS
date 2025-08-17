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

        // Pass staging flag from Program.cs (see below)
        public FileCertStore(string dir, bool staging = false)
        {
            _dir = dir;
            _staging = staging;
        }

        private string PathFor(string host)
            => Path.Combine(_dir, $"{host}{(_staging ? ".staging" : "")}.pfx");

        public async Task<X509Certificate2?> LoadAsync(string host, CancellationToken ct)
        {
            Directory.CreateDirectory(_dir);

            // Prefer the suffix path if staging; prefer unsuffixed if prod.
            var path = PathFor(host);

            if (!File.Exists(path))
            {
                if (_staging)
                {
                    // In staging, DO NOT fall back to prod file.
                    return null;
                }
                else
                {
                    // In prod, we also accept the legacy unsuffixed file (back-compat).
                    var legacy = Path.Combine(_dir, $"{host}.pfx");
                    if (!File.Exists(legacy)) return null;
                    path = legacy;
                }
            }

            var bytes = await File.ReadAllBytesAsync(path, ct);

            // Use the modern loader (avoids obsolete constructor/import warnings)
            return X509CertificateLoader.LoadPkcs12(bytes, ReadOnlySpan<char>.Empty);
        }

        public async Task SaveAsync(string host, X509Certificate2 cert, CancellationToken ct)
        {
            Directory.CreateDirectory(_dir);
            var path = PathFor(host);

            // Write a PKCS#12 (PFX). Empty password is fine for your server-side store.
            var bytes = cert.Export(X509ContentType.Pkcs12);
            await File.WriteAllBytesAsync(path, bytes, ct);
        }
    }


}

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
        public FileCertStore(string dir) => _dir = dir;

        public async Task<X509Certificate2?> LoadAsync(string host, CancellationToken ct)
        {
            Directory.CreateDirectory(_dir);
            var pfx = Path.Combine(_dir, $"{host}.pfx");
            if (!File.Exists(pfx)) return null;
            var bytes = await File.ReadAllBytesAsync(pfx, ct);
            return new X509Certificate2(bytes);
        }

        public async Task SaveAsync(string host, X509Certificate2 cert, CancellationToken ct)
        {
            Directory.CreateDirectory(_dir);
            var pfx = Path.Combine(_dir, $"{host}.pfx");
            await File.WriteAllBytesAsync(pfx, cert.Export(X509ContentType.Pkcs12), ct);
        }
    }

}

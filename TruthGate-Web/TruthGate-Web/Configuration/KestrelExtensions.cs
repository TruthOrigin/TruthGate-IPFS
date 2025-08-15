using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TruthGate_Web.Models;

namespace TruthGate_Web.Configuration
{
    public static class KestrelExtensions
    {
        public static X509Certificate2 CreateSelfSignedServerCert(
    IEnumerable<string>? dnsNames = null,
    IEnumerable<IPAddress>? ipAddresses = null,
    TimeSpan? lifetime = null)
        {
            using var rsa = RSA.Create(2048);

            // Reasonable CN (doesn't affect matching if SAN present)
            var primaryName = dnsNames?.FirstOrDefault() ?? ipAddresses?.FirstOrDefault()?.ToString() ?? "localhost";
            var req = new CertificateRequest($"CN={primaryName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // SAN: include all provided DNS + IPs
            var san = new SubjectAlternativeNameBuilder();
            if (dnsNames != null)
                foreach (var d in dnsNames.Where(s => !string.IsNullOrWhiteSpace(s)))
                    san.AddDnsName(d);

            if (ipAddresses != null)
                foreach (var ip in ipAddresses)
                    san.AddIpAddress(ip);

            req.CertificateExtensions.Add(san.Build());

            // Basic constraints / usages
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

            var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }; // Server Auth
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));

            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            var notAfter = notBefore + (lifetime ?? TimeSpan.FromDays(365));
            using var tmp = req.CreateSelfSigned(notBefore, notAfter);

            // Export without password (NET 9: SecureString?; loader uses ReadOnlySpan<char>)
            var pfxBytes = tmp.Export(X509ContentType.Pkcs12, (SecureString?)null);
            return X509CertificateLoader.LoadPkcs12(pfxBytes, ReadOnlySpan<char>.Empty);
        }


        public static void UseConfiguredKestrel(this IWebHostBuilder webHost, IConfiguration config, IWebHostEnvironment env)
        {
            if (env.IsDevelopment()) return;

            var ports = config.GetSection("Ports").Get<PortOptions>() ?? new PortOptions();
            var cert = config.GetSection("Certificate").Get<CertificateOptions>() ?? new CertificateOptions();

            webHost.ConfigureKestrel(options =>
            {
                options.ListenAnyIP(ports.Http);

                if (!string.IsNullOrWhiteSpace(cert.Path) && File.Exists(cert.Path))
                {
                    options.ListenAnyIP(ports.Https, lo => lo.UseHttps(cert.Path, cert.Password));
                }
                else
                {
                    Console.WriteLine($"[WARN] HTTPS certificate not found at '{cert.Path}'. HTTPS not started.");
                }
            });
        }
    }
}

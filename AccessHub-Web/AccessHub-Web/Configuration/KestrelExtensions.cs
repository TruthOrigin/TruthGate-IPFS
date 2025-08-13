using TruthGate_Web.Models;

namespace TruthGate_Web.Configuration
{
    public static class KestrelExtensions
    {
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

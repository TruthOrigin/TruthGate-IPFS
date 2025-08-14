using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.ResponseCompression;
using System.IO.Compression;
using TruthGate_Web.Models;

namespace TruthGate_Web.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddTruthGateCore(
            this IServiceCollection services,
            IConfiguration config)
        {
            services.AddHttpClient();
            services.AddMemoryCache();

            // Auth & Authorization
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o =>
                {
                    o.LoginPath = "/login";
                    o.AccessDeniedPath = "/login";
                    o.SlidingExpiration = true;
                    o.ExpireTimeSpan = TimeSpan.FromHours(8);

                    o.Cookie.Path = "/";                     // send to /ipfs/*
                    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    o.Cookie.SameSite = SameSiteMode.None;    // or None (requires HTTPS) if you ever cross-origin
                    o.Cookie.HttpOnly = true;
                    // o.Cookie.Domain = "yourdomain.com";   // only if you truly need it
                });


            services.AddAuthorization();
            services.AddCascadingAuthenticationState();

            // Options
            services.Configure<SecurityOptions>(config);
            services.Configure<PortOptions>(config.GetSection("Ports"));
            services.Configure<DomainListOptions>(config);
            //services.Configure<CertificateOptions>(config.GetSection("Certificate"));

            // Compression
            services.AddResponseCompression(options =>
            {
                options.EnableForHttps = true;
                options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(new[]
                {
                "text/css",
                "application/javascript",
                "application/wasm",
                "application/msgpack",
                "font/woff2",
                "image/svg+xml"
            });
            });

            services.Configure<BrotliCompressionProviderOptions>(o => o.Level = CompressionLevel.SmallestSize);
            services.Configure<GzipCompressionProviderOptions>(o => o.Level = CompressionLevel.SmallestSize);

            return services;
        }
    }
}
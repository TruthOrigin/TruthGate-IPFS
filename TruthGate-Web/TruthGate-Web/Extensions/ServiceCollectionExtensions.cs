using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.ResponseCompression;
using System.IO.Compression;
using TruthGate_Web.Models;
using TruthGate_Web.Services;

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
                });


            services.AddAuthorization();
            services.AddCascadingAuthenticationState();

            // Options
            services.Configure<PortOptions>(config.GetSection("Ports"));
            //services.Configure<DomainListOptions>(config);
            //services.Configure<CertificateOptions>(config.GetSection("Certificate"));

            // Compression

            services.AddResponseCompression(options =>
            {
                options.EnableForHttps = true;

                // Add providers explicitly
                options.Providers.Add<BrotliCompressionProvider>();
                options.Providers.Add<GzipCompressionProvider>();

                // Be explicit about compressible text/binary types
                options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(new[]
                {
                    "text/plain",
                    "text/css",
                    "text/html",
                    "text/xml",
                    "application/xml",
                    "application/json",
                    "application/ld+json",
                    "application/x-ndjson",
                    "application/javascript",
                    "application/x-javascript",
                    "image/svg+xml",
                    "application/wasm",
                });
            });

            services.Configure<BrotliCompressionProviderOptions>(o => o.Level = CompressionLevel.Fastest);
            services.Configure<GzipCompressionProviderOptions>(o => o.Level = CompressionLevel.Fastest);

            return services;
        }
    }
}
using Microsoft.AspNetCore.Authentication.Cookies;
using TruthGate_Web.Components;
using TruthGate_Web.Extensions;
using TruthGate_Web.Configuration;
using TruthGate_Web.Middleware;
using TruthGate_Web.Endpoints;
using Microsoft.AspNetCore.HttpOverrides;
using System.Runtime.ConstrainedExecution;
using System.Net;
using TruthGate_Web.Utils;
using MudBlazor.Services;
using Blazored.LocalStorage;
using TruthGate_Web.Services;
using Microsoft.AspNetCore.Components;
using Certes.Pkcs;
using FluffySpoon.AspNet.EncryptWeMust.Certes;
using FluffySpoon.AspNet.EncryptWeMust;
using Microsoft.AspNetCore.Server.Kestrel.Https;
var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddTruthGateCore(builder.Configuration);

// Blazor
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddScoped(sp =>
{
    var nav = sp.GetRequiredService<NavigationManager>();
    return new HttpClient { BaseAddress = new Uri(nav.BaseUri) };
});


builder.Services.AddServerSideBlazor()
    .AddCircuitOptions(o => o.DetailedErrors = true);
// Program.cs / Startup
builder.Services.AddSingleton<IConfigService, ConfigService>();
builder.Services.AddHostedService(sp => (ConfigService)sp.GetRequiredService<IConfigService>());

builder.Services.AddMudServices();
builder.Services.AddBlazoredLocalStorage();


if (!builder.Environment.IsDevelopment())
{
    // --- 0) Resolve cert storage dir from env (TRUTHGATE_CERT_PATH)
    var certDir = Environment.GetEnvironmentVariable("TRUTHGATE_CERT_PATH");
    if (string.IsNullOrWhiteSpace(certDir))
        certDir = "/opt/truthgate/certs";
    certDir = Path.GetFullPath(certDir);
    Directory.CreateDirectory(certDir);

    // --- 1) Build your self-signed fallback (IP/unknown hosts)
    IReadOnlyList<IPAddress> discoveredIps = Array.Empty<IPAddress>();
    var ipOverride = Environment.GetEnvironmentVariable("TRUTHGATE_CERT_IPS");
    if (!string.IsNullOrWhiteSpace(ipOverride))
    {
        var parsed = ipOverride.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                               .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
                               .Where(ip => ip is not null)!
                               .Cast<IPAddress>()
                               .Distinct()
                               .ToList();
        discoveredIps = parsed;
    }

    var dnsOverride = Environment.GetEnvironmentVariable("TRUTHGATE_CERT_DNS");
    var dnsNames = string.IsNullOrWhiteSpace(dnsOverride)
        ? Array.Empty<string>()
        : dnsOverride.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    var selfSignedCert = KestrelExtensions.CreateSelfSignedServerCert(
        dnsNames: dnsNames,
        ipAddresses: discoveredIps);

    // --- 2) Services
    builder.Services.AddSingleton<IConfigService, ConfigService>();

    builder.Services.AddSingleton<SelfSignedCertCache>(_ => new SelfSignedCertCache(selfSignedCert));
    builder.Services.AddSingleton<ICertificateStore>(_ => new FileCertStore(certDir));

    builder.Services.AddSingleton<IAcmeChallengeStore, MemoryChallengeStore>();
    builder.Services.AddSingleton<IAcmeIssuer>(sp =>
        new CertesAcmeIssuer(
            sp.GetRequiredService<IAcmeChallengeStore>(),
            useStaging: builder.Environment.IsDevelopment(),
            accountPemPath: Path.Combine(certDir, "account.pem")));

    builder.Services.AddSingleton<LiveCertProvider>();
    builder.Services.AddHostedService<ConfigWatchAndIssueService>();

    // --- 3) Kestrel endpoints
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ListenAnyIP(80);    // For HTTP-01 (Let’s Encrypt)
        options.ListenAnyIP(8080);  // Optional plain HTTP

        // TLS 443 with per-SNI selection (sync)
        options.ListenAnyIP(443, listenOpts =>
        {
            var sp = options.ApplicationServices;
            var live = sp.GetRequiredService<LiveCertProvider>();

            listenOpts.UseHttps(new HttpsConnectionAdapterOptions
            {
                ServerCertificateSelector = (connectionContext, sni) =>
                {
                    // 1) IP/No SNI -> self-signed fallback
                    if (string.IsNullOrWhiteSpace(sni) || IPAddress.TryParse(sni, out _))
                        return live.GetSelfSigned();

                    // 2) Decide based on config
                    var decision = live.DecideForHost(sni);
                    switch (decision.Kind)
                    {
                        case SslDecisionKind.SelfSigned:
                            return live.GetSelfSigned();

                        case SslDecisionKind.NoneFailTls:    // UseSSL=false => no cert => handshake fails
                            return null;

                        case SslDecisionKind.RealIfPresent:  // UseSSL=true => use real cert if we already have it
                            return live.TryLoadIssued(sni);
                    }

                    return null;
                }
            });
        });
    });

}

var app = builder.Build();

app.Logger.LogInformation("ContentRoot: {cr}", app.Environment.ContentRootPath);
app.Logger.LogInformation("WebRoot:     {wr}", app.Environment.WebRootPath);
app.Logger.LogInformation("BaseDir:     {bd}", AppContext.BaseDirectory);

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                       ForwardedHeaders.XForwardedProto |
                       ForwardedHeaders.XForwardedHost
});

// Pipeline
app.UseStandardErrorPipeline();

// Auth
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

if (!builder.Environment.IsDevelopment())
{
    app.UseFluffySpoonLetsEncrypt();

    app.MapGet("/.well-known/acme-challenge/{token}",
        (string token, IAcmeChallengeStore store)
            => Results.Text(store.TryGetContent(token) ?? "", "text/plain"));
}

// Domain to IPFS gateway (host-mapped, SPA fallback logic, etc.)
app.UseDomainGateway();

// Force auth for non-mapped domains (your guard)
app.UseNonMappedDomainAuthGuard();


// Static + components
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(TruthGate_Web.Client._Imports).Assembly);

// Endpoints
app.MapTruthGateAuthEndpoints();
app.MapTruthGateIpfsEndpoints();
app.MapTruthGateApiProxyEndpoints();

app.Run();

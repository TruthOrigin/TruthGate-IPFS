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
    // === env & dirs ===
    var certDir = Environment.GetEnvironmentVariable("TRUTHGATE_CERT_PATH");
    if (string.IsNullOrWhiteSpace(certDir))
        certDir = "/opt/truthgate/certs";
    certDir = Path.GetFullPath(certDir);
    Directory.CreateDirectory(certDir);

    // --- 1) Build your self-signed fallback (IP/unknown hosts)
    IReadOnlyList<IPAddress> discoveredIps;
    var ipOverride = Environment.GetEnvironmentVariable("TRUTHGATE_CERT_IPS");

    if (!string.IsNullOrWhiteSpace(ipOverride))
    {
        discoveredIps = ipOverride
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
            .Where(ip => ip is not null)!
            .Cast<IPAddress>()
            .Distinct()
            .ToList();
    }
    else
    {
        // Fallback: auto-discover public interface IPs (your helper)
        discoveredIps = IPHelper.GetPublicInterfaceIPs()
            .Distinct()
            .ToList();
    }

    var selfSignedCert = KestrelExtensions.CreateSelfSignedServerCert(
        dnsNames: Array.Empty<string>(),
        ipAddresses: discoveredIps);

    // === DI: NO FLUFFYSPOON HERE ===
    builder.Services.AddSingleton<IConfigService, ConfigService>();
    builder.Services.AddSingleton(new SelfSignedCertCache(selfSignedCert));
    builder.Services.AddSingleton<ICertificateStore>(sp => new FileCertStore(certDir));
    builder.Services.AddSingleton<IAcmeChallengeStore, MemoryChallengeStore>();

    var acmeStaging =
        builder.Environment.IsDevelopment() ||
        string.Equals(Environment.GetEnvironmentVariable("TRUTHGATE_ACME_STAGING"), "true", StringComparison.OrdinalIgnoreCase);


    var accountPem = Path.Combine(certDir, acmeStaging ? "account.staging.pem" : "account.prod.pem");

    builder.Services.AddSingleton<IAcmeIssuer>(sp =>
        new CertesAcmeIssuer(
            sp.GetRequiredService<IAcmeChallengeStore>(),
            sp.GetRequiredService<ILogger<CertesAcmeIssuer>>(),
            useStaging: acmeStaging,
            accountPemPath: accountPem));


    builder.Services.AddSingleton<LiveCertProvider>();



    builder.Services.AddHostedService<ConfigWatchAndIssueService>();

    // === Kestrel ===
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ListenAnyIP(80);   // ACME HTTP-01
        options.ListenAnyIP(8080); // optional HTTP

        options.ListenAnyIP(443, lo =>
        {
            lo.UseHttps(new HttpsConnectionAdapterOptions
            {
                ServerCertificateSelector = (ctx, sniRaw) =>
                {
                    var live = lo.ApplicationServices.GetRequiredService<LiveCertProvider>();
                    var fallback = live.GetSelfSigned();
                    var sni = sniRaw?.Trim();

                    if (string.IsNullOrWhiteSpace(sni) || IPAddress.TryParse(sni, out _))
                        return fallback;

                    var decision = live.DecideForHost(sni);
                    switch (decision.Kind)
                    {
                        case SslDecisionKind.SelfSigned:
                            return fallback;

                        case SslDecisionKind.NoneFailTls:
                            return null;

                        case SslDecisionKind.RealIfPresent:
                            {
                                var issued = live.TryLoadIssued(sni);
                                if (issued is not null) return issued;

                                // only queue if not already in-flight
                                if (!live.IsInFlight(sni))
                                    live.QueueIssueIfMissing(sni);

                                return fallback;
                            }

                        default:
                            return fallback;
                    }
                }

            });
        });


    });


    builder.Services.AddHostedService<EagerIssueAtStartup>();
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

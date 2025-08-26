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
using TruthGate_Web.Models;
using TruthGate_Web.Interfaces;
using Microsoft.AspNetCore.Http.Features;
using TruthGate_Web.Models.Metrics;
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

builder.Services.AddSingleton<ApiKeyService>();
builder.Services.AddSingleton<IApiKeyProvider>(sp => sp.GetRequiredService<ApiKeyService>());
// same instance is used as the hosted service
builder.Services.AddHostedService(sp => sp.GetRequiredService<ApiKeyService>());


builder.Services.AddServerSideBlazor()
    .AddCircuitOptions(o => o.DetailedErrors = true);
// Program.cs / Startup
builder.Services.AddSingleton<IConfigService, ConfigService>();
builder.Services.AddHostedService(sp => (ConfigService)sp.GetRequiredService<IConfigService>());

builder.Services.AddScoped<AdminApiKeyOnlyFilter>();

builder.Services.Configure<IpnsUpdateOptions>(o =>
{
    o.MaxConcurrency = 4;                          // tune as you like
    o.ScheduledPerKeyCooldown = TimeSpan.FromMinutes(10);
});

builder.Services.AddSingleton<IIpnsUpdateService, IpnsUpdateWorker>();
builder.Services.AddHostedService(sp => (IpnsUpdateWorker)sp.GetRequiredService<IIpnsUpdateService>());


builder.Services.AddSingleton<IPublishQueue, PublishQueue>();
builder.Services.AddHostedService(sp => (PublishQueue)sp.GetRequiredService<IPublishQueue>());

// Program.cs
builder.Services.Configure<MetricsOptions>(cfg =>
{
    cfg.SampleMs = 1000;
    cfg.WindowSeconds = 600;
    cfg.EnablePerThreadLinux = false; // flip true if you want Linux per-thread spikes
    cfg.MaxPerThread = 5;
});

builder.Services.AddSingleton<IMetricService, MetricService>();
builder.Services.AddHostedService(sp => (MetricService)sp.GetRequiredService<IMetricService>());


builder.Services.AddMudServices();
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddControllers();

builder.Services.AddScoped<ITruthGatePublishService, TruthGatePublishService>();

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

    var acmeStaging =
    builder.Environment.IsDevelopment() ||
    string.Equals(Environment.GetEnvironmentVariable("TRUTHGATE_ACME_STAGING"), "true", StringComparison.OrdinalIgnoreCase);


    builder.Services.AddSingleton<ICertificateStore>(sp => new FileCertStore(certDir, acmeStaging));

    builder.Services.AddSingleton<IAcmeChallengeStore, MemoryChallengeStore>();



    var accountPem = Path.Combine(certDir, acmeStaging ? "account.staging.pem" : "account.prod.pem");

    builder.Services.AddSingleton<IAcmeIssuer>(sp =>
        new CertesAcmeIssuer(
            sp.GetRequiredService<IAcmeChallengeStore>(),
            sp.GetRequiredService<ILogger<CertesAcmeIssuer>>(),
            useStaging: acmeStaging,
            accountPemPath: accountPem));


    builder.Services.AddSingleton<LiveCertProvider>(sp =>
    new LiveCertProvider(
        sp.GetRequiredService<SelfSignedCertCache>(),
        sp.GetRequiredService<ICertificateStore>(),
        sp.GetRequiredService<IAcmeIssuer>(),
        sp.GetRequiredService<IConfigService>(),
        sp.GetRequiredService<ILogger<LiveCertProvider>>()));


    builder.Services.Configure<FormOptions>(o =>
    {
        // Allow *many* files/fields
        o.ValueCountLimit = int.MaxValue;               // number of keys/fields in a form
        o.MultipartBodyLengthLimit = long.MaxValue;     // total body size across all parts
        o.MultipartHeadersCountLimit = int.MaxValue;
        o.MultipartHeadersLengthLimit = int.MaxValue;
        o.MemoryBufferThreshold = int.MaxValue;         // push buffering threshold way up
        o.ValueLengthLimit = int.MaxValue;              // length of each individual form value
        o.KeyLengthLimit = int.MaxValue;                // length of each field name
    });

    builder.Services.AddHostedService<ConfigWatchAndIssueService>();

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("TruthGatePublic", policy =>
            policy
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader()
        );
    });

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
                    var sni = sniRaw?.Trim()?.ToLowerInvariant();

                    if (string.IsNullOrWhiteSpace(sni) || IPAddress.TryParse(sni, out _))
                        return fallback;

                    // --- normalize SNI ---
                    if (sni.EndsWith(".")) sni = sni[..^1]; // strip trailing dot
                    try
                    {
                        sni = new System.Globalization.IdnMapping().GetAscii(sni);
                    }
                    catch
                    {
                        // best-effort: leave as-is if normalization fails
                    }

                    var decision = live.DecideForHostIncludingStarish(sni);
                    switch (decision.Kind)
                    {
                        case SslDecisionKind.SelfSigned:
                        case SslDecisionKind.NoneFailTls:
                            return fallback;

                        case SslDecisionKind.RealIfPresent:
                            {
                                var issued = live.TryLoadIssued(sni); // exact host (star-ish)
                                if (issued is not null) return issued;

                                if (!live.IsInFlight(sni))
                                    live.TryQueueIssueIfMissing(sni);

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

app.UseCors(cors => cors
.AllowAnyMethod()
.AllowAnyHeader()
.SetIsOriginAllowed(origin => true)
.AllowCredentials()
.WithExposedHeaders("Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding")
);

app.UseCors("TruthGatePublic");

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


app.MapControllers().RequireCors("TruthGatePublic"); ;

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

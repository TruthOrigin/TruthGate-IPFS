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

#if DEBUG
#else

var baseDir = AppContext.BaseDirectory;                 // publish folder at runtime
var webRoot = Path.Combine(baseDir, "wwwroot");

var opts = new WebApplicationOptions
{
    ContentRootPath = baseDir,
    WebRootPath = Directory.Exists(webRoot) ? webRoot : null
};

// 1) Auto-discover public IPs on this machine
var discoveredIps = IPHelper.GetPublicInterfaceIPs().Distinct().ToList();

// 2) Optional overrides via env vars (comma-separated)
// e.g., TRUTHGATE_CERT_IPS="203.0.113.42,2001:db8::1234"
//       TRUTHGATE_CERT_DNS="example.com,www.example.com"
var ipOverride = Environment.GetEnvironmentVariable("TRUTHGATE_CERT_IPS");
if (!string.IsNullOrWhiteSpace(ipOverride))
{
    var parsed = ipOverride.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                           .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
                           .Where(ip => ip is not null)!
                           .Cast<IPAddress>();
    discoveredIps = parsed.Distinct().ToList();
}

var dnsOverride = Environment.GetEnvironmentVariable("TRUTHGATE_CERT_DNS");
var dnsNames = string.IsNullOrWhiteSpace(dnsOverride)
    ? Array.Empty<string>()
    : dnsOverride.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

// 3) Create an in-memory self-signed cert with all SANs we gathered
var cert = KestrelExtensions.CreateSelfSignedServerCert(
    dnsNames: dnsNames,
    ipAddresses: discoveredIps);

// 4) HTTPS-only Kestrel
builder.WebHost.ConfigureKestrel(k =>
{
    k.ListenAnyIP(443, o => o.UseHttps(cert)); // Only HTTPS
    // HTTP on 8080
    k.ListenAnyIP(8080); // no HTTPS here
});
#endif

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

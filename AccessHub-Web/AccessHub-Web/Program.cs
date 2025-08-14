using Microsoft.AspNetCore.Authentication.Cookies;
using TruthGate_Web.Components;
using TruthGate_Web.Extensions;
using TruthGate_Web.Configuration;
using TruthGate_Web.Middleware;
using TruthGate_Web.Endpoints;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddTruthGateCore(builder.Configuration);

// Blazor
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

// Kestrel (prod)
//builder.WebHost.UseConfiguredKestrel(builder.Configuration, builder.Environment);

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                       ForwardedHeaders.XForwardedProto |
                       ForwardedHeaders.XForwardedHost
});

// Pipeline
app.UseStandardErrorPipeline();

// Domain to IPFS gateway (host-mapped, SPA fallback logic, etc.)
app.UseDomainGateway();

// Auth
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

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

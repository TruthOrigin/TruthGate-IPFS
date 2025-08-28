using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using TruthGate_Web.Services;

namespace Test.TruthGate.Tests
{

    [Collection("TruthGateServerCollection")]
    public sealed class WhitelistUnbanTests : IAsyncLifetime
    {
        private readonly TruthGateWebApplicationFactory _f;
        private readonly TestClient _client;

        public WhitelistUnbanTests(SqliteTestFixture fx)
        {
            _f = new TruthGateWebApplicationFactory(fx);
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

        [Fact]
        public async Task ManualWhitelist_Bypasses_Then_Removal_Reenables_Limits()
        {
            var ip = "203.0.113.55";
            // Add whitelist via DI
            using var scope = _f.Services.CreateScope();
            var svc = scope.ServiceProvider.GetRequiredService<IRateLimiterService>();
            await svc.AddWhitelistIpAsync(ip, reason: "test");

            // Should be allowed even if we exceed limits
            var resps = await _client.BurstAsync("/public/ping", 8000, ip: ip);
            Assert.All(resps, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));

            // Remove whitelist and trigger 429 quickly
            await svc.RemoveWhitelistIpAsync(ip);
            for (int i = 0; i < 300; i++) Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync("/public/ping", ip: ip)).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync("/public/ping", ip: ip)).StatusCode);
        }

        [Fact]
        public async Task Unban_By_Ip_Clears_Forbidden()
        {
            var ip = "198.51.100.23";
            // Force a gateway ban
            for (int i = 0; i < 8000; i++) await _client.SendAsync("/ipfs/cat", ip: ip);
            var banned = await _client.SendAsync("/ipfs/cat", ip: ip);
            Assert.Equal(HttpStatusCode.Forbidden, banned.StatusCode);
            // Unban
            using var scope = _f.Services.CreateScope();
            var svc = scope.ServiceProvider.GetRequiredService<IRateLimiterService>();

            var isbanned = svc.IsBanned(ip);
                 Assert.Equal(true, isbanned);
            var unbanned = await svc.UnbanIpAsync(ip);

            isbanned = svc.IsBanned(ip);
            Assert.Equal(true, unbanned);

            var ok = await _client.SendAsync("/ipfs/cat", ip: ip);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        [Fact]
        public async Task Unban_By_Ipv6_Clears_Forbidden()
        {
            var ip = "2001:db8::1234"; // doc-range IPv6

            // Trip a gateway ban
            for (int i = 0; i < 8000; i++)
                await _client.SendAsync("/ipfs/cat", ip: ip);

            var banned = await _client.SendAsync("/ipfs/cat", ip: ip);
            Assert.Equal(HttpStatusCode.Forbidden, banned.StatusCode);

            using var scope = _f.Services.CreateScope();
            var svc = scope.ServiceProvider.GetRequiredService<IRateLimiterService>();

            var okUnban = await svc.UnbanIpAsync(ip, resetWindowMinutes: 60);
            Assert.True(okUnban);

            var ok = await _client.SendAsync("/ipfs/cat", ip: ip);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }


    }
}

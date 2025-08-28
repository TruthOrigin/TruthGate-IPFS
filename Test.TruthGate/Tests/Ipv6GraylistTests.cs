using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using TruthGate_Web.Security;
using TruthGate_Web.Services;

namespace Test.TruthGate.Tests
{

    [Collection("TruthGateServerCollection")]
    public sealed class Ipv6GraylistTests : IAsyncLifetime
    {
        private readonly TruthGateWebApplicationFactory _f;
        private readonly TestClient _client;

        public Ipv6GraylistTests(SqliteTestFixture fx)
        {
            _f = new TruthGateWebApplicationFactory(fx);
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

        [Fact(Skip = "Automatic /64 aggregation not present; test demonstrates manual prefix ban application")]
        public async Task ManualPrefixBan_Applies_To_All_In_Prefix()
        {
            // Example of how to add a prefix ban via reflection if you need to validate behavior now
            var ipv6a = "2001:db8:1:2::1"; var ipv6b = "2001:db8:1:2::2";
            using var scope = _f.Services.CreateScope();
            var rl = (RateLimiterService)scope.ServiceProvider.GetRequiredService<IRateLimiterService>();
            var dbf = (IDbContextFactory<RateLimiterDbContext>)typeof(RateLimiterService).GetProperty("DbFactory", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(rl)!;
            await using var db = await dbf.CreateDbContextAsync();
            var prefix = "2001:db8:1:2::/64";
            var addBan = typeof(RateLimiterService).GetMethod("AddBanAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
            await (Task)addBan.Invoke(rl, new object?[] { db, new Ban { IpV6Prefix = prefix, Scope = RateScope.Gateway, Type = BanType.True, IsTrueBan = true, ReasonCode = "TEST", CreatedUtc = DateTimeOffset.UtcNow, ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) }, false })!;
            // Requests from any IP in /64 should now be 403
            Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync("/ipfs/cat", ipv6: ipv6a)).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync("/ipfs/cat", ipv6: ipv6b)).StatusCode);
        }
    }
}

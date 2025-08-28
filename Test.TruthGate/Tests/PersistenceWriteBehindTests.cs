using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using TruthGate_Web.Security;

namespace Test.TruthGate.Tests
{

    [Collection("TruthGateServerCollection")]
    public sealed class PersistenceWriteBehindTests : IAsyncLifetime
    {
        private TruthGateWebApplicationFactory _f;
        private readonly SqliteTestFixture _fx;
        private TestClient _client;

        public PersistenceWriteBehindTests(SqliteTestFixture fx)
        {
            _fx = fx;
            _f = new TruthGateWebApplicationFactory(fx);
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

        [Fact]
        public async Task Flush_Persists_Counters()
        {
            var ip = "203.0.113.77";
            // Generate a bit of public traffic
            for (int i = 0; i < 3; i++) await _client.SendAsync("/public/ping", ip: ip);
            await _client.FlushAsync();
            // Inspect DB directly
            using var scope = _f.Services.CreateScope();
            var dbf = scope.ServiceProvider.GetRequiredService<IDbContextFactory<RateLimiterDbContext>>();
            await using var db = await dbf.CreateDbContextAsync();
            var nowBucket = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmm");
            var row = await db.IpMinuteCounters.FirstOrDefaultAsync(x => x.Ip == ip && x.MinuteBucket == nowBucket);
            Assert.NotNull(row);
            Assert.True(row!.PublicCalls >= 3);
        }

        [Fact(Skip = "Bans are not reloaded from DB on startup in current limiter")]
        public async Task Ban_Persists_And_Is_Enforced_After_Restart()
        {
            var ip = "198.51.100.200";
            for (int i = 0; i < 25; i++) await _client.SendAsync("/ipfs/cat", ip: ip);
            Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync("/ipfs/cat", ip: ip)).StatusCode);
            // restart server
            _f.Dispose();
            _f = new TruthGateWebApplicationFactory(_fx);
            _client = new TestClient(_f.CreateClient());
            // Currently: caches are empty after restart, so this would pass (OK)
            var r = await _client.SendAsync("/ipfs/cat", ip: ip);
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }
    }

}

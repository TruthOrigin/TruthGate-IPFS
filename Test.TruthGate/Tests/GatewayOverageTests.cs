using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Test.TruthGate.Tests
{

    [Collection("TruthGateServerCollection")]
    public sealed class GatewayOverageTests : IAsyncLifetime
    {
        private readonly TruthGateWebApplicationFactory _f;
        private readonly TestClient _client;

        public GatewayOverageTests(SqliteTestFixture fx)
        {
            _f = new TruthGateWebApplicationFactory(fx);
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

        [Fact]
        public async Task Overage_Consumption_Then_Ban_On_Exhaustion()
        {
            var ip = "172.16.0.5";

            for (int i = 0; i < 24; i++)
            {
                var ok = await _client.SendAsync("/ipfs/cat", ip: ip);
                Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
            }

            HttpResponseMessage? ban = null;
            for (int i = 0; i < 277; i++)
            {
                ban = await _client.SendAsync("/ipfs/cat", ip: ip);
            }
            Assert.Equal(HttpStatusCode.Forbidden, ban.StatusCode);
        }

        [Fact]
        public async Task ValidKey_AutoWhitelist_Bypasses_Gateway_Limits()
        {
            var ip = "172.16.0.8";
            // One call with valid key → auto-whitelist (on) and grace refresh
            var first = await _client.SendAsync("/ipfs/cat", ip: ip, apiKey: TruthGateWebApplicationFactory.ValidAdminKey);
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            // Now blast beyond limits; should continue OK due to whitelist
            var resps = await _client.BurstAsync("/ipfs/cat", 40, ip: ip);
            Assert.All(resps, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        }
    }
}

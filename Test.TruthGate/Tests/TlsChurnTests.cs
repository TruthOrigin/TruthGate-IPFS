using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Test.TruthGate.Tests
{

    [Collection("TruthGateServerCollection")]
    public sealed class TlsChurnTests : IAsyncLifetime
    {
        private readonly TruthGateWebApplicationFactory _f;
        private readonly TestClient _client;

        public TlsChurnTests(SqliteTestFixture fx)
        {
            _f = new TruthGateWebApplicationFactory(fx);
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

        [Fact]
        public async Task NewConn_Burst_Triggers_SoftBan()
        {
            var ip = "192.168.1.20";
            // 10 requests as new connections (threshold ~9 over 3s window)
            var resps = await _client.BurstAsync("/ipfs/cat", 2000, ip: ip, newConn: true);
            // Last may already be banned, but ensure next request is
            var next = await _client.SendAsync("/ipfs/cat", ip: ip);
            Assert.Equal(HttpStatusCode.Forbidden, next.StatusCode);
        }
    }
}

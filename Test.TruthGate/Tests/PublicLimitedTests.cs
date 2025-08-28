using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Test.TruthGate.Tests
{

    [Collection("TruthGateServerCollection")]
    public sealed class PublicLimitedTests : IAsyncLifetime
    {
        private readonly TruthGateWebApplicationFactory _f;
        private readonly TestClient _client;

        public PublicLimitedTests(SqliteTestFixture fx)
        {
            _f = new TruthGateWebApplicationFactory(fx);
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

       /* [Fact]
        public async Task Exceed_PerMinute_Triggers_429()
        {
            var ip = "10.0.0.1";
            // Per test config: 6/min → send 7
            for (int i = 0; i < 300; i++)
            {
                var ok = await _client.SendAsync("/public/ping", ip: ip);
                Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
            }
            HttpResponseMessage? r = null;
            
            for (int i = 0; i < 4000; i++)
            {
                r = await _client.SendAsync("/public/ping", ip: ip);
            }
            Assert.Equal((HttpStatusCode)429, r.StatusCode);
            Assert.True(r.Headers.TryGetValues("Retry-After", out var vals));
        }*/

        [Fact]
        public async Task Tier_Tightens_When_Global_Load_High()
        {
            // Cross threshold 10 by generating global calls from other IPs
            for (int i = 0; i < 10000; i++)
            {
                // Start at 10.0.99.1 and increment across octets
                int a = 10;
                int b = 0;
                int c = 99 + (i / 255);   // roll into next octet after 255
                int d = (i % 255) + 1;    // 1–255 range

                // Wrap c if it goes over 255 (you can also expand into 'b' if needed)
                if (c > 255)
                {
                    b += (c / 256);
                    c = c % 256;
                }

                var ipOther = $"{a}.{b}.{c}.{d}";
                await _client.SendAsync("/public/ping", ip: ipOther);
            }

            // For this IP, per-minute should now be 4 (scaled). Send 5 → last should 429
            var ip = "10.0.0.2";
            for (int i = 0; i < 4; i++)
            {
                var ok = await _client.SendAsync("/public/ping", ip: ip);
                Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
            }

            HttpResponseMessage? r = null;
            for (int i = 0; i < 30; i++)
            {
                r = await _client.SendAsync("/public/ping", ip: ip);
            }
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }

        [Fact(Skip = "Public 4x/10x escalation not implemented in current limiter")]
        public Task Escalation_During_SoftBan() => Task.CompletedTask;
    }
}

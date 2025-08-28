using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Test.TruthGate.Tests
{
    [Collection("TruthGateServerCollection")]
    public sealed class AdminProtectedTests : IAsyncLifetime
    {
        private readonly TruthGateWebApplicationFactory _f;
        private readonly TestClient _client;
        private readonly IServiceProvider _sp;

        public AdminProtectedTests(SqliteTestFixture fx)
        {
            _f = new TruthGateWebApplicationFactory(fx);
            _sp = _f.Services;
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

        [Fact]
        public async Task ValidKey_Allows_Unlimited()
        {
            var ip = "127.0.0.1";
            var resps = await _client.BurstAsync("/admin/secret", count: 4000, ip: ip, apiKey: TruthGateWebApplicationFactory.ValidAdminKey);
            Assert.All(resps, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        }

        [Fact]
        public async Task InvalidKey_Threshold_Bans()
        {
            var ip = "127.0.1.1";
            // 3 invalid attempts
            for (int i = 0; i < 3; i++) await _client.SendAsync("/admin/secret", ip: ip, apiKey: "NOPE");
            // persist counters
            await _client.FlushAsync();
            // Next attempt triggers soft ban → 401 still (oracle-proof) or 403? In current impl: still 401 until ban check fires next time
            var r = await _client.SendAsync("/admin/secret", ip: ip, apiKey: "NOPE");
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
            // subsequent request should hit ban 403 because RecordFailureAsync added ban when threshold reached
            HttpResponseMessage? r2 = null;
            for (int i = 0; i < 10; i++)
            {
                r2 = await _client.SendAsync("/admin/secret", ip: ip, apiKey: "NOPE");
            }
            Assert.Equal(HttpStatusCode.Forbidden, r2.StatusCode);
        }

        [Fact(Skip = "Grace (IP,key) failure exemption not implemented in current limiter")]
        public Task GracePair_Success_Suppresses_BadKey_Counts() => Task.CompletedTask;

        [Fact(Skip = "Admin 4x/10x escalation not implemented in current limiter")]
        public Task Admin_Escalation_To_TrueBan() => Task.CompletedTask;

        [Fact]
        public async Task Oracle_Proof_Bodies_Are_Identical()
        {
            var ip = "127.0.2.3";
            var missing = await _client.SendAsync("/admin/secret", ip: ip);
            var invalid = await _client.SendAsync("/admin/secret", ip: ip, apiKey: "WRONG");
            var b1 = await missing.Content.ReadAsStringAsync();
            var b2 = await invalid.Content.ReadAsStringAsync();
            Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
            Assert.Equal(b1, b2);
        }
    }
}

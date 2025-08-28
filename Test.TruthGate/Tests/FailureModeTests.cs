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
    public sealed class FailureModeTests : IAsyncLifetime
    {
        private readonly TruthGateWebApplicationFactory _f;
        private readonly TestClient _client;
        private readonly SqliteTestFixture _fx;   // <-- keep the fixture

        public FailureModeTests(SqliteTestFixture fx)
        {
            _fx = fx;                              // <-- store it
            _f = new TruthGateWebApplicationFactory(fx);
            _client = new TestClient(_f.CreateClient());
        }

        public Task InitializeAsync() => Task.CompletedTask;
        public Task DisposeAsync() { _f.Dispose(); return Task.CompletedTask; }

        [Fact]
        public async Task Counter_Flush_Exception_Fails_Open_For_Counters()
        {
            // Use the fixture (no DI lookup)
            var dbPath = Path.Combine(Path.GetDirectoryName(_fx.ConfigPath)!, "ratelimiter.db");

            var attrs = File.GetAttributes(dbPath);
            File.SetAttributes(dbPath, attrs | FileAttributes.ReadOnly);
            try
            {
                // Generate some traffic and flush
                var r1 = await _client.SendAsync("/public/ping", ip: "203.0.113.90");
                Assert.Equal(HttpStatusCode.OK, r1.StatusCode);

                // Flush (internal flush may log an error). Endpoint stays 200.
                await _client.FlushAsync();

                // Service should still serve (fail-open for counters)
                var r2 = await _client.SendAsync("/public/ping", ip: "203.0.113.90");
                Assert.Equal(HttpStatusCode.OK, r2.StatusCode);
            }
            finally
            {
                File.SetAttributes(dbPath, attrs);
            }
        }
    }

}

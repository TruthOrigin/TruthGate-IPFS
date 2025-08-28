using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Test.TruthGate
{
    public sealed class TestClient
    {
        private readonly HttpClient _http;

        public TestClient(HttpClient http) => _http = http;

        public Task<HttpResponseMessage> SendAsync(
            string path, string? ip = null, string? ipv6 = null, bool? authenticated = null,
            string? apiKey = null, bool newConn = false, HttpMethod? method = null)
        {
            var req = new HttpRequestMessage(method ?? HttpMethod.Get, path);
            if (!string.IsNullOrEmpty(ip)) req.Headers.Add("X-Test-IP", ip);
            if (!string.IsNullOrEmpty(ipv6)) req.Headers.Add("X-Test-IPv6", ipv6);
            if (authenticated == true) req.Headers.Add("X-Test-User-Authenticated", "1");
            if (!string.IsNullOrEmpty(apiKey)) req.Headers.Add("X-Admin-Key", apiKey);
            if (newConn) req.Headers.Add("X-Test-Conn-Close", "1");
            return _http.SendAsync(req);
        }

        public async Task<HttpResponseMessage[]> BurstAsync(
            string path, int count, string? ip = null, string? ipv6 = null, bool? authenticated = null,
            string? apiKey = null, bool newConn = false)
        {
            var list = new List<HttpResponseMessage>(count);
            for (int i = 0; i < count; i++) list.Add(await SendAsync(path, ip, ipv6, authenticated, apiKey, newConn));
            return list.ToArray();
        }

        public async Task FlushAsync()
        {
            var r = await _http.PostAsync("/_test/flush", content: null);
            r.EnsureSuccessStatusCode();
        }
    }
}

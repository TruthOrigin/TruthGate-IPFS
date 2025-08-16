using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace TruthGate_Web.Configuration
{
    public interface IAcmeIssuer
    {
        Task<X509Certificate2?> IssueOrRenewAsync(string host, CancellationToken ct = default);
    }

    public interface IAcmeChallengeStore
    {
        string? TryGetContent(string token);
        void Put(string token, string content, TimeSpan ttl);
        void Remove(string token);
    }

    public sealed class MemoryChallengeStore : IAcmeChallengeStore
    {
        private readonly ConcurrentDictionary<string, (string content, DateTimeOffset exp)> _m = new();
        public string? TryGetContent(string token)
            => _m.TryGetValue(token, out var v) && v.exp > DateTimeOffset.UtcNow ? v.content : null;
        public void Put(string token, string content, TimeSpan ttl)
            => _m[token] = (content, DateTimeOffset.UtcNow + ttl);
        public void Remove(string token) => _m.TryRemove(token, out _);
    }


}

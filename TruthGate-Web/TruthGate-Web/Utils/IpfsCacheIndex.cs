using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;

namespace TruthGate_Web.Utils
{
    public static class IpfsCacheIndex
    {
        private static readonly ConcurrentDictionary<string, CancellationTokenSource> CidTokens = new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, CancellationTokenSource> MfsTokens = new(StringComparer.Ordinal);

        private static CancellationTokenSource GetOrCreate(ConcurrentDictionary<string, CancellationTokenSource> dict, string key)
        {
            return dict.AddOrUpdate(
                key,
                _ => new CancellationTokenSource(),
                (_, existing) => existing.IsCancellationRequested ? new CancellationTokenSource() : existing
            );
        }

        public static IChangeToken GetCidToken(string cid)
            => new CancellationChangeToken(GetOrCreate(CidTokens, cid).Token);

        public static void InvalidateCid(string cid)
        {
            if (CidTokens.TryGetValue(cid, out var cts))
            {
                try { cts.Cancel(); } catch { /* ignore */ }
            }
        }

        public static IChangeToken GetMfsToken(string mfsPath)
            => new CancellationChangeToken(GetOrCreate(MfsTokens, mfsPath).Token);

        public static void InvalidateMfs(string mfsPath)
        {
            if (MfsTokens.TryGetValue(mfsPath, out var cts))
            {
                try { cts.Cancel(); } catch { /* ignore */ }
            }
        }
    }
}

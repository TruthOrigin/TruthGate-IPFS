using Microsoft.Extensions.Primitives;
using System.Collections.Concurrent;

namespace TruthGate_Web.Utils
{
    public static class IpfsCacheIndex
    {
        private static readonly ConcurrentDictionary<string, CancellationTokenSource> CidTokens = new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, CancellationTokenSource> MfsTokens = new(StringComparer.Ordinal);

        // NEW: a single global CTS used to invalidate *all* cache entries at once.
        private static readonly object _globalLock = new();
        private static CancellationTokenSource _globalCts = new();

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
                // Optional: reclaim memory by removing the canceled CTS.
                // CidTokens.TryRemove(cid, out _);
            }
        }

        public static IChangeToken GetMfsToken(string mfsPath)
            => new CancellationChangeToken(GetOrCreate(MfsTokens, mfsPath).Token);

        public static void InvalidateMfs(string mfsPath)
        {
            if (MfsTokens.TryGetValue(mfsPath, out var cts))
            {
                try { cts.Cancel(); } catch { /* ignore */ }
                // Optional:
                // MfsTokens.TryRemove(mfsPath, out _);
            }
        }

        // === NEW: Global token APIs ===

        public static IChangeToken GetGlobalToken()
        {
            lock (_globalLock) return new CancellationChangeToken(_globalCts.Token);
        }

        public static void InvalidateAll()
        {
            lock (_globalLock)
            {
                var old = _globalCts;
                _globalCts = new CancellationTokenSource();
                try { old.Cancel(); } catch { /* ignore */ }
                old.Dispose();
            }
        }
    }

}

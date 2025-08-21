using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Runtime.InteropServices;
using TruthGate_Web.Models.Metrics;

namespace TruthGate_Web.Services
{
    public interface IMetricService
    {
        MetricSnapshot GetSnapshot();
    }

    public sealed class MetricService : BackgroundService, IMetricService
    {
        private readonly RingBuffer<MetricPoint> _points;
        private readonly MetricsOptions _opts;
        private readonly ILogger<MetricService> _log;
        private readonly bool _linux;
        private readonly object _lock = new();

        private readonly ISystemReader _sys;
        private TimeSpan _prevProcCpu = TimeSpan.Zero;
        private DateTime _prevWall = DateTime.UtcNow;
        private IReadOnlyList<ThreadSpike>? _lastThreads;

        // Linux per-thread state
        private static readonly Dictionary<int, (ulong utime, ulong stime)> _threadPrev = new();
        private static readonly double _clkTck = GetClockTicksPerSec();

        public MetricService(IOptions<MetricsOptions> opts, ILogger<MetricService> log)
        {
            _opts = opts.Value;
            _log = log;
            _points = new RingBuffer<MetricPoint>(_opts.WindowSeconds);
            _linux = OperatingSystem.IsLinux();
            _prevProcCpu = Process.GetCurrentProcess().TotalProcessorTime;
            _sys = SystemReaderFactory.Create();
        }

        public MetricSnapshot GetSnapshot()
        {
            lock (_lock)
            {
                return new MetricSnapshot(_points.Snapshot(), _lastThreads);
            }
        }


        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _prevWall = DateTime.UtcNow;
            while (!stoppingToken.IsCancellationRequested)
            {
                try { SampleOnce(); }
                catch (Exception ex) { _log.LogError(ex, "Metrics sample failed"); }

                await Task.Delay(_opts.SampleMs, stoppingToken);
            }
        }

        private void SampleOnce()
        {
            var proc = Process.GetCurrentProcess();
            var now = DateTime.UtcNow;

            // --- Process CPU% ---
            var cpuNow = proc.TotalProcessorTime;
            var cpuDeltaMs = (cpuNow - _prevProcCpu).TotalMilliseconds;
            var wallDelta = now - _prevWall;
            var wallDeltaMs = wallDelta.TotalMilliseconds;

            double procCpuPct = 0;
            if (wallDeltaMs > 0)
            {
                // normalized across logical cores
                procCpuPct = Math.Clamp(cpuDeltaMs / (wallDeltaMs * Environment.ProcessorCount) * 100.0, 0, 100);
            }
            _prevProcCpu = cpuNow;
            _prevWall = now;

            // --- Process RAM/GC/Threads ---
            var procWsMB = proc.WorkingSet64 / (1024.0 * 1024.0);
            var procGcMB = GC.GetTotalMemory(false) / (1024.0 * 1024.0);
            int procThreads = proc.Threads.Count;

            int tpThreads = ThreadPool.ThreadCount;
            int tpQueue = (int)ThreadPool.PendingWorkItemCount;

            // --- System CPU% & Memory ---
            var (sysCpuPct, sysUsedMB, sysTotalMB) = _sys.Sample(wallDelta);

            // --- Optional per-thread (Linux) ---
            List<ThreadSpike>? topThreads = null;
            if (_opts.EnablePerThreadLinux && _linux && wallDeltaMs > 0)
                topThreads = TrySampleLinuxPerThread(wallDeltaMs);

            var point = new MetricPoint(
                Ts: DateTimeOffset.UtcNow,
                ProcCpuPct: procCpuPct,
                ProcWorkingSetMB: procWsMB,
                ProcGcHeapMB: procGcMB,
                ProcThreads: procThreads,
                ThreadPoolThreads: tpThreads,
                ThreadPoolQueueLength: tpQueue,
                SysCpuPct: sysCpuPct,
                SysMemUsedMB: sysUsedMB,
                SysMemTotalMB: sysTotalMB
            );

            lock (_lock)
            {
                _points.Add(point);
                _lastThreads = topThreads;
            }
        }

        // ---- Linux per-thread via /proc/self/task/*/stat ----
        private static double GetClockTicksPerSec()
        {
            if (!OperatingSystem.IsLinux()) return 100.0;
            try { return Interop.sysconf(Interop._SC_CLK_TCK); } catch { return 100.0; }
        }

        private List<ThreadSpike>? TrySampleLinuxPerThread(double cpuWindowMs)
        {
            var dir = "/proc/self/task";
            if (!Directory.Exists(dir)) return null;
            var list = new List<ThreadSpike>(16);

            foreach (var taskDir in Directory.EnumerateDirectories(dir))
            {
                var statFile = Path.Combine(taskDir, "stat");
                try
                {
                    var stat = File.ReadAllText(statFile);
                    int close = stat.LastIndexOf(')');
                    if (close < 0) continue;
                    var rest = stat[(close + 2)..];
                    var parts = rest.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 15) continue;

                    ulong utime = ulong.Parse(parts[11]);
                    ulong stime = ulong.Parse(parts[12]);

                    int tid = int.Parse(Path.GetFileName(taskDir));
                    var prev = _threadPrev.TryGetValue(tid, out var v) ? v : default;
                    _threadPrev[tid] = (utime, stime);
                    if (prev.utime == 0 && prev.stime == 0) continue;

                    ulong dut = utime - prev.utime;
                    ulong dst = stime - prev.stime;
                    double cpuSec = (dut + dst) / _clkTck;
                    double cpuPct = Math.Clamp(cpuSec * 1000.0 / cpuWindowMs * 100.0 / Environment.ProcessorCount, 0, 100.0);

                    if (cpuPct > 0.01) list.Add(new ThreadSpike(tid, cpuPct));
                }
                catch { /* ignore */ }
            }

            if (list.Count == 0) return list;
            list.Sort((a, b) => b.CpuPercent.CompareTo(a.CpuPercent));
            if (list.Count > _opts.MaxPerThread) list = list.GetRange(0, _opts.MaxPerThread);
            return list;
        }

        private static class Interop
        {
            public const int _SC_CLK_TCK = 2;
            [DllImport("libc", SetLastError = true)]
            public static extern long sysconf(int name);
        }
    }
}

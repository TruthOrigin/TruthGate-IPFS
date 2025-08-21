namespace TruthGate_Web.Models.Metrics
{
    public sealed record MetricPoint(
        DateTimeOffset Ts,
        // Process
        double ProcCpuPct,
        double ProcWorkingSetMB,
        double ProcGcHeapMB,
        int ProcThreads,
        int ThreadPoolThreads,
        int ThreadPoolQueueLength,
        // System
        double SysCpuPct,
        double SysMemUsedMB,
        double SysMemTotalMB
    );

    public sealed record ThreadSpike(
        int Tid,                 // OS thread id
        double CpuPercent        // per-thread % normalized
    );

    public sealed record MetricSnapshot(
        IReadOnlyList<MetricPoint> Points,
        IReadOnlyList<ThreadSpike>? TopThreads // null if disabled or unsupported
    );
    public sealed class RingBuffer<T>
    {
        private readonly T[] _buf;
        private int _idx;
        private int _count;

        public RingBuffer(int capacity) => _buf = new T[capacity];

        public void Add(in T item)
        {
            _buf[_idx] = item;
            _idx = (_idx + 1) % _buf.Length;
            if (_count < _buf.Length) _count++;
        }

        public IReadOnlyList<T> Snapshot()
        {
            var res = new List<T>(_count);
            int start = (_idx - _count + _buf.Length) % _buf.Length;
            for (int i = 0; i < _count; i++)
                res.Add(_buf[(start + i) % _buf.Length]);
            return res;
        }
    }

    public sealed class MetricsOptions
    {
        public int SampleMs { get; set; } = 1000;        // 1s
        public int WindowSeconds { get; set; } = 600;    // 10m
        public bool EnablePerThreadLinux { get; set; } = false; // opt-in
        public int MaxPerThread { get; set; } = 5;
    }


}

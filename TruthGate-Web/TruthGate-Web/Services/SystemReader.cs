using System.Runtime.InteropServices;

namespace TruthGate_Web.Services
{
    internal interface ISystemReader
    {
        // Returns CPU% (0..100) for the whole machine (normalized across cores)
        // and memory (usedMB, totalMB)
        (double cpuPct, double usedMB, double totalMB) Sample(TimeSpan wallDelta);
    }

    internal static class SystemReaderFactory
    {
        public static ISystemReader Create() =>
            OperatingSystem.IsWindows() ? new WinSystemReader() :
            OperatingSystem.IsLinux() ? new LinuxSystemReader() :
            new NoopSystemReader();
    }

    // ---------- Windows ----------
    internal sealed class WinSystemReader : ISystemReader
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        private long _prevIdle, _prevKernel, _prevUser;
        private bool _primed;

        public (double cpuPct, double usedMB, double totalMB) Sample(TimeSpan wallDelta)
        {
            // CPU
            if (!GetSystemTimes(out var idle, out var kernel, out var user)) return (0, 0, 0);
            double cpuPct = 0;
            if (_primed)
            {
                var idleDelta = idle - _prevIdle;
                var kernelDelta = kernel - _prevKernel;
                var userDelta = user - _prevUser;

                // kernel includes idle on Windows; remove idle
                var total = kernelDelta + userDelta;
                var busy = total - idleDelta;
                if (total > 0) cpuPct = Math.Clamp(busy * 100.0 / total, 0, 100);
            }
            _prevIdle = idle; _prevKernel = kernel; _prevUser = user; _primed = true;

            // Memory
            var ms = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (!GlobalMemoryStatusEx(ref ms)) return (cpuPct, 0, 0);
            double totalMB = ms.ullTotalPhys / (1024.0 * 1024.0);
            double availMB = ms.ullAvailPhys / (1024.0 * 1024.0);
            double usedMB = Math.Max(0, totalMB - availMB);
            return (cpuPct, usedMB, totalMB);
        }
    }

    // ---------- Linux ----------
    internal sealed class LinuxSystemReader : ISystemReader
    {
        private (ulong user, ulong nice, ulong system, ulong idle, ulong iowait, ulong irq, ulong softirq, ulong steal) _prev;
        private bool _primed;

        public (double cpuPct, double usedMB, double totalMB) Sample(TimeSpan wallDelta)
        {
            // CPU: /proc/stat first "cpu" line
            double cpuPct = 0;
            try
            {
                var first = File.ReadLines("/proc/stat").FirstOrDefault();
                if (first is not null && first.StartsWith("cpu "))
                {
                    var parts = first.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    // cpu user nice system idle iowait irq softirq steal guest guest_nice
                    ulong user = ulong.Parse(parts[1]);
                    ulong nice = ulong.Parse(parts[2]);
                    ulong system = ulong.Parse(parts[3]);
                    ulong idle = ulong.Parse(parts[4]);
                    ulong iow = parts.Length > 5 ? ulong.Parse(parts[5]) : 0;
                    ulong irq = parts.Length > 6 ? ulong.Parse(parts[6]) : 0;
                    ulong sirq = parts.Length > 7 ? ulong.Parse(parts[7]) : 0;
                    ulong steal = parts.Length > 8 ? ulong.Parse(parts[8]) : 0;

                    if (_primed)
                    {
                        ulong prevIdle = _prev.idle + _prev.iowait;
                        ulong idleNow = idle + iow;
                        ulong prevNon = _prev.user + _prev.nice + _prev.system + _prev.irq + _prev.softirq + _prev.steal;
                        ulong nonNow = user + nice + system + irq + sirq + steal;

                        ulong totald = (idleNow + nonNow) - (prevIdle + prevNon);
                        ulong idled = idleNow - prevIdle;
                        if (totald > 0)
                            cpuPct = Math.Clamp((totald - idled) * 100.0 / totald, 0, 100);
                    }

                    _prev = (user, nice, system, idle, iow, irq, sirq, steal);
                    _primed = true;
                }
            }
            catch { /* ignore */ }

            // Mem: /proc/meminfo
            double usedMB = 0, totalMB = 0;
            try
            {
                ulong memTotalKb = 0, memAvailKb = 0;
                foreach (var line in File.ReadLines("/proc/meminfo"))
                {
                    if (line.StartsWith("MemTotal:")) memTotalKb = ParseKb(line);
                    else if (line.StartsWith("MemAvailable:")) memAvailKb = ParseKb(line);
                    if (memTotalKb != 0 && memAvailKb != 0) break;
                }
                totalMB = memTotalKb / 1024.0;
                var availMB = memAvailKb / 1024.0;
                usedMB = Math.Max(0, totalMB - availMB);
            }
            catch { /* ignore */ }

            return (cpuPct, usedMB, totalMB);

            static ulong ParseKb(string s)
            {
                var parts = s.Split(':', StringSplitOptions.RemoveEmptyEntries);
                var kbStr = parts[1].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
                return ulong.TryParse(kbStr, out var v) ? v : 0;
            }
        }
    }

    // ---------- Fallback ----------
    internal sealed class NoopSystemReader : ISystemReader
    {
        public (double cpuPct, double usedMB, double totalMB) Sample(TimeSpan wallDelta) => (0, 0, 0);
    }

}

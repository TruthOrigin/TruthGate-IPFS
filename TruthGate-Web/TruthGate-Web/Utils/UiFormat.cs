namespace TruthGate_Web.Utils
{
    public static class UiFormat
    {
        public static string Bytes(long b) => Bytes((double)b);
        public static string Bytes(double b)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
            int i = 0; while (b >= 1024 && i < units.Length - 1) { b /= 1024; i++; }
            return $"{b:0.##} {units[i]}";
        }

        public static string BytesPerSec(double bps) => $"{Bytes(bps)}/s";

        public static string Percent(double part, double whole)
        {
            if (whole <= 0) return "0%";
            return $"{(part / whole * 100):0.#}%";
        }
    }

}

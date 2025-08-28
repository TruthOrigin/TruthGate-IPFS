using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace TruthGate_Web.Utils
{
    internal static class IpUtils
    {
        public static string NormalizeIp(IPAddress ip)
            => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();

        public static string GetClientIpString(HttpContext ctx)
        {
            var ip = ctx.Connection.RemoteIpAddress ?? IPAddress.IPv6None;
            return NormalizeIp(ip);
        }

        public static bool TryGetIpv6Prefix64(string ipStr, out string prefix)
        {
            prefix = string.Empty;
            if (!IPAddress.TryParse(ipStr, out var ip)) return false;
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return false;
            var bytes = ip.GetAddressBytes();
            // zero lower 64 bits
            for (int i = 8; i < 16; i++) bytes[i] = 0;
            var norm = new IPAddress(bytes).ToString();
            prefix = norm + "/64";
            return true;
        }
    }

    internal static class TimeUtils
    {
        public static string MinuteBucketUtc(DateTimeOffset utc) => utc.ToString("yyyyMMddHHmm");
    }

    internal static class HashUtils
    {
        public static string Sha256Hex(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            var hash = SHA256.HashData(bytes);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}

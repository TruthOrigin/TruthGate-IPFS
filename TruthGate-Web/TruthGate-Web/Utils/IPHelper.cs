using System.Net.NetworkInformation;
using System.Net;

namespace TruthGate_Web.Utils
{
    public class IPHelper
    {
        public static bool IsPrivateIPv4(IPAddress ip)
        {
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
            var bytes = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31)) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            return false;
        }

        public static bool IsPublicIPv6(IPAddress ip)
        {
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return false;
            if (IPAddress.IsLoopback(ip)) return false;
            if (ip.IsIPv6LinkLocal) return false;       // fe80::/10
            if (ip.IsIPv6Multicast) return false;       // ff00::/8
            if (ip.IsIPv6SiteLocal) return false;       // fec0::/10 (deprecated but some stacks flag it)
                                                        // Unique Local Address fc00::/7 (fd00::/8 typical)
                                                        // Quick check: first 7 bits 1111110x
            var bytes = ip.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC) return false; // fc00::/7
            return true;
        }

        public static IEnumerable<IPAddress> GetPublicInterfaceIPs()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                // Optional: skip loopback/tunnel to reduce noise
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    var ip = ua.Address;
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        if (!IPAddress.IsLoopback(ip) && !IsPrivateIPv4(ip))
                            yield return ip;
                    }
                    else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        if (IsPublicIPv6(ip))
                            yield return ip;
                    }
                }
            }
        }
    }
}

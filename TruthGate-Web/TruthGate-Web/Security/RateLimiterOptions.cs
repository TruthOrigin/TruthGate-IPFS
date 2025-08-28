namespace TruthGate_Web.Security
{
    public sealed class RateLimiterOptions
    {
        public AdminOptions Admin { get; set; } = new();
        public PublicOptions Public { get; set; } = new();
        public SoftBanOptions SoftBan { get; set; } = new();
        public TlsChurnOptions TlsChurn { get; set; } = new();
        public Ipv6GraylistOptions Ipv6Graylist { get; set; } = new();
        public RetentionOptions Retention { get; set; } = new();
        public GatewayOptions Gateway { get; set; } = new();

        public sealed class AdminOptions
        {
            public int MaxBadKeyPerIpPer24h { get; set; } = 10;
            public TimeSpan BanDurationSoft { get; set; } = TimeSpan.FromHours(72);
            public TimeSpan BanDurationEscalate4x { get; set; } = TimeSpan.FromDays(7);
            public TimeSpan BanDurationEscalate10x { get; set; } = TimeSpan.FromDays(1825);
            public int GraceDays { get; set; } = 7;
            public bool EnablePerKeyCeiling { get; set; } = false;
            public int PerKeySustainedRps { get; set; } = 100; // example
            public int PerKeyBurstRps { get; set; } = 500;     // example
        }

        public sealed class PublicOptions
        {
            public int PerIpPerMinute { get; set; } = 300;
            public (int Threshold, int NewPerMinute)[] GlobalTiers { get; set; } =
                new[] { (2000, 200), (8000, 100), (16000, 30) };
            public TimeSpan SoftBanDuration { get; set; } = TimeSpan.FromMinutes(15);
        }

        public sealed class SoftBanOptions
        {
            public int ObserveMinutes { get; set; } = 10; // for escalation checks
        }

        public sealed class TlsChurnOptions
        {
            public int NewConnectionsPerSec { get; set; } = 30;
            public double MinReqPerConn { get; set; } = 1.2;
            public int ObserveSeconds { get; set; } = 10;
            public bool Enabled { get; set; } = true;
        }

        public sealed class Ipv6GraylistOptions
        {
            public (int Count, int Minutes) Short { get; set; } = (8, 10);
            public (int Count, int Minutes) Long { get; set; } = (20, 60);
        }

        public sealed class RetentionOptions
        {
            public int PurgeOlderThanDays { get; set; } = 180;
            public int PurgeExpiredBanAfterDays { get; set; } = 30;
        }

        public sealed class GatewayOptions
        {
            public int FreePerMinute { get; set; } = 400;
            public int HourlyOverage { get; set; } = 3200; // sliding last 60 mins
            public TimeSpan BanOnExhaustion { get; set; } = TimeSpan.FromHours(4);
            public int Escalate4xMinuteMultiple { get; set; } = 4; // multiply duration
            public TimeSpan Escalate10xMinuteTrueBan { get; set; } = TimeSpan.FromDays(7);
            public bool AutoWhitelistOnAuthOrValidKey { get; set; } = true;
        }
    }
}

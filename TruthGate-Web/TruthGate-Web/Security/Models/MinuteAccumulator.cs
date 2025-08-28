namespace TruthGate_Web.Security.Models
{
    internal sealed class MinuteAccumulator
    {
        public int PublicCalls;
        public int AdminBadKeyCalls;
        public int AdminGoodKeyCalls;
        public int GatewayCalls;
        public int GatewayOverageUsed;
    }

    internal sealed class GlobalAccumulator { public int TotalCalls; }
}

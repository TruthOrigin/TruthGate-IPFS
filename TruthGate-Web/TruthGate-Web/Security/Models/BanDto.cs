namespace TruthGate_Web.Security.Models
{
    public enum BanScopeFilter { Global, Public, Admin, Gateway }

    public sealed class BanDto
    {
        public Guid Id { get; init; }
        public string? Ip { get; init; }
        public string? Ipv6Prefix { get; init; }
        public RateScope Scope { get; init; }
        public bool IsTrueBan { get; init; }
        public string ReasonCode { get; init; } = "";
        public DateTimeOffset CreatedUtc { get; init; }
        public DateTimeOffset ExpiresUtc { get; init; }
    }
}

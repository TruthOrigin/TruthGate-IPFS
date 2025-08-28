using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Reflection.Emit;

namespace TruthGate_Web.Security
{

    public enum RateScope { Global = 0, Public = 1, Admin = 2, Gateway = 3 }
    public enum BanType { Soft = 0, True = 1 }

    [PrimaryKey(nameof(Ip), nameof(MinuteBucket))]
    public sealed class IpMinuteCounter
    {
        [MaxLength(64)] public string Ip { get; set; } = default!; // normalized string
        [MaxLength(12)] public string MinuteBucket { get; set; } = default!; // yyyyMMddHHmm UTC

        public RateScope Scope { get; set; } // mostly for observability

        public int PublicCalls { get; set; }
        public int AdminBadKeyCalls { get; set; }
        public int AdminGoodKeyCalls { get; set; }
        public int GatewayCalls { get; set; }
        public int GatewayOverageUsed { get; set; }
    }

    [PrimaryKey(nameof(MinuteBucket))]
    public sealed class GlobalMinuteCounter
    {
        [MaxLength(12)] public string MinuteBucket { get; set; } = default!;
        public int TotalCalls { get; set; }
    }

    public sealed class Ban
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        [MaxLength(64)] public string? Ip { get; set; }
        [MaxLength(64)] public string? IpV6Prefix { get; set; } // /64 string
        public RateScope Scope { get; set; }
        public BanType Type { get; set; }
        [MaxLength(64)] public string ReasonCode { get; set; } = "";
        public DateTimeOffset CreatedUtc { get; set; }
        public DateTimeOffset ExpiresUtc { get; set; }
        public bool IsTrueBan { get; set; }
    }

    [PrimaryKey(nameof(Ip), nameof(KeyHash))]
    public sealed class GracePair
    {
        [MaxLength(64)] public string Ip { get; set; } = default!;
        [MaxLength(128)] public string KeyHash { get; set; } = default!;
        public DateTimeOffset ExpiresUtc { get; set; }
    }

    [PrimaryKey(nameof(Ip), nameof(WindowStartUtc))]
    public sealed class TlsChurnMetric
    {
        [MaxLength(64)] public string Ip { get; set; } = default!;
        public DateTimeOffset WindowStartUtc { get; set; } // round to seconds
        public int NewConnections { get; set; }
        public int Requests { get; set; }
        public double AvgReqPerConn { get; set; }
    }

    public sealed class Whitelist
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        [MaxLength(64)] public string? Ip { get; set; }
        [MaxLength(64)] public string? Ipv6Prefix { get; set; }
        [MaxLength(256)] public string? Reason { get; set; }
        public DateTimeOffset CreatedUtc { get; set; }
        public DateTimeOffset? ExpiresUtc { get; set; }
        public bool Auto { get; set; }
    }

    public sealed class AdminAuditLog
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public DateTimeOffset TsUtc { get; set; }
        [MaxLength(128)] public string Actor { get; set; } = "system"; // who
        [MaxLength(64)] public string Action { get; set; } = "";      // e.g., UnbanIp
        [MaxLength(128)] public string Target { get; set; } = "";      // ip/prefix/banId
        public string? DetailsJson { get; set; }
    }

    public sealed class RateLimiterDbContext : DbContext
    {
        public DbSet<IpMinuteCounter> IpMinuteCounters => Set<IpMinuteCounter>();
        public DbSet<GlobalMinuteCounter> GlobalMinuteCounters => Set<GlobalMinuteCounter>();
        public DbSet<Ban> Bans => Set<Ban>();
        public DbSet<GracePair> GracePairs => Set<GracePair>();
        public DbSet<TlsChurnMetric> TlsChurnMetrics => Set<TlsChurnMetric>();
        public DbSet<Whitelist> Whitelists => Set<Whitelist>();
        public DbSet<AdminAuditLog> AdminAuditLogs => Set<AdminAuditLog>();

        public RateLimiterDbContext(DbContextOptions<RateLimiterDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder b)
        {
            base.OnModelCreating(b);

            b.Entity<IpMinuteCounter>().Property(x => x.Ip).IsRequired();
            b.Entity<IpMinuteCounter>().Property(x => x.MinuteBucket).IsRequired();
            b.Entity<GlobalMinuteCounter>().Property(x => x.MinuteBucket).IsRequired();

            b.Entity<GracePair>().HasIndex(x => x.ExpiresUtc);
            b.Entity<Whitelist>().HasIndex(x => x.ExpiresUtc);
            b.Entity<Ban>().HasIndex(x => x.ExpiresUtc);

            // Helpful indexes
            b.Entity<IpMinuteCounter>().HasIndex(x => x.MinuteBucket);
            b.Entity<IpMinuteCounter>().HasIndex(x => new { x.Ip, x.Scope });
            b.Entity<Ban>().HasIndex(x => new { x.Ip, x.IpV6Prefix, x.Scope, x.Type });
        }
    }
}

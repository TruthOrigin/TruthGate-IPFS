using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TruthGate_Web.Migrations.RateLimiter
{
    /// <inheritdoc />
    public partial class Initial_RateLimiter : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AdminAuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TsUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    Actor = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Action = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Target = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    DetailsJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdminAuditLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Bans",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    IpV6Prefix = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Scope = table.Column<int>(type: "INTEGER", nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false),
                    ReasonCode = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    CreatedUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ExpiresUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    IsTrueBan = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Bans", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "GlobalMinuteCounters",
                columns: table => new
                {
                    MinuteBucket = table.Column<string>(type: "TEXT", maxLength: 12, nullable: false),
                    TotalCalls = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GlobalMinuteCounters", x => x.MinuteBucket);
                });

            migrationBuilder.CreateTable(
                name: "GracePairs",
                columns: table => new
                {
                    Ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    KeyHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    ExpiresUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GracePairs", x => new { x.Ip, x.KeyHash });
                });

            migrationBuilder.CreateTable(
                name: "IpMinuteCounters",
                columns: table => new
                {
                    Ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    MinuteBucket = table.Column<string>(type: "TEXT", maxLength: 12, nullable: false),
                    Scope = table.Column<int>(type: "INTEGER", nullable: false),
                    PublicCalls = table.Column<int>(type: "INTEGER", nullable: false),
                    AdminBadKeyCalls = table.Column<int>(type: "INTEGER", nullable: false),
                    AdminGoodKeyCalls = table.Column<int>(type: "INTEGER", nullable: false),
                    GatewayCalls = table.Column<int>(type: "INTEGER", nullable: false),
                    GatewayOverageUsed = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IpMinuteCounters", x => new { x.Ip, x.MinuteBucket });
                });

            migrationBuilder.CreateTable(
                name: "TlsChurnMetrics",
                columns: table => new
                {
                    Ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    WindowStartUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    NewConnections = table.Column<int>(type: "INTEGER", nullable: false),
                    Requests = table.Column<int>(type: "INTEGER", nullable: false),
                    AvgReqPerConn = table.Column<double>(type: "REAL", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TlsChurnMetrics", x => new { x.Ip, x.WindowStartUtc });
                });

            migrationBuilder.CreateTable(
                name: "Whitelists",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Ip = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Ipv6Prefix = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    CreatedUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ExpiresUtc = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    Auto = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Whitelists", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Bans_ExpiresUtc",
                table: "Bans",
                column: "ExpiresUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Bans_Ip_IpV6Prefix_Scope_Type",
                table: "Bans",
                columns: new[] { "Ip", "IpV6Prefix", "Scope", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_GracePairs_ExpiresUtc",
                table: "GracePairs",
                column: "ExpiresUtc");

            migrationBuilder.CreateIndex(
                name: "IX_IpMinuteCounters_Ip_Scope",
                table: "IpMinuteCounters",
                columns: new[] { "Ip", "Scope" });

            migrationBuilder.CreateIndex(
                name: "IX_IpMinuteCounters_MinuteBucket",
                table: "IpMinuteCounters",
                column: "MinuteBucket");

            migrationBuilder.CreateIndex(
                name: "IX_Whitelists_ExpiresUtc",
                table: "Whitelists",
                column: "ExpiresUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AdminAuditLogs");

            migrationBuilder.DropTable(
                name: "Bans");

            migrationBuilder.DropTable(
                name: "GlobalMinuteCounters");

            migrationBuilder.DropTable(
                name: "GracePairs");

            migrationBuilder.DropTable(
                name: "IpMinuteCounters");

            migrationBuilder.DropTable(
                name: "TlsChurnMetrics");

            migrationBuilder.DropTable(
                name: "Whitelists");
        }
    }
}

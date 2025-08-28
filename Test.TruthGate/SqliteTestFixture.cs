using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Test.TruthGate
{
    public sealed class SqliteTestFixture : IDisposable
    {
        public string TempRoot { get; }
        public string ConfigPath { get; }
        public string DbPath => Path.Combine(Path.GetDirectoryName(ConfigPath)!, "ratelimiter.db");
        public string ConnectionString => $"Data Source={DbPath};Cache=Shared";

        public SqliteTestFixture()
        {
            TempRoot = Path.Combine(Path.GetTempPath(), "truthgate-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(TempRoot);
            ConfigPath = Path.Combine(TempRoot, "config.json");
            File.WriteAllText(ConfigPath, "{}");
            if (File.Exists(DbPath)) File.Delete(DbPath);
        }

        public void Dispose()
        {
            try { if (Directory.Exists(TempRoot)) Directory.Delete(TempRoot, true); } catch { }
        }
    }

    [CollectionDefinition("TruthGateServerCollection")]
    public sealed class TruthGateServerCollection : ICollectionFixture<SqliteTestFixture> { }

}

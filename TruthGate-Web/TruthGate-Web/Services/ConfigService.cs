using System.Text.Json;
using System.Text.Json.Serialization;
using TruthGate_Web.Models;

namespace TruthGate_Web.Services
{
    public interface IConfigService
    {
        /// <summary>Returns a deep copy snapshot of the current config.</summary>
        Config Get();

        /// <summary>Saves the provided config (replaces in-memory & file, atomic write).</summary>
        Task SaveAsync(Config newConfig, CancellationToken ct = default);

        /// <summary>Mutate & persist in one locked step.</summary>
        Task UpdateAsync(Action<Config> mutator, CancellationToken ct = default);

        /// <summary>Full resolved absolute path to the config file.</summary>
        string ConfigPath { get; }
    }

    public sealed class ConfigService : IConfigService, IHostedService
    {
        private const string EnvVarName = "TRUTHGATE_CONFIG_PATH";

        private readonly ILogger<ConfigService> _logger;
        private readonly SemaphoreSlim _mutex = new(1, 1);
        private readonly JsonSerializerOptions _jsonOptions;

        private string _configPath = default!;
        private Config _config = default!;

        public string ConfigPath
        {
            get
            {
                _mutex.Wait();
                try { return _configPath; }
                finally { _mutex.Release(); }
            }
        }

        public ConfigService(ILogger<ConfigService> logger)
        {
            _logger = logger;

            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = null // keep PascalCase to match your class names
            };
        }

        // ---- IHostedService: ensures load happens on app startup ----
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await _mutex.WaitAsync(cancellationToken);
            try
            {
                // Keep same env-var call pattern you used
                var env = Environment.GetEnvironmentVariable(EnvVarName, EnvironmentVariableTarget.Machine);
                if (string.IsNullOrWhiteSpace(env))
                {
                    throw new InvalidOperationException(
                        $"Environment variable '{EnvVarName}' is not set. " +
                        "Set it to the JSON config file path (supports ~ and relative paths).");
                }

                _configPath = ResolvePath(env);

                // Ensure parent directory exists
                Directory.CreateDirectory(Path.GetDirectoryName(_configPath)!);

                if (File.Exists(_configPath))
                {
                    var json = await File.ReadAllTextAsync(_configPath, cancellationToken);
                    _config = JsonSerializer.Deserialize<Config>(json, _jsonOptions) ?? new Config();
                }
                else
                {
                    _logger.LogInformation("Config file not found at '{Path}'. Starting with a new config in memory.", _configPath);
                    _config = new Config();
                    // Don’t write yet—let caller decide when to persist first time.
                }

                // Force materialization of default admin, in case file is empty/missing admin
                _ = _config.Users;
            }
            finally
            {
                _mutex.Release();
            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            // Nothing special; config is saved explicitly by callers.
            return Task.CompletedTask;
        }

        // ---- Public API ----

        public Config Get()
        {
            _mutex.Wait();
            try
            {
                // Return a deep copy so external code can’t mutate in-memory state without Save/Update
                var json = JsonSerializer.Serialize(_config, _jsonOptions);
                return JsonSerializer.Deserialize<Config>(json, _jsonOptions)!;
            }
            finally
            {
                _mutex.Release();
            }
        }

        public async Task SaveAsync(Config newConfig, CancellationToken ct = default)
        {
            if (newConfig is null) throw new ArgumentNullException(nameof(newConfig));

            await _mutex.WaitAsync(ct);
            try
            {
                // normalize via Users getter (ensures admin, trims, etc.)
                _ = newConfig.Users;

                // Replace in-memory
                _config = newConfig;

                await AtomicWriteAsync(_configPath, _config, _jsonOptions, ct).ConfigureAwait(false);
            }
            finally
            {
                _mutex.Release();
            }
        }

        public async Task UpdateAsync(Action<Config> mutator, CancellationToken ct = default)
        {
            if (mutator is null) throw new ArgumentNullException(nameof(mutator));

            await _mutex.WaitAsync(ct);
            try
            {
                // Work on a copy, then swap in if successful
                var json = JsonSerializer.Serialize(_config, _jsonOptions);
                var working = JsonSerializer.Deserialize<Config>(json, _jsonOptions)!;

                mutator(working);

                // normalize & ensure admin
                _ = working.Users;

                _config = working;
                await AtomicWriteAsync(_configPath, _config, _jsonOptions, ct).ConfigureAwait(false);
            }
            finally
            {
                _mutex.Release();
            }
        }

        // ---- Helpers ----

        private static string ResolvePath(string raw)
        {
            var val = raw.Trim();

            // Expand ~
            if (val.StartsWith("~"))
            {
                var home =
                    Environment.GetEnvironmentVariable("HOME") // Linux/macOS
                    ?? Environment.GetEnvironmentVariable("USERPROFILE") // Windows
                    ?? throw new InvalidOperationException("Cannot resolve '~' because HOME/USERPROFILE is not set.");

                val = Path.Combine(home, val.Substring(1).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }

            // If not rooted, make it absolute relative to current working directory
            if (!Path.IsPathRooted(val))
            {
                val = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), val));
            }

            return val;
        }

        private static async Task AtomicWriteAsync(string path, Config cfg, JsonSerializerOptions options, CancellationToken ct)
        {
            var dir = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(dir);

            var tempPath = Path.Combine(dir, $".{Path.GetFileName(path)}.tmp");

            await using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await JsonSerializer.SerializeAsync(fs, cfg, options, ct).ConfigureAwait(false);
                await fs.FlushAsync(ct).ConfigureAwait(false);
            }

            // Replace original atomically if possible
            if (File.Exists(path))
            {
                // On Windows, File.Replace gives best atomic semantics; fallback to Move on others
                try
                {
                    var backup = Path.Combine(dir, $".{Path.GetFileName(path)}.bak");
                    File.Replace(tempPath, path, backup, ignoreMetadataErrors: true);
                    TryDeleteQuiet(backup);
                }
                catch
                {
                    // Fallback: delete + move
                    File.Delete(path);
                    File.Move(tempPath, path);
                }
            }
            else
            {
                File.Move(tempPath, path);
            }
        }

        private static void TryDeleteQuiet(string p)
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { /* ignore */ }
        }
    }

}

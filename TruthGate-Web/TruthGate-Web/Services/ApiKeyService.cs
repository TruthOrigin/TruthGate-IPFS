using System.Security.Cryptography;

namespace TruthGate_Web.Services
{
    public interface IApiKeyProvider
    {
        string GetCurrentKey();                 // for internal callers
        bool IsValid(string? apiKey);           // quick validator
        DateTimeOffset CreatedAt { get; }       // when current key was born
        DateTimeOffset ExpiresAt { get; }       // when it will rotate
    }

    public sealed class ApiKeyService : BackgroundService, IApiKeyProvider
    {
        private readonly ILogger<ApiKeyService> _log;

        // we only ever swap this reference atomically
        private volatile KeyRecord _state;

        private readonly TimeSpan _rotationPeriod = TimeSpan.FromDays(30);

        private sealed record KeyRecord(string Value, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);

        public ApiKeyService(ILogger<ApiKeyService> log)
        {
            _log = log;
            _state = NewKey();
            _log.LogInformation("API key created at {CreatedAt}, expires at {ExpiresAt}",
                _state.CreatedAt, _state.ExpiresAt);
        }

        public string GetCurrentKey() => _state.Value;

        public bool IsValid(string? apiKey) => !string.IsNullOrEmpty(apiKey) && apiKey == _state.Value;

        public DateTimeOffset CreatedAt => _state.CreatedAt;

        public DateTimeOffset ExpiresAt => _state.ExpiresAt;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Wait until the current key’s expiry, then rotate, forever.
            while (!stoppingToken.IsCancellationRequested)
            {
                var delay = _state.ExpiresAt - DateTimeOffset.UtcNow;
                if (delay < TimeSpan.Zero) delay = TimeSpan.Zero;

                try
                {
                    await Task.Delay(delay, stoppingToken);
                }
                catch (OperationCanceledException) { break; }

                Rotate();
            }
        }

        private void Rotate()
        {
            var next = NewKey();
            _state = next; // atomic reference swap
            _log.LogInformation("API key rotated at {CreatedAt}, next rotation at {ExpiresAt}",
                next.CreatedAt, next.ExpiresAt);
        }

        private KeyRecord NewKey()
        {
            // 256-bit key, base64url (unpadded). Tweak bytes if you want longer/shorter.
            Span<byte> bytes = stackalloc byte[32];
            RandomNumberGenerator.Fill(bytes);

            var key = Base64Url(bytes);
            var now = DateTimeOffset.UtcNow;
            return new KeyRecord(key, now, now + _rotationPeriod);
        }

        private static string Base64Url(ReadOnlySpan<byte> bytes)
        {
            // Convert.ToBase64String → make it URL-safe and strip padding
            var s = Convert.ToBase64String(bytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
            return s;
        }
    }
}

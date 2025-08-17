using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace TruthGate_Web.Configuration
{
    public sealed class CertesAcmeIssuer : IAcmeIssuer, IAcmeIssuerLabel
    {
        private readonly Uri _dirUri;
        private readonly string _accountPemPath;
        private readonly IAcmeChallengeStore _challengeStore;
        private readonly ILogger<CertesAcmeIssuer> _logger;
        private readonly bool _isStaging;
        public string Label => _isStaging ? "staging" : "prod";
        public CertesAcmeIssuer(
            IAcmeChallengeStore challengeStore,
            ILogger<CertesAcmeIssuer> logger,
            bool useStaging = false,
            string accountPemPath = "/opt/truthgate/certs/account.pem")
        {
            _challengeStore = challengeStore;
            _accountPemPath = accountPemPath;
            _logger = logger;
            _isStaging = useStaging;
            _dirUri = useStaging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;
        }

        public async Task<X509Certificate2?> IssueOrRenewAsync(string host, CancellationToken ct = default)
        {
            try
            {
                _logger.LogInformation("ACME[{Dir}] start {Host}", _isStaging ? "staging" : "prod", host);

                var accountKey = await LoadOrCreateAccountKeyAsync(ct);
                var acme = new AcmeContext(_dirUri, accountKey);

                try { await acme.NewAccount(Array.Empty<string>(), true); }
                catch { _logger.LogDebug("ACME account exists"); }

                var order = await acme.NewOrder(new[] { host });
                _logger.LogInformation("ACME[{Dir}] order created for {Host}", _isStaging ? "staging" : "prod", host);

                var authzs = await order.Authorizations();
                foreach (var authz in authzs)
                {
                    // inside the foreach (var authz in authzs)
                    var http = await authz.Http();
                    var token = http.Token;
                    var keyAuthz = http.KeyAuthz;

                    _logger.LogInformation("ACME[{Dir}] token for {Host}: GET http://{Host}/.well-known/acme-challenge/{Token}",
                        _isStaging ? "staging" : "prod", host, host, token);
                    _logger.LogInformation("ACME[{Dir}] expected body (keyAuthz) for {Host}: {KeyAuthz}",
                        _isStaging ? "staging" : "prod", host, keyAuthz);

                    _challengeStore.Put(token, keyAuthz, TimeSpan.FromMinutes(10));
                    await http.Validate();

                    var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();
                        var res = await authz.Resource();
                        if (res.Status == Certes.Acme.Resource.AuthorizationStatus.Valid)
                        {
                            _logger.LogInformation("ACME[{Dir}] authorization VALID for {Host}", _isStaging ? "staging" : "prod", host);
                            break;
                        }
                        if (res.Status == Certes.Acme.Resource.AuthorizationStatus.Invalid)
                            throw new InvalidOperationException($"ACME authorization failed for {host}");
                        if (DateTimeOffset.UtcNow > deadline)
                            throw new TimeoutException($"ACME authorization timed out for {host}");
                        await Task.Delay(1000, ct);
                    }

                    _challengeStore.Remove(http.Token);
                }

                var key = KeyFactory.NewKey(KeyAlgorithm.ES256);
                var chain = await order.Generate(new CsrInfo { CommonName = host }, key);
                var pfxBytes = chain.ToPfx(key).Build(host, (string?)null);

                _logger.LogInformation("ACME[{Dir}] issued PFX for {Host} (len={Len})",
                    _isStaging ? "staging" : "prod", host, pfxBytes.Length);

                return X509CertificateLoader.LoadPkcs12(pfxBytes, ReadOnlySpan<char>.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ACME[{Dir}] issuance FAILED for {Host}", _isStaging ? "staging" : "prod", host);
                throw;
            }
        }

        private async Task<IKey> LoadOrCreateAccountKeyAsync(CancellationToken ct)
        {
            var dir = Path.GetDirectoryName(_accountPemPath)!;
            System.IO.Directory.CreateDirectory(dir);
            if (File.Exists(_accountPemPath))
            {
                _logger.LogInformation("ACME account key: using existing {Path}", _accountPemPath);
                var pem = await File.ReadAllTextAsync(_accountPemPath, ct);
                return KeyFactory.FromPem(pem);
            }

            _logger.LogInformation("ACME account key: creating {Path}", _accountPemPath);
            var key = KeyFactory.NewKey(KeyAlgorithm.ES256);
            await File.WriteAllTextAsync(_accountPemPath, key.ToPem(), ct);
            return key;
        }
    }

}

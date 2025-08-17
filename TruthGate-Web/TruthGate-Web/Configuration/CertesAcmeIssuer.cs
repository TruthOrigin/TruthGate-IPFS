using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace TruthGate_Web.Configuration
{
    public sealed class CertesAcmeIssuer : IAcmeIssuer
    {
        private readonly Uri _dirUri;
        private readonly string _accountPemPath;
        private readonly IAcmeChallengeStore _challengeStore;
        private readonly ILogger<CertesAcmeIssuer> _logger;

        public CertesAcmeIssuer(
            IAcmeChallengeStore challengeStore,
            ILogger<CertesAcmeIssuer> logger,
            bool useStaging = false,
            string accountPemPath = "/opt/truthgate/certs/account.pem")
        {
            _challengeStore = challengeStore;
            _accountPemPath = accountPemPath;
            _logger = logger;
            _dirUri = useStaging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;
        }

        public async Task<X509Certificate2?> IssueOrRenewAsync(string host, CancellationToken ct = default)
        {
            try
            {
                _logger.LogInformation("ACME: Starting issuance for {Host}", host);

                var accountKey = await LoadOrCreateAccountKeyAsync(ct);
                var acme = new AcmeContext(_dirUri, accountKey);

                try
                {
                    await acme.NewAccount(Array.Empty<string>(), termsOfServiceAgreed: true);
                    _logger.LogInformation("ACME: Account created for {Host}", host);
                }
                catch
                {
                    _logger.LogDebug("ACME: Account already exists.");
                }

                var order = await acme.NewOrder(new[] { host });
                _logger.LogInformation("ACME: Order created for {Host}", host);

                var authzs = await order.Authorizations();
                foreach (var authz in authzs)
                {
                    var http = await authz.Http();
                    _logger.LogInformation("ACME: Placing challenge {Token} for {Host}", http.Token, host);

                    _challengeStore.Put(http.Token, http.KeyAuthz, TimeSpan.FromMinutes(10));
                    await http.Validate();

                    var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();
                        var res = await authz.Resource();

                        if (res.Status == AuthorizationStatus.Valid)
                        {
                            _logger.LogInformation("ACME: Challenge validated for {Host}", host);
                            break;
                        }

                        if (res.Status == AuthorizationStatus.Invalid)
                        {
                            _logger.LogError("ACME: Challenge failed for {Host}", host);
                            throw new InvalidOperationException($"ACME authorization failed for {host}");
                        }

                        if (DateTimeOffset.UtcNow > deadline)
                            throw new TimeoutException($"ACME authorization timed out for {host}");

                        await Task.Delay(1500, ct);
                    }

                    _challengeStore.Remove(http.Token);
                }

                var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
                var chain = await order.Generate(new CsrInfo { CommonName = host }, privateKey);

                var pfxBytes = chain.ToPfx(privateKey).Build(host, (string?)null);
                _logger.LogInformation("ACME: Certificate successfully issued for {Host}", host);

                return new X509Certificate2(pfxBytes);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ACME: Issuance failed for {Host}", host);
                throw;
            }
        }

        private async Task<IKey> LoadOrCreateAccountKeyAsync(CancellationToken ct)
        {
            var dir = Path.GetDirectoryName(_accountPemPath)!;
            System.IO.Directory.CreateDirectory(dir);

            if (File.Exists(_accountPemPath))
            {
                _logger.LogInformation("ACME: Using existing account key at {Path}", _accountPemPath);
                var pem = await File.ReadAllTextAsync(_accountPemPath, ct);
                return KeyFactory.FromPem(pem);
            }

            _logger.LogInformation("ACME: Creating new account key at {Path}", _accountPemPath);
            var key = KeyFactory.NewKey(KeyAlgorithm.ES256);
            await File.WriteAllTextAsync(_accountPemPath, key.ToPem(), ct);
            return key;
        }
    }
}

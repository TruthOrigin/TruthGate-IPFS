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

        public CertesAcmeIssuer(
            IAcmeChallengeStore challengeStore,
            bool useStaging = false,
            string accountPemPath = "/opt/truthgate/acme/account.pem")
        {
            _challengeStore = challengeStore;
            _accountPemPath = accountPemPath;
            _dirUri = useStaging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;
        }

        public async Task<X509Certificate2?> IssueOrRenewAsync(string host, CancellationToken ct = default)
        {
            var accountKey = await LoadOrCreateAccountKeyAsync(ct);
            var acme = new AcmeContext(_dirUri, accountKey);

            try { await acme.NewAccount(Array.Empty<string>(), termsOfServiceAgreed: true); } catch { /* exists */ }

            var order = await acme.NewOrder(new[] { host });

            var authzs = await order.Authorizations();
            foreach (var authz in authzs)
            {
                ct.ThrowIfCancellationRequested();

                var http = await authz.Http();
                var token = http.Token;
                var keyAuthz = http.KeyAuthz;

                _challengeStore.Put(token, keyAuthz, TimeSpan.FromMinutes(10));
                await http.Validate();

                var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    var res = await authz.Resource();
                    if (res.Status == Certes.Acme.Resource.AuthorizationStatus.Valid) break;
                    if (res.Status == Certes.Acme.Resource.AuthorizationStatus.Invalid)
                        throw new InvalidOperationException($"ACME authorization failed for {host}.");
                    if (DateTimeOffset.UtcNow > deadline)
                        throw new TimeoutException($"ACME authorization timed out for {host}.");
                    await Task.Delay(1500, ct);
                }

                _challengeStore.Remove(token);
            }

            var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var chain = await order.Generate(new CsrInfo { CommonName = host }, privateKey);
            var pfxBytes = chain.ToPfx(privateKey).Build(host, (string?)null);
            return new X509Certificate2(pfxBytes);
        }

        private async Task<IKey> LoadOrCreateAccountKeyAsync(CancellationToken ct)
        {
            var dir = Path.GetDirectoryName(_accountPemPath)!;
            System.IO.Directory.CreateDirectory(dir);
            if (System.IO.File.Exists(_accountPemPath))
            {
                var pem = await System.IO.File.ReadAllTextAsync(_accountPemPath, ct);
                return KeyFactory.FromPem(pem);
            }

            var key = KeyFactory.NewKey(KeyAlgorithm.ES256);
            await System.IO.File.WriteAllTextAsync(_accountPemPath, key.ToPem(), ct);
            return key;
        }
    }
}

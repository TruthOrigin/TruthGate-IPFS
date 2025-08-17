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
                    var http = await authz.Http();
                    var token = http.Token;
                    var keyAuthz = http.KeyAuthz;
                    var url = $"http://{host}/.well-known/acme-challenge/{token}";

                    _logger.LogInformation("ACME[{Dir}] token URL {Url}", _isStaging ? "staging" : "prod", url);
                    _logger.LogInformation("ACME[{Dir}] expected keyAuthz for {Host}: {Key}", _isStaging ? "staging" : "prod", host, keyAuthz);

                    // Preflight: fetch our own endpoint over HTTP (should be 200 and exact body; no redirect)
                    try
                    {
                        using var hc = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = System.Net.DecompressionMethods.None });
                        hc.Timeout = TimeSpan.FromSeconds(5);
                        var resp = await hc.GetAsync(url, ct);
                        var body = await resp.Content.ReadAsStringAsync(ct);
                        _logger.LogInformation("Preflight GET {Url} -> {Status} len={Len}", url, (int)resp.StatusCode, body.Length);

                        if (resp.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            // Compare exact contents
                            if (!string.Equals(body, keyAuthz, StringComparison.Ordinal))
                            {
                                _logger.LogWarning("Preflight mismatch: body != keyAuthz (first 60 bytes) body='{Body}'", body.Length > 60 ? body.Substring(0, 60) : body);
                            }
                        }
                        else
                        {
                            _logger.LogWarning("Preflight not 200: {Code} (no redirect allowed)", (int)resp.StatusCode);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Preflight GET failed (this can indicate firewall/proxy/redirect)");
                    }

                    _challengeStore.Put(token, keyAuthz, TimeSpan.FromMinutes(10));
                    await http.Validate();

                    // Poll the *challenge* for detailed errors
                    var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();

                        var chRes = await http.Resource(); // challenge resource
                        if (chRes.Status == Certes.Acme.Resource.ChallengeStatus.Valid)
                        {
                            _logger.LogInformation("ACME[{Dir}] challenge VALID for {Host}", _isStaging ? "staging" : "prod", host);
                            break;
                        }
                        if (chRes.Status == Certes.Acme.Resource.ChallengeStatus.Invalid)
                        {
                            var errType = chRes.Error?.Type;
                            var errDetail = chRes.Error?.Detail;
                            _logger.LogError("ACME[{Dir}] challenge INVALID for {Host}. Type={Type} Detail={Detail}", _isStaging ? "staging" : "prod", host, errType, errDetail);
                            throw new InvalidOperationException($"ACME authorization failed for {host}: {errType} {errDetail}");
                        }

                        if (DateTimeOffset.UtcNow > deadline)
                            throw new TimeoutException($"ACME authorization timed out for {host}");

                        await Task.Delay(1000, ct);
                    }

                    _challengeStore.Remove(http.Token);
                }

                var key = KeyFactory.NewKey(KeyAlgorithm.ES256);
                var chain = await order.Generate(new CsrInfo { CommonName = host }, key);
                var pfxBytes = chain.ToPfx(key).Build(host, (string?)null);

                _logger.LogInformation("ACME[{Dir}] issued PFX for {Host} (len={Len})", _isStaging ? "staging" : "prod", host, pfxBytes.Length);
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

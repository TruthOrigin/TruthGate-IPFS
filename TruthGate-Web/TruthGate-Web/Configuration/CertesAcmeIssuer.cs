using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using System.Security.Cryptography.Pkcs;

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
                _logger.LogInformation("ACME[{Dir}] start {Host}", Label, host);

                // 1) ACME context + account
                var accountKey = await LoadOrCreateAccountKeyAsync(ct);
                var acme = new AcmeContext(_dirUri, accountKey);
                try { await acme.NewAccount(Array.Empty<string>(), true); }
                catch { _logger.LogDebug("ACME[{Dir}] account exists", Label); }

                // 2) Create order & validate HTTP-01
                var order = await acme.NewOrder(new[] { host });
                _logger.LogInformation("ACME[{Dir}] order created for {Host}", Label, host);

                var authzs = await order.Authorizations();
                foreach (var authz in authzs)
                {
                    var http = await authz.Http();
                    var token = http.Token;
                    var keyAuthz = http.KeyAuthz;
                    var url = $"http://{host}/.well-known/acme-challenge/{token}";

                    // Preflight (best-effort)
                    try
                    {
                        using var hc = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
                        hc.Timeout = TimeSpan.FromSeconds(5);
                        var resp = await hc.GetAsync(url, ct);
                        var body = await resp.Content.ReadAsStringAsync(ct);
                        _logger.LogInformation("Preflight GET {Url} -> {Status} len={Len}", url, (int)resp.StatusCode, body.Length);
                        if (resp.StatusCode == System.Net.HttpStatusCode.OK && !string.Equals(body, keyAuthz, StringComparison.Ordinal))
                            _logger.LogWarning("Preflight mismatch: body != keyAuthz (first 60) body='{Body}'", body.Length > 60 ? body[..60] : body);
                    }
                    catch (Exception ex) { _logger.LogWarning(ex, "Preflight GET failed"); }

                    _challengeStore.Put(token, keyAuthz, TimeSpan.FromMinutes(10));
                    await http.Validate();

                    var chDeadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();
                        var chRes = await http.Resource();
                        if (chRes.Status == ChallengeStatus.Valid)
                        {
                            _logger.LogInformation("ACME[{Dir}] challenge VALID for {Host}", Label, host);
                            break;
                        }
                        if (chRes.Status == ChallengeStatus.Invalid)
                            throw new InvalidOperationException($"ACME authorization failed for {host}: {chRes.Error?.Type} {chRes.Error?.Detail}");
                        if (DateTimeOffset.UtcNow > chDeadline)
                            throw new TimeoutException($"ACME challenge timed out for {host}");
                        await Task.Delay(1000, ct);
                    }

                    _challengeStore.Remove(token);
                }

                // 3) Finalize order (poll to READY → finalize → poll to VALID)
                var acctKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
                var csrInfo = new CsrInfo { CommonName = host };

                var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
                var oRes = await order.Resource();
                while (oRes.Status is OrderStatus.Pending or OrderStatus.Processing)
                {
                    if (DateTimeOffset.UtcNow > deadline)
                        throw new TimeoutException($"ACME order not ready for {host} (status={oRes.Status}).");
                    await Task.Delay(1000, ct);
                    oRes = await order.Resource();
                }

                if (oRes.Status != OrderStatus.Valid)
                {
                    await order.Finalize(csrInfo, acctKey);
                }

                deadline = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(2);
                oRes = await order.Resource();
                while (oRes.Status is OrderStatus.Processing or OrderStatus.Pending or OrderStatus.Ready)
                {
                    if (DateTimeOffset.UtcNow > deadline)
                        throw new TimeoutException($"ACME finalize timed out for {host} (status={oRes.Status}).");
                    await Task.Delay(1000, ct);
                    oRes = await order.Resource();
                }
                if (oRes.Status != OrderStatus.Valid)
                    throw new InvalidOperationException($"ACME order did not become valid for {host} (status={oRes.Status}).");

                // 4) Download chain and build PFX WITHOUT using key-bound ToPem
                var chain = await order.Download();

                // PARAMETERLESS ToPem → LEAF+INTERMEDIATES as PEM. No issuer lookup.
                var pemChain = chain.ToPem();

                static IEnumerable<string> SplitPem(string pemAll)
                {
                    const string begin = "-----BEGIN CERTIFICATE-----";
                    const string end = "-----END CERTIFICATE-----";
                    var i = 0;
                    while (true)
                    {
                        var s = pemAll.IndexOf(begin, i, StringComparison.Ordinal);
                        if (s < 0) yield break;
                        var e = pemAll.IndexOf(end, s, StringComparison.Ordinal);
                        if (e < 0) yield break;
                        e += end.Length;
                        yield return pemAll.Substring(s, e - s);
                        i = e;
                    }
                }

                var certs = SplitPem(pemChain).ToList();
                if (certs.Count == 0)
                    throw new InvalidOperationException("ACME returned an empty certificate chain.");

                var leafPem = certs[0];
                var interPem = certs.Skip(1).ToList();

                var leafPublic = X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(leafPem));

                using var ecdsa = ECDsa.Create();
                ecdsa.ImportPkcs8PrivateKey(acctKey.ToDer(), out _);
                var leafWithKey = leafPublic.CopyWithPrivateKey(ecdsa);

                var pfxBuilder = new Pkcs12Builder();

                var leafBag = new Pkcs12SafeContents();
                leafBag.AddCertificate(leafWithKey);
                leafBag.AddShroudedKey(
                    ecdsa,
                    password: "",
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000)
                );
                pfxBuilder.AddSafeContentsUnencrypted(leafBag);

                if (interPem.Count > 0)
                {
                    var interBag = new Pkcs12SafeContents();
                    foreach (var icPem in interPem)
                    {
                        var ic = X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(icPem));
                        interBag.AddCertificate(ic);
                    }
                    pfxBuilder.AddSafeContentsUnencrypted(interBag);
                }

                pfxBuilder.SealWithMac("", HashAlgorithmName.SHA256, 100_000);
                var pfxBytes = pfxBuilder.Encode();

                _logger.LogInformation("ACME[{Dir}] issued PFX for {Host} (len={Len})", Label, host, pfxBytes.Length);
                return X509CertificateLoader.LoadPkcs12(pfxBytes, ReadOnlySpan<char>.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ACME[{Dir}] issuance FAILED for {Host}", Label, host);
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

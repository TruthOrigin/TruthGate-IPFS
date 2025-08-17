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
                // 4) Download the chain
                var chain = await order.Download();

                // === Build PFX without any ToPem/ToPfx usage ===
                var (leafDer, issuersDer) = ExtractDerFromChain(chain);

                // Load leaf (public)
                var leafPublic = X509CertificateLoader.LoadCertificate(leafDer);

                // Import ES256 private key from Certes and bind to leaf
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportPkcs8PrivateKey(acctKey.ToDer(), out _);
                var leafWithKey = leafPublic.CopyWithPrivateKey(ecdsa);

                // Assemble PKCS#12
                var pfxBuilder = new Pkcs12Builder();

                // Bag A: leaf + shrouded private key
                var leafBag = new Pkcs12SafeContents();
                leafBag.AddCertificate(leafWithKey);
                leafBag.AddShroudedKey(
                    ecdsa,
                    password: "", // empty is fine for your server-side storage
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000)
                );
                pfxBuilder.AddSafeContentsUnencrypted(leafBag);

                // Bag B: intermediates
                if (issuersDer.Count > 0)
                {
                    var interBag = new Pkcs12SafeContents();
                    foreach (var der in issuersDer)
                    {
                        var ic = X509CertificateLoader.LoadCertificate(der);
                        interBag.AddCertificate(ic);
                    }
                    pfxBuilder.AddSafeContentsUnencrypted(interBag);
                }

                // Seal & emit
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

        // Pulls leaf + issuer DER certs out of Certes' CertificateChain without calling ToPem().
        private static (byte[] leafDer, List<byte[]> issuersDer) ExtractDerFromChain(object certificateChain)
        {
            var t = certificateChain.GetType();

            // Leaf: property is often "Certificate" or "Leaf"
            var leafObj =
                t.GetProperty("Certificate")?.GetValue(certificateChain)
                ?? t.GetProperty("Leaf")?.GetValue(certificateChain)
                ?? throw new InvalidOperationException("CertificateChain leaf not found.");

            var toDer = leafObj.GetType().GetMethod("ToDer")
                       ?? throw new InvalidOperationException("Leaf.ToDer() not found.");
            var leafDer = (byte[])toDer.Invoke(leafObj, Array.Empty<object>())!;

            // Issuers: property names vary across Certes versions
            var issuerPropNames = new[] { "Chain", "IssuerChain", "IssuerCertificates", "Certificates" };
            var issuersDer = new List<byte[]>();

            foreach (var name in issuerPropNames)
            {
                var p = t.GetProperty(name);
                if (p == null) continue;

                if (p.GetValue(certificateChain) is System.Collections.IEnumerable coll)
                {
                    foreach (var item in coll)
                    {
                        var m = item.GetType().GetMethod("ToDer");
                        if (m == null) continue;
                        var der = (byte[])m.Invoke(item, Array.Empty<object>())!;
                        // Some versions include the leaf again in the list — filter it out
                        if (!der.AsSpan().SequenceEqual(leafDer))
                            issuersDer.Add(der);
                    }
                    break; // we found a valid property
                }
            }

            return (leafDer, issuersDer);
        }

    }
}

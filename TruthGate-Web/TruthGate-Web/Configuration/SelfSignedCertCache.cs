using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace TruthGate_Web.Configuration
{
    public sealed class SelfSignedCertCache
    {
        private readonly X509Certificate2 _cached;
        public SelfSignedCertCache(X509Certificate2 cert) => _cached = cert;
        public X509Certificate2 Get() => _cached;
    }
}

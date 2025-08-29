using Newtonsoft.Json;

namespace TruthGate_Web.Models
{
    public class IpnsSiteKey
    {
        [JsonProperty("IpnsKey")]
        public string IpnsKey { get; set; }
    }
}

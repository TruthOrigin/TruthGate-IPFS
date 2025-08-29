using Newtonsoft.Json;
using System.Text.Json.Serialization;

namespace TruthGate_Web.Models
{
    public class IpnsSiteKey
    {
        [JsonPropertyName("IpnsKey")]
        public string IpnsKey { get; set; }
    }
}

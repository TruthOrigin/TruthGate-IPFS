namespace TruthGate_Web.Models
{
    public class PeersResponse
    {
        public List<SwarmPeer> Peers { get; set; }
    }

    public class SwarmPeer
    {
        public string Addr { get; set; }
        public string Peer { get; set; }
        public Identify Identify { get; set; }
    }

    public class Identify
    {
        public string ID { get; set; }
        public string PublicKey { get; set; }
        public object Addresses { get; set; }
        public string AgentVersion { get; set; }
        public object Protocols { get; set; }
    }
}

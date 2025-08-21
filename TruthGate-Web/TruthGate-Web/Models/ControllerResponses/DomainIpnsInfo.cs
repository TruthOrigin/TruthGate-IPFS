namespace TruthGate_Web.Models.ControllerResponses
{
    public class DomainIpnsInfo
    {
        public string Domain { get; set; } = "";
        public string? IpnsPeerId { get; set; }       // k51...
        public string? TgpCid { get; set; }           // CID of TGP folder
        public string? CurrentCid { get; set; }       // from tgp.json (normalized to bare cid)
        public string? LastPublishedCid { get; set; } // from config (site root)
    }

}

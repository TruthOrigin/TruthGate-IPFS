namespace TruthGate_Web.Models.ControllerResponses
{
    public class DomainIpnsInfo
    {
        public string Domain { get; set; } = "";
        public string? IpnsKeyName { get; set; }
        public string? IpnsPeerId { get; set; }       // k51...
        public string? IpnsPath { get; set; }         // "/ipns/<peerId>"
        public string? TgpFolder { get; set; }        // "/production/pinned/<tgp-leaf>"
        public string? TgpCid { get; set; }           // CID of TGP folder
        public string? CurrentCid { get; set; }       // from tgp.json (normalized to bare cid)
        public string? LastPublishedCid { get; set; } // from config (site root)
        public string? Warning { get; set; }
    }

}

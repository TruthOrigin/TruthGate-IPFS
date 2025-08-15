namespace TruthGate_Web.Models
{
    public sealed class IpfsLsResponse
    {
        public List<IpfsLsObject> Objects { get; set; } = new();
        public sealed class IpfsLsObject
        {
            public string Hash { get; set; } = "";
            public List<IpfsLink> Links { get; set; } = new();
        }
        public sealed class IpfsLink
        {
            public string Name { get; set; } = "";
            public string Hash { get; set; } = "";
            public int Type { get; set; } // 1=dir, 2=file (varies by implementation)
            public long Size { get; set; }
        }
    }

}

namespace TruthGate_Web.Models
{
    public sealed class PortOptions
    {
        public int Http { get; set; } = 5000;  // default if not set
        public int Https { get; set; } = 5001; // default if not set
    }
}

namespace TruthGate_Web.Models
{
    public sealed class SecurityOptions
    {
        public List<AppUser> Users { get; set; } = new();
        public List<string> Keys { get; set; } = new();
    }
}

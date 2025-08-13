namespace TruthGate_Web.Models
{
    public sealed class DomainListOptions
    {
        public List<string> Domains { get; set; } = new();

        // Dev-only host emulation; when set in Development, we treat all requests as if from this host
        public string? DevEmulateHost { get; set; }
    }

}

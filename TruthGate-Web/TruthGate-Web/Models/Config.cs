namespace TruthGate_Web.Models
{
    public class Config
    {
        public const string DefaultAdminHash = "/EUxvODjrpkTKnal6nVEAh2m+52H4OgXGEBLcE3xilcgZ8gbeE5ay/CfzYr9PCJ0";
        private List<UserAccount>? _users;

        public List<EdgeDomains> Domains { get; set; } = new List<EdgeDomains>();
        public List<ApiKey> ApiKeys { get; set; } = new List<ApiKey>();

        public List<UserAccount> Users
        {
            get
            {
                _users ??= new List<UserAccount>();

                // Normalize all existing entries
                foreach (var u in _users)
                {
                    u.UserName = (u.UserName ?? string.Empty).Trim().ToLowerInvariant();
                    u.PasswordHashed = (u.PasswordHashed ?? string.Empty).Trim();
                }

                // Ensure an admin exists (case-insensitive; after normalization, direct compare)
                bool hasAdmin = _users.Any(u => u.UserName == "admin");
                if (!hasAdmin)
                {
                    _users.Add(new UserAccount
                    {
                        UserName = "admin",
                        PasswordHashed = DefaultAdminHash
                    });
                }

                return _users;
            }
            set
            {
                // Accept incoming list but store a copy (avoid external reference surprises)
                _users = value is null ? new List<UserAccount>() : new List<UserAccount>(value);
            }
        }
    }

    public class EdgeDomains
    {
        public string Domain { get; set; }
    }

    public class ApiKey
    {
        public string Name { get; set; }
        public string KeyHashed { get; set; }
    }
    public class UserAccount
    {
        public string UserName { get; set; }
        public string PasswordHashed { get; set; }
    }
}

namespace TruthGate_Web.Models
{
    public class Config
    {
        public const string DefaultAdminHash = "/EUxvODjrpkTKnal6nVEAh2m+52H4OgXGEBLcE3xilcgZ8gbeE5ay/CfzYr9PCJ0";
        private List<UserAccount>? _users;
        public IpnsWildCardSubDomain IpnsWildCardSubDomain { get; set; }
        public List<EdgeDomain> Domains { get; set; } = new List<EdgeDomain>();
        public List<ApiKey> ApiKeys { get; set; } = new List<ApiKey>();
        public List<IpnsKey> IpnsKeys { get; set; } = new List<IpnsKey>();

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

    public class IpnsWildCardSubDomain
    {
        public string WildCardSubDomain { get; set; } = "";
        public string UseSSL { get; set; } = "true";
    }

        public class EdgeDomain
    {
        public string Domain { get; set; } = "";
        public string UseSSL { get; set; } = "false";
        public string? RedirectUrl { get; set; }

        // NEW: site/TGP wiring
        public string SiteFolderLeaf { get; set; } = "";         // e.g., "example.com"
        public string TgpFolderLeaf { get; set; } = "";          // e.g., "tgp-example-com"
        public string IpnsKeyName { get; set; } = "";            // key name in node keystore
        public string IpnsPeerId { get; set; } = "";             // returned from key/gen or import
        public string? LastPublishedCid { get; set; }
        public DateTimeOffset? LastPublishedAt { get; set; }

        // NEW: encrypted private key (for backup/import)
        // We store an armored/exported key protected by a user passphrase.
        public int? IpnsKeyEncVersion { get; set; }              // 1 = AES-GCM + scrypt
        public string? IpnsKeySaltB64 { get; set; }              // per-domain random salt
        public string? IpnsKeyCipherB64 { get; set; }            // sealed secret
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

    public class IpnsKey
    {
        public string Key { get; set; }
        public string Name { get; set; }
        public string CurrentCID { get; set; }
        public bool AutoUpdateToPin { get; set; }
        public bool KeepOldCidPinned { get; set; }
    }
}

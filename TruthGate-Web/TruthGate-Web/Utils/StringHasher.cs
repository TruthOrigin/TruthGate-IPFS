using System.Security.Cryptography;

namespace TruthGate_Web.Utils
{
    public static class StringHasher
    {
        // Generates a salted hash from a plain text string
        public static string HashString(string input)
        {
            // Generate a cryptographically secure salt
            byte[] saltBytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }

            // Derive the hash using PBKDF2
            using (var pbkdf2 = new Rfc2898DeriveBytes(input, saltBytes, 100000, HashAlgorithmName.SHA256))
            {
                byte[] hashBytes = pbkdf2.GetBytes(32); // 256-bit hash

                // Combine salt + hash into one string (Base64)
                byte[] combinedBytes = new byte[saltBytes.Length + hashBytes.Length];
                Buffer.BlockCopy(saltBytes, 0, combinedBytes, 0, saltBytes.Length);
                Buffer.BlockCopy(hashBytes, 0, combinedBytes, saltBytes.Length, hashBytes.Length);

                return Convert.ToBase64String(combinedBytes);
            }
        }

        // Verifies whether the given plain text matches the stored hash
        public static bool VerifyHash(string input, string storedHash)
        {
            byte[] combinedBytes = Convert.FromBase64String(storedHash);

            // Extract salt (first 16 bytes)
            byte[] saltBytes = new byte[16];
            Buffer.BlockCopy(combinedBytes, 0, saltBytes, 0, 16);

            // Extract hash (remaining bytes)
            byte[] storedHashBytes = new byte[combinedBytes.Length - 16];
            Buffer.BlockCopy(combinedBytes, 16, storedHashBytes, 0, storedHashBytes.Length);

            // Hash the input with the same salt
            using (var pbkdf2 = new Rfc2898DeriveBytes(input, saltBytes, 100000, HashAlgorithmName.SHA256))
            {
                byte[] computedHash = pbkdf2.GetBytes(32);

                // Compare byte-by-byte in constant time
                return CryptographicOperations.FixedTimeEquals(storedHashBytes, computedHash);
            }
        }
    }
}

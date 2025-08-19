using System.Security.Cryptography;
using System.Text;
using Norgerman.Cryptography.Scrypt;

namespace TruthGate_Web.Utils
{
    public static class CryptoBox
    {
        // sizes
        private const int SaltLen = 16;
        private const int NonceLen = 12; // AES-GCM standard nonce
        private const int TagLen = 16;   // AES-GCM 128-bit tag
        private const int KeyLen = 32;   // AES-256

        // scrypt params (tune as needed)
        private const int N = 1 << 14; // 16384
        private const int R = 8;
        private const int P = 1;

        // AES-GCM with scrypt KDF. Returns (saltB64, cipherB64)
        public static (string saltB64, string cipherB64) Seal(string plaintext, string passphrase)
        {
            Span<byte> salt = stackalloc byte[SaltLen];
            RandomNumberGenerator.Fill(salt);

            var key = ScryptUtil.Scrypt(Encoding.UTF8.GetBytes(passphrase), salt.ToArray(), N, R, P, KeyLen);

            Span<byte> nonce = stackalloc byte[NonceLen];
            RandomNumberGenerator.Fill(nonce);

            var pt = Encoding.UTF8.GetBytes(plaintext);
            var ct = new byte[pt.Length];
            Span<byte> tag = stackalloc byte[TagLen];

            using var gcm = new AesGcm(key);
            gcm.Encrypt(nonce, pt, ct, tag);

            var payload = new byte[NonceLen + ct.Length + TagLen];
            nonce.CopyTo(payload.AsSpan(0, NonceLen));
            ct.AsSpan().CopyTo(payload.AsSpan(NonceLen));
            tag.CopyTo(payload.AsSpan(NonceLen + ct.Length));

            CryptographicOperations.ZeroMemory(key);
            return (Convert.ToBase64String(salt), Convert.ToBase64String(payload));
        }

        public static string Open(string saltB64, string cipherB64, string passphrase)
        {
            var salt = Convert.FromBase64String(saltB64);
            var payload = Convert.FromBase64String(cipherB64);

            if (payload.Length < NonceLen + TagLen)
                throw new FormatException("Cipher payload too short.");

            var key = ScryptUtil.Scrypt(Encoding.UTF8.GetBytes(passphrase), salt, N, R, P, KeyLen);

            var nonce = payload.AsSpan(0, NonceLen);
            var ct = payload.AsSpan(NonceLen, payload.Length - NonceLen - TagLen);
            var tag = payload.AsSpan(payload.Length - TagLen, TagLen);

            var pt = new byte[ct.Length];

            try
            {
                using var gcm = new AesGcm(key);
                gcm.Decrypt(nonce, ct, tag, pt);
            }
            catch (CryptographicException)
            {
                throw new UnauthorizedAccessException("Decryption failed (wrong passphrase or corrupted data).");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }

            return Encoding.UTF8.GetString(pt);
        }
    }

}

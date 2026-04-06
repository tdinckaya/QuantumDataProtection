using System.Security.Cryptography;
using System.Text;

namespace QuantumDataProtection;

/// <summary>
/// Cross-platform key encryption using PBKDF2 + AES-256-GCM.
/// Used by both native and BouncyCastle providers for consistent
/// encrypted key storage format.
/// </summary>
internal static class KeyEncryptionHelper
{
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int Iterations = 100_000;
    private static readonly byte[] Header = "QDPK1"u8.ToArray(); // QuantumDataProtection Key v1

    /// <summary>
    /// Encrypts raw key bytes with a password using PBKDF2 + AES-256-GCM.
    /// Format: [QDPK1][algNameLen][algName][salt][nonce][tag][ciphertext]
    /// </summary>
    public static byte[] Encrypt(string password, byte[] rawKey, string algorithmName)
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);

        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[rawKey.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(derivedKey, tagSizeInBytes: TagSize);
        aes.Encrypt(nonce, rawKey, ciphertext, tag);

        CryptographicOperations.ZeroMemory(derivedKey);

        // Pack: header + algNameLen(1) + algName + salt + nonce + tag + ciphertext
        var algBytes = Encoding.UTF8.GetBytes(algorithmName);
        var result = new byte[Header.Length + 1 + algBytes.Length + SaltSize + NonceSize + TagSize + ciphertext.Length];
        var offset = 0;

        Buffer.BlockCopy(Header, 0, result, offset, Header.Length); offset += Header.Length;
        result[offset++] = (byte)algBytes.Length;
        Buffer.BlockCopy(algBytes, 0, result, offset, algBytes.Length); offset += algBytes.Length;
        Buffer.BlockCopy(salt, 0, result, offset, SaltSize); offset += SaltSize;
        Buffer.BlockCopy(nonce, 0, result, offset, NonceSize); offset += NonceSize;
        Buffer.BlockCopy(tag, 0, result, offset, TagSize); offset += TagSize;
        Buffer.BlockCopy(ciphertext, 0, result, offset, ciphertext.Length);

        return result;
    }

    /// <summary>
    /// Decrypts key bytes encrypted by <see cref="Encrypt"/>.
    /// Returns (rawKey, algorithmName).
    /// </summary>
    public static (byte[] RawKey, string AlgorithmName) Decrypt(string password, byte[] encrypted)
    {
        var offset = 0;

        // Verify header
        for (var i = 0; i < Header.Length; i++)
        {
            if (encrypted[offset++] != Header[i])
                throw new CryptographicException("Invalid encrypted key format (bad header).");
        }

        var algLen = encrypted[offset++];
        var algName = Encoding.UTF8.GetString(encrypted, offset, algLen); offset += algLen;

        var salt = new byte[SaltSize];
        Buffer.BlockCopy(encrypted, offset, salt, 0, SaltSize); offset += SaltSize;

        var nonce = new byte[NonceSize];
        Buffer.BlockCopy(encrypted, offset, nonce, 0, NonceSize); offset += NonceSize;

        var tag = new byte[TagSize];
        Buffer.BlockCopy(encrypted, offset, tag, 0, TagSize); offset += TagSize;

        var ciphertextLen = encrypted.Length - offset;
        var ciphertext = new byte[ciphertextLen];
        Buffer.BlockCopy(encrypted, offset, ciphertext, 0, ciphertextLen);

        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, Iterations, HashAlgorithmName.SHA256, 32);

        var plaintext = new byte[ciphertextLen];

        try
        {
            using var aes = new AesGcm(derivedKey, tagSizeInBytes: TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return (plaintext, algName);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedKey);
        }
    }
}

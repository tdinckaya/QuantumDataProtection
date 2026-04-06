using System.Security.Cryptography;

namespace QuantumDataProtection;

/// <summary>
/// Internal abstraction for ML-KEM key operations.
/// Allows switching between native .NET 10 and BouncyCastle implementations.
/// </summary>
internal interface IMlKemKeyOperations : IDisposable
{
    string KeyId { get; }
    bool HasDecapsulationKey { get; }
    string ProviderName { get; }
    (byte[] SharedSecret, byte[] Ciphertext) Encapsulate();
    byte[] Decapsulate(byte[] ciphertext);
    byte[] ExportEncapsulationKey();
    byte[] ExportDecapsulationKey();
    byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParams);
}

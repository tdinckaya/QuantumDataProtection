using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;

namespace QuantumDataProtection;

/// <summary>
/// <see cref="IXmlDecryptor"/> that decrypts Data Protection XML keys
/// encrypted by <see cref="MlKemXmlEncryptor"/>.
/// </summary>
public sealed class MlKemXmlDecryptor : IXmlDecryptor
{
    private readonly IKeyStore _keyStore;
    private readonly string _pkcs8Password;

    /// <summary>
    /// Initializes a new <see cref="MlKemXmlDecryptor"/>.
    /// </summary>
    public MlKemXmlDecryptor(IServiceProvider services)
    {
        var options = services.GetRequiredService<MlKemDataProtectionOptions>();
        _keyStore = options.ResolveKeyStore();
        _pkcs8Password = options.ResolvePkcs8Password();
    }

    /// <summary>
    /// Decrypts an XML element that was encrypted by <see cref="MlKemXmlEncryptor"/>.
    /// </summary>
    public XElement Decrypt(XElement encryptedElement)
    {
        // Parse XML
        var algorithmStr = encryptedElement.Element("algorithm")?.Value
            ?? throw new CryptographicException("Missing 'algorithm' element.");
        var keyId = encryptedElement.Element("keyId")?.Value
            ?? throw new CryptographicException("Missing 'keyId' element.");
        var kemCiphertext = Convert.FromBase64String(
            encryptedElement.Element("kemCiphertext")?.Value
            ?? throw new CryptographicException("Missing 'kemCiphertext' element."));
        var nonce = Convert.FromBase64String(
            encryptedElement.Element("nonce")?.Value
            ?? throw new CryptographicException("Missing 'nonce' element."));
        var ciphertext = Convert.FromBase64String(
            encryptedElement.Element("ciphertext")?.Value
            ?? throw new CryptographicException("Missing 'ciphertext' element."));
        var tag = Convert.FromBase64String(
            encryptedElement.Element("tag")?.Value
            ?? throw new CryptographicException("Missing 'tag' element."));

        // Validate algorithm
        if (!MlKemAlgorithms.All.Contains(algorithmStr))
            throw new CryptographicException(
                $"Unsupported ML-KEM algorithm '{algorithmStr}'. " +
                $"Supported: {string.Join(", ", MlKemAlgorithms.All)}");

        // Load decapsulation key from store
        var encryptedDecapKey = _keyStore.LoadPrivateKeyAsync(keyId)
            .GetAwaiter().GetResult()
            ?? throw new CryptographicException($"Decapsulation key '{keyId}' not found in key store.");

        // Import the decapsulation key (using user's password, not hardcoded)
        using var mlKem = MLKem.ImportEncryptedPkcs8PrivateKey(_pkcs8Password, encryptedDecapKey);

        // Decapsulate → shared secret
        var sharedSecret = mlKem.Decapsulate(kemCiphertext);

        try
        {
            // AES-256-GCM decrypt
            var plaintext = new byte[ciphertext.Length];

            try
            {
                using var aes = new AesGcm(sharedSecret, tagSizeInBytes: 16);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);

                var xml = System.Text.Encoding.UTF8.GetString(plaintext);
                return XElement.Parse(xml);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}

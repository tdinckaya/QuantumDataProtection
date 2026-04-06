using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;

namespace QuantumDataProtection;

/// <summary>
/// <see cref="IXmlEncryptor"/> that protects Data Protection XML keys using
/// ML-KEM (FIPS 203) key encapsulation + AES-256-GCM symmetric encryption.
/// </summary>
public sealed class MlKemXmlEncryptor : IXmlEncryptor
{
    private readonly MlKemDataProtectionOptions _options;
    private readonly IKeyStore _keyStore;
    private readonly string _pkcs8Password;
    private readonly ILogger? _logger;

    /// <summary>
    /// Initializes a new <see cref="MlKemXmlEncryptor"/>.
    /// </summary>
    public MlKemXmlEncryptor(MlKemDataProtectionOptions options, ILoggerFactory? loggerFactory = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _keyStore = options.ResolveKeyStore();
        _pkcs8Password = options.ResolvePkcs8Password();
        _logger = loggerFactory?.CreateLogger<MlKemXmlEncryptor>();
    }

    /// <summary>
    /// Encrypts the given XML element using ML-KEM + AES-256-GCM.
    /// </summary>
    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        var plaintext = System.Text.Encoding.UTF8.GetBytes(plaintextElement.ToString());

        try
        {
            using var kemKey = MlKemKey.Generate(_options.Algorithm, _logger);

            var (sharedSecret, kemCiphertext) = kemKey.Encapsulate();

            try
            {
                var nonce = new byte[12];
                RandomNumberGenerator.Fill(nonce);

                var ciphertext = new byte[plaintext.Length];
                var tag = new byte[16];

                using var aes = new AesGcm(sharedSecret, tagSizeInBytes: 16);
                aes.Encrypt(nonce, plaintext, ciphertext, tag);

                var encryptedDecapKey = kemKey.ExportEncryptedKey(_pkcs8Password, _options.Algorithm);

                _keyStore.SavePrivateKeyAsync(kemKey.KeyId, encryptedDecapKey)
                    .GetAwaiter().GetResult();

                _logger?.LogDebug("XML key encrypted with ML-KEM. KeyId={KeyId}, Provider={Provider}",
                    kemKey.KeyId, kemKey.ProviderName);

                var algName = MlKemAlgorithms.ToAlgorithmString(_options.Algorithm);

                var encryptedElement = new XElement("mlKemEncryptedKey",
                    new XElement("algorithm", algName),
                    new XElement("keyId", kemKey.KeyId),
                    new XElement("kemCiphertext", Convert.ToBase64String(kemCiphertext)),
                    new XElement("nonce", Convert.ToBase64String(nonce)),
                    new XElement("ciphertext", Convert.ToBase64String(ciphertext)),
                    new XElement("tag", Convert.ToBase64String(tag)));

                return new EncryptedXmlInfo(encryptedElement, typeof(MlKemXmlDecryptor));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

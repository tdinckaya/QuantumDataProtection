using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace QuantumDataProtection;

/// <summary>
/// <see cref="IXmlDecryptor"/> that handles both ML-KEM-encrypted and legacy
/// RSA/DPAPI-encrypted Data Protection XML keys.
/// <para>
/// Routes decryption based on the XML element name:
/// <list type="bullet">
///   <item><c>mlKemEncryptedKey</c> → <see cref="MlKemXmlDecryptor"/></item>
///   <item>Anything else → legacy decryptor (RSA/DPAPI/custom)</item>
/// </list>
/// </para>
/// </summary>
public sealed class HybridXmlDecryptor : IXmlDecryptor
{
    private readonly MlKemXmlDecryptor _mlKemDecryptor;
    private readonly IXmlDecryptor? _fallbackDecryptor;
    private readonly ILogger? _logger;

    /// <summary>
    /// Initializes a new <see cref="HybridXmlDecryptor"/>.
    /// </summary>
    public HybridXmlDecryptor(IServiceProvider services)
    {
        _mlKemDecryptor = new MlKemXmlDecryptor(services);
        _logger = services.GetService<ILoggerFactory>()?.CreateLogger<HybridXmlDecryptor>();

        var options = services.GetRequiredService<MlKemDataProtectionOptions>();

        if (options.LegacyDecryptorType is not null)
        {
            _fallbackDecryptor = (IXmlDecryptor)ActivatorUtilities.CreateInstance(
                services, options.LegacyDecryptorType);
        }
    }

    /// <summary>
    /// Decrypts an XML element, routing to the correct decryptor based on format.
    /// </summary>
    public XElement Decrypt(XElement encryptedElement)
    {
        if (encryptedElement.Name.LocalName == "mlKemEncryptedKey")
            return _mlKemDecryptor.Decrypt(encryptedElement);

        if (_fallbackDecryptor is not null)
        {
            _logger?.LogWarning(
                "Legacy decryptor used for key element '{ElementName}'. " +
                "Consider re-encrypting with ML-KEM after all legacy keys expire.",
                encryptedElement.Name.LocalName);
            return _fallbackDecryptor.Decrypt(encryptedElement);
        }

        _logger?.LogError(
            "Cannot decrypt element '{ElementName}': not ML-KEM and no legacy decryptor configured.",
            encryptedElement.Name.LocalName);

        throw new CryptographicException(
            "Cannot decrypt: the XML key is not ML-KEM encrypted and no legacy decryptor is configured. " +
            "If migrating from RSA/DPAPI, set LegacyDecryptorType in ProtectKeysWithMlKem options. " +
            "Example: options.LegacyDecryptorType = typeof(CertificateXmlDecryptor);");
    }
}

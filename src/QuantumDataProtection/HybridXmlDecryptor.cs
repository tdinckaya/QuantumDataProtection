using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;

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
/// <para>
/// This enables zero-downtime migration: deploy the package and all existing
/// cookies/sessions continue working. New keys are wrapped with ML-KEM,
/// old keys are still readable via the fallback decryptor.
/// </para>
/// </summary>
public sealed class HybridXmlDecryptor : IXmlDecryptor
{
    private readonly MlKemXmlDecryptor _mlKemDecryptor;
    private readonly IXmlDecryptor? _fallbackDecryptor;

    /// <summary>
    /// Initializes a new <see cref="HybridXmlDecryptor"/>.
    /// </summary>
    public HybridXmlDecryptor(IServiceProvider services)
    {
        _mlKemDecryptor = new MlKemXmlDecryptor(services);

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
        // ML-KEM encrypted keys use our custom element name
        if (encryptedElement.Name.LocalName == "mlKemEncryptedKey")
            return _mlKemDecryptor.Decrypt(encryptedElement);

        // Legacy key — use fallback decryptor
        if (_fallbackDecryptor is not null)
            return _fallbackDecryptor.Decrypt(encryptedElement);

        throw new CryptographicException(
            "Cannot decrypt: the XML key is not ML-KEM encrypted and no legacy decryptor is configured. " +
            "If migrating from RSA/DPAPI, set LegacyDecryptorType in ProtectKeysWithMlKem options. " +
            "Example: options.LegacyDecryptorType = typeof(CertificateXmlDecryptor);");
    }
}

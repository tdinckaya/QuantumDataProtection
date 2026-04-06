using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;

namespace QuantumDataProtection;

/// <summary>
/// Extension methods for integrating ML-KEM key wrapping into ASP.NET Core Data Protection.
/// </summary>
public static class MlKemDataProtectionExtensions
{
    /// <summary>
    /// Configures Data Protection to encrypt new XML keys using ML-KEM (FIPS 203)
    /// key encapsulation + AES-256-GCM.
    /// <para>
    /// By default, existing RSA/DPAPI-wrapped keys remain readable via
    /// <see cref="HybridXmlDecryptor"/>. Set <see cref="MlKemDataProtectionOptions.LegacyDecryptorType"/>
    /// to your previous decryptor type for seamless migration.
    /// </para>
    /// </summary>
    /// <example>
    /// <code>
    /// // New project (no legacy keys):
    /// builder.Services.AddDataProtection()
    ///     .ProtectKeysWithMlKem(options =>
    ///     {
    ///         options.Algorithm = MLKemAlgorithm.MLKem768;
    ///         options.KeyStoreDirectory = "/var/keys";
    ///         options.KeyStorePassword = config["KeyPassword"];
    ///     });
    ///
    /// // Migration from certificate-based protection:
    /// builder.Services.AddDataProtection()
    ///     .ProtectKeysWithMlKem(options =>
    ///     {
    ///         options.Algorithm = MLKemAlgorithm.MLKem768;
    ///         options.KeyStoreDirectory = "/var/keys";
    ///         options.KeyStorePassword = config["KeyPassword"];
    ///         options.LegacyDecryptorType = typeof(CertificateXmlDecryptor);
    ///     });
    /// </code>
    /// </example>
    public static IDataProtectionBuilder ProtectKeysWithMlKem(
        this IDataProtectionBuilder builder,
        Action<MlKemDataProtectionOptions> configure)
    {
        var options = new MlKemDataProtectionOptions();
        configure(options);

        // Register options as singleton for encryptor, decryptor, and hybrid
        builder.Services.AddSingleton(options);

        // Always encrypt new keys with ML-KEM
        builder.Services.AddSingleton<IXmlEncryptor>(sp => new MlKemXmlEncryptor(options));

        // Decryptor: hybrid (ML-KEM + legacy fallback) or pure ML-KEM
        if (options.EnableLegacyKeyDecryption)
            builder.Services.AddSingleton<IXmlDecryptor, HybridXmlDecryptor>();
        else
            builder.Services.AddSingleton<IXmlDecryptor, MlKemXmlDecryptor>();

        return builder;
    }
}

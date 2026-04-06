using System.Security.Cryptography;

namespace QuantumDataProtection;

/// <summary>
/// Configuration options for ML-KEM based Data Protection key wrapping.
/// </summary>
public sealed class MlKemDataProtectionOptions
{
    private IKeyStore? _resolvedKeyStore;

    /// <summary>
    /// The ML-KEM algorithm variant. Defaults to ML-KEM-768 (recommended).
    /// </summary>
    public MLKemAlgorithm Algorithm { get; set; } = MLKemAlgorithm.MLKem768;

    /// <summary>
    /// Custom <see cref="IKeyStore"/> for storing decapsulation keys.
    /// If set, <see cref="KeyStoreDirectory"/> and <see cref="KeyStorePassword"/> are ignored.
    /// </summary>
    public IKeyStore? KeyStore { get; set; }

    /// <summary>
    /// Directory for the built-in <see cref="FileKeyStore"/>.
    /// Used only if <see cref="KeyStore"/> is null.
    /// </summary>
    public string? KeyStoreDirectory { get; set; }

    /// <summary>
    /// Password for encrypting/decrypting decapsulation keys stored via <see cref="FileKeyStore"/>
    /// and for PKCS#8 private key encryption at rest.
    /// <para>
    /// <b>Required.</b> This password protects the ML-KEM decapsulation keys on disk.
    /// Do not hardcode — load from a secret manager or environment variable.
    /// </para>
    /// </summary>
    public string? KeyStorePassword { get; set; }

    /// <summary>
    /// When <c>true</c> (default), existing RSA/DPAPI-wrapped keys can still be decrypted
    /// using a fallback decryptor. New keys are always wrapped with ML-KEM.
    /// <para>
    /// Set to <c>false</c> only after all legacy keys have expired or been re-encrypted.
    /// </para>
    /// </summary>
    public bool EnableLegacyKeyDecryption { get; set; } = true;

    /// <summary>
    /// The legacy <see cref="Microsoft.AspNetCore.DataProtection.XmlEncryption.IXmlDecryptor"/>
    /// type to use for decrypting pre-existing RSA/DPAPI-wrapped keys.
    /// <para>
    /// Only used when <see cref="EnableLegacyKeyDecryption"/> is <c>true</c>.
    /// If null, the <see cref="HybridXmlDecryptor"/> will attempt to resolve any
    /// previously registered <c>IXmlDecryptor</c> from the service provider.
    /// </para>
    /// <para>
    /// Common values: <c>typeof(CertificateXmlDecryptor)</c>, <c>typeof(DpapiNGXmlDecryptor)</c>.
    /// </para>
    /// </summary>
    public Type? LegacyDecryptorType { get; set; }

    /// <summary>
    /// Resolves the <see cref="IKeyStore"/> from the configured options.
    /// Returns a cached instance on subsequent calls.
    /// </summary>
    internal IKeyStore ResolveKeyStore()
    {
        if (_resolvedKeyStore is not null)
            return _resolvedKeyStore;

        if (KeyStore is not null)
        {
            _resolvedKeyStore = KeyStore;
            return _resolvedKeyStore;
        }

        if (string.IsNullOrEmpty(KeyStoreDirectory) || string.IsNullOrEmpty(KeyStorePassword))
            throw new InvalidOperationException(
                "Either set KeyStore directly, or provide both KeyStoreDirectory and KeyStorePassword.");

        _resolvedKeyStore = new FileKeyStore(KeyStoreDirectory, KeyStorePassword);
        return _resolvedKeyStore;
    }

    /// <summary>
    /// Returns the password used for PKCS#8 encryption of decapsulation keys.
    /// </summary>
    internal string ResolvePkcs8Password()
    {
        if (string.IsNullOrEmpty(KeyStorePassword))
            throw new InvalidOperationException(
                "KeyStorePassword is required for PKCS#8 encryption of decapsulation keys.");

        return KeyStorePassword;
    }
}

namespace QuantumDataProtection;

/// <summary>
/// Configuration options for ML-KEM based Data Protection key wrapping.
/// </summary>
public sealed class MlKemDataProtectionOptions
{
    private IKeyStore? _resolvedKeyStore;

    /// <summary>
    /// The ML-KEM algorithm variant. Defaults to ML-KEM-768 (recommended).
    /// Use <see cref="MlKemAlgorithms"/> constants.
    /// </summary>
    public string Algorithm { get; set; } = MlKemAlgorithms.MlKem768;

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
    /// Password for encrypting/decrypting decapsulation keys.
    /// <para>
    /// <b>Required.</b> Do not hardcode — load from a secret manager or environment variable.
    /// </para>
    /// </summary>
    public string? KeyStorePassword { get; set; }

    /// <summary>
    /// When <c>true</c> (default), existing RSA/DPAPI-wrapped keys can still be decrypted.
    /// </summary>
    public bool EnableLegacyKeyDecryption { get; set; } = true;

    /// <summary>
    /// The legacy decryptor type for pre-existing RSA/DPAPI-wrapped keys.
    /// </summary>
    public Type? LegacyDecryptorType { get; set; }

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

    internal string ResolvePkcs8Password()
    {
        if (string.IsNullOrEmpty(KeyStorePassword))
            throw new InvalidOperationException(
                "KeyStorePassword is required for encryption of decapsulation keys.");

        return KeyStorePassword;
    }
}

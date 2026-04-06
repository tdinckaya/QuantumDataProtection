#pragma warning disable SYSLIB5006

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace QuantumDataProtection;

/// <summary>
/// ML-KEM key wrapper that automatically selects the best available provider:
/// native .NET 10 on Windows/Linux, BouncyCastle fallback on macOS and older platforms.
/// </summary>
public sealed class MlKemKey : IDisposable
{
    private readonly IMlKemKeyOperations _ops;
    private bool _disposed;

    private MlKemKey(IMlKemKeyOperations ops)
    {
        _ops = ops;
    }

    /// <summary>Unique key identifier derived from encapsulation key hash.</summary>
    public string KeyId => _ops.KeyId;

    /// <summary>Whether this key can perform decapsulation (has private key).</summary>
    public bool HasDecapsulationKey => _ops.HasDecapsulationKey;

    /// <summary>The crypto provider being used ("Native (.NET 10)" or "BouncyCastle").</summary>
    public string ProviderName => _ops.ProviderName;

    /// <summary>The underlying operations (for internal use by encryptor/decryptor).</summary>
    internal IMlKemKeyOperations Operations => _ops;

    // ── Static factory methods ───────────────────────────────────

    /// <summary>
    /// Generates a new ML-KEM key pair. Automatically selects native or BouncyCastle provider.
    /// </summary>
    public static MlKemKey Generate(MLKemAlgorithm? algorithm = null, ILogger? logger = null)
    {
        var alg = algorithm ?? MLKemAlgorithm.MLKem768;
        var algName = MlKemAlgorithms.ToAlgorithmString(alg);

        IMlKemKeyOperations ops;

        if (MLKem.IsSupported)
        {
            ops = NativeMlKemOperations.Generate(alg);
        }
        else
        {
            logger?.LogInformation("ML-KEM native not supported. Using BouncyCastle fallback.");
            ops = BouncyCastleMlKemOperations.Generate(algName);
        }

        logger?.LogInformation("ML-KEM key generated. KeyId={KeyId}, Algorithm={Algorithm}, Provider={Provider}",
            ops.KeyId, algName, ops.ProviderName);

        return new MlKemKey(ops);
    }

    /// <summary>
    /// Creates a key from an exported encapsulation key (encapsulate only).
    /// </summary>
    public static MlKemKey FromEncapsulationKey(byte[] encapsulationKey, MLKemAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(encapsulationKey);
        var algName = MlKemAlgorithms.ToAlgorithmString(algorithm);

        var ops = MLKem.IsSupported
            ? (IMlKemKeyOperations)NativeMlKemOperations.FromEncapsulationKey(encapsulationKey, algorithm)
            : BouncyCastleMlKemOperations.FromEncapsulationKey(encapsulationKey, algName);

        return new MlKemKey(ops);
    }

    /// <summary>
    /// Creates a key from an exported decapsulation key (decapsulate).
    /// </summary>
    public static MlKemKey FromDecapsulationKey(byte[] decapsulationKey, MLKemAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(decapsulationKey);
        var algName = MlKemAlgorithms.ToAlgorithmString(algorithm);

        var ops = MLKem.IsSupported
            ? (IMlKemKeyOperations)NativeMlKemOperations.FromDecapsulationKey(decapsulationKey, algorithm)
            : BouncyCastleMlKemOperations.FromDecapsulationKey(decapsulationKey, algName);

        return new MlKemKey(ops);
    }

    /// <summary>
    /// Creates a key from an encrypted PKCS#8 private key.
    /// </summary>
    internal static MlKemKey FromEncryptedPkcs8(string password, byte[] encryptedKey)
    {
        var ops = MLKem.IsSupported
            ? (IMlKemKeyOperations)NativeMlKemOperations.FromEncryptedPkcs8(password, encryptedKey)
            : BouncyCastleMlKemOperations.FromEncryptedPkcs8(password, encryptedKey);

        return new MlKemKey(ops);
    }

    // ── KEM operations ───────────────────────────────────────────

    /// <summary>
    /// Encapsulates a shared secret. Returns the shared secret and ciphertext.
    /// </summary>
    public (byte[] SharedSecret, byte[] Ciphertext) Encapsulate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ops.Encapsulate();
    }

    /// <summary>
    /// Decapsulates a shared secret from ciphertext.
    /// </summary>
    public byte[] Decapsulate(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ops.Decapsulate(ciphertext);
    }

    // ── Export methods ───────────────────────────────────────────

    /// <summary>Exports the encapsulation (public) key.</summary>
    public byte[] ExportEncapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ops.ExportEncapsulationKey();
    }

    /// <summary>Exports the decapsulation (private) key.</summary>
    public byte[] ExportDecapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ops.ExportDecapsulationKey();
    }

    /// <summary>Exports the private key as encrypted PKCS#8.</summary>
    internal byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParams)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ops.ExportEncryptedPkcs8PrivateKey(password, pbeParams);
    }

    // ── IDisposable ──────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _ops.Dispose();
    }
}

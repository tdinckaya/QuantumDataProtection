using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace QuantumDataProtection;

/// <summary>
/// ML-KEM key wrapper that automatically selects the best available provider:
/// native .NET 10 on Windows/Linux, BouncyCastle fallback on all other platforms.
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

    internal IMlKemKeyOperations Operations => _ops;

    // ── Static factory methods ───────────────────────────────────

    /// <summary>
    /// Generates a new ML-KEM key pair. Automatically selects native or BouncyCastle provider.
    /// </summary>
    /// <param name="algorithm">Algorithm name. Use <see cref="MlKemAlgorithms"/> constants. Defaults to ML-KEM-768.</param>
    /// <param name="logger">Optional logger.</param>
    public static MlKemKey Generate(string? algorithm = null, ILogger? logger = null)
    {
        var algName = algorithm ?? MlKemAlgorithms.MlKem768;
        MlKemAlgorithms.Validate(algName);

        IMlKemKeyOperations ops;

#if NET10_0_OR_GREATER
        if (System.Security.Cryptography.MLKem.IsSupported)
        {
            ops = NativeMlKemOperations.Generate(MlKemAlgorithms.ToMLKemAlgorithm(algName));
        }
        else
#endif
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
    public static MlKemKey FromEncapsulationKey(byte[] encapsulationKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(encapsulationKey);
        MlKemAlgorithms.Validate(algorithm);

#if NET10_0_OR_GREATER
        if (System.Security.Cryptography.MLKem.IsSupported)
            return new MlKemKey(NativeMlKemOperations.FromEncapsulationKey(
                encapsulationKey, MlKemAlgorithms.ToMLKemAlgorithm(algorithm)));
#endif
        return new MlKemKey(BouncyCastleMlKemOperations.FromEncapsulationKey(encapsulationKey, algorithm));
    }

    /// <summary>
    /// Creates a key from an exported decapsulation key (decapsulate).
    /// </summary>
    public static MlKemKey FromDecapsulationKey(byte[] decapsulationKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(decapsulationKey);
        MlKemAlgorithms.Validate(algorithm);

#if NET10_0_OR_GREATER
        if (System.Security.Cryptography.MLKem.IsSupported)
            return new MlKemKey(NativeMlKemOperations.FromDecapsulationKey(
                decapsulationKey, MlKemAlgorithms.ToMLKemAlgorithm(algorithm)));
#endif
        return new MlKemKey(BouncyCastleMlKemOperations.FromDecapsulationKey(decapsulationKey, algorithm));
    }

    /// <summary>
    /// Creates a key from an encrypted private key (cross-platform format).
    /// </summary>
    internal static MlKemKey FromEncryptedKey(string password, byte[] encryptedKey)
    {
        var (rawKey, algName) = KeyEncryptionHelper.Decrypt(password, encryptedKey);
        try
        {
#if NET10_0_OR_GREATER
            if (System.Security.Cryptography.MLKem.IsSupported)
            {
                var mlKemAlg = MlKemAlgorithms.ToMLKemAlgorithm(algName);
                return new MlKemKey(NativeMlKemOperations.FromDecapsulationKey(rawKey, mlKemAlg));
            }
#endif
            return new MlKemKey(BouncyCastleMlKemOperations.FromDecapsulationKey(rawKey, algName));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    // ── KEM operations ───────────────────────────────────────────

    /// <inheritdoc cref="IMlKemKeyOperations.Encapsulate"/>
    public (byte[] SharedSecret, byte[] Ciphertext) Encapsulate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ops.Encapsulate();
    }

    /// <inheritdoc cref="IMlKemKeyOperations.Decapsulate"/>
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

    /// <summary>Exports the private key in encrypted cross-platform format.</summary>
    internal byte[] ExportEncryptedKey(string password, string algorithmName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var rawKey = _ops.ExportDecapsulationKey();
        try
        {
            return KeyEncryptionHelper.Encrypt(password, rawKey, algorithmName);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    // ── IDisposable ──────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _ops.Dispose();
    }
}

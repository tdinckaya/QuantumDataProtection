#pragma warning disable SYSLIB5006

using System.Security.Cryptography;

namespace QuantumDataProtection;

/// <summary>
/// ML-KEM operations using .NET 10 native <see cref="MLKem"/> (Windows 11/Server 2025, Linux OpenSSL 3.5+).
/// </summary>
internal sealed class NativeMlKemOperations : IMlKemKeyOperations
{
    private readonly MLKem _mlKem;
    private readonly bool _ownsKey;
    private readonly bool _hasDecapsulationKey;
    private bool _disposed;

    public NativeMlKemOperations(MLKem mlKem, bool ownsKey = true)
    {
        _mlKem = mlKem;
        _ownsKey = ownsKey;
        _hasDecapsulationKey = TryDetectDecapsulationKey(mlKem);

        var encapKey = mlKem.ExportEncapsulationKey();
        var hash = SHA256.HashData(encapKey);
        KeyId = Convert.ToBase64String(hash).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    public string KeyId { get; }
    public bool HasDecapsulationKey => _hasDecapsulationKey;
    public string ProviderName => "Native (.NET 10)";

    public static NativeMlKemOperations Generate(MLKemAlgorithm algorithm)
    {
        var mlKem = MLKem.GenerateKey(algorithm);
        return new NativeMlKemOperations(mlKem, ownsKey: true);
    }

    public static NativeMlKemOperations FromEncapsulationKey(byte[] key, MLKemAlgorithm algorithm)
    {
        var mlKem = MLKem.ImportEncapsulationKey(algorithm, key);
        return new NativeMlKemOperations(mlKem, ownsKey: true);
    }

    public static NativeMlKemOperations FromDecapsulationKey(byte[] key, MLKemAlgorithm algorithm)
    {
        var mlKem = MLKem.ImportDecapsulationKey(algorithm, key);
        return new NativeMlKemOperations(mlKem, ownsKey: true);
    }

    public static NativeMlKemOperations FromEncryptedPkcs8(string password, byte[] encryptedKey)
    {
        var (rawKey, algName) = KeyEncryptionHelper.Decrypt(password, encryptedKey);
        try
        {
            var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
            var mlKem = MLKem.ImportDecapsulationKey(algorithm, rawKey);
            return new NativeMlKemOperations(mlKem, ownsKey: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public (byte[] SharedSecret, byte[] Ciphertext) Encapsulate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _mlKem.Encapsulate(out var ciphertext, out var sharedSecret);
        return (sharedSecret, ciphertext);
    }

    public byte[] Decapsulate(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_hasDecapsulationKey)
            throw new InvalidOperationException("No decapsulation key available.");
        return _mlKem.Decapsulate(ciphertext);
    }

    public byte[] ExportEncapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _mlKem.ExportEncapsulationKey();
    }

    public byte[] ExportDecapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_hasDecapsulationKey)
            throw new InvalidOperationException("No decapsulation key available.");
        return _mlKem.ExportDecapsulationKey();
    }

    public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParams)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_hasDecapsulationKey)
            throw new InvalidOperationException("No decapsulation key available.");

        // Use cross-platform encryption helper for consistency with BouncyCastle
        var rawKey = _mlKem.ExportDecapsulationKey();
        var algName = MlKemAlgorithms.ToAlgorithmString(_mlKem.Algorithm);
        try
        {
            return KeyEncryptionHelper.Encrypt(password, rawKey, algName);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsKey) _mlKem.Dispose();
    }

    private static bool TryDetectDecapsulationKey(MLKem mlKem)
    {
        try { _ = mlKem.ExportDecapsulationKey(); return true; }
        catch (CryptographicException) { return false; }
    }
}

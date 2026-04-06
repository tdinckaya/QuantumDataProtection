using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using BcMLKemParameters = Org.BouncyCastle.Crypto.Parameters.MLKemParameters;

namespace QuantumDataProtection;

/// <summary>
/// ML-KEM operations using BouncyCastle (works on all platforms including macOS).
/// </summary>
internal sealed class BouncyCastleMlKemOperations : IMlKemKeyOperations
{
    private readonly MLKemPublicKeyParameters? _publicKey;
    private readonly MLKemPrivateKeyParameters? _privateKey;
    private readonly BcMLKemParameters _bcParams;
    private bool _disposed;

    private BouncyCastleMlKemOperations(
        MLKemPublicKeyParameters? publicKey,
        MLKemPrivateKeyParameters? privateKey,
        BcMLKemParameters bcParams)
    {
        _publicKey = publicKey;
        _privateKey = privateKey;
        _bcParams = bcParams;

        var encapKey = ExportEncapsulationKey();
        var hash = SHA256.HashData(encapKey);
        KeyId = Convert.ToBase64String(hash).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    public string KeyId { get; }
    public bool HasDecapsulationKey => _privateKey is not null;
    public string ProviderName => "BouncyCastle";

    public static BouncyCastleMlKemOperations Generate(string algorithmName)
    {
        var bcParams = MapToBcParams(algorithmName);
        var random = new SecureRandom();
        var keyGenParams = new MLKemKeyGenerationParameters(random, bcParams);
        var generator = new MLKemKeyPairGenerator();
        generator.Init(keyGenParams);
        var keyPair = generator.GenerateKeyPair();

        return new BouncyCastleMlKemOperations(
            (MLKemPublicKeyParameters)keyPair.Public,
            (MLKemPrivateKeyParameters)keyPair.Private,
            bcParams);
    }

    public static BouncyCastleMlKemOperations FromEncapsulationKey(byte[] key, string algorithmName)
    {
        var bcParams = MapToBcParams(algorithmName);
        var pubKey = MLKemPublicKeyParameters.FromEncoding(bcParams, key);
        return new BouncyCastleMlKemOperations(pubKey, null, bcParams);
    }

    public static BouncyCastleMlKemOperations FromDecapsulationKey(byte[] key, string algorithmName)
    {
        var bcParams = MapToBcParams(algorithmName);
        var privKey = MLKemPrivateKeyParameters.FromEncoding(bcParams, key);
        return new BouncyCastleMlKemOperations(privKey.GetPublicKey(), privKey, bcParams);
    }

    public static BouncyCastleMlKemOperations FromEncryptedPkcs8(string password, byte[] encryptedKey)
    {
        var (rawKey, algName) = KeyEncryptionHelper.Decrypt(password, encryptedKey);
        try
        {
            var bcParams = MapToBcParams(algName);
            var privKey = MLKemPrivateKeyParameters.FromEncoding(bcParams, rawKey);
            return new BouncyCastleMlKemOperations(privKey.GetPublicKey(), privKey, bcParams);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public (byte[] SharedSecret, byte[] Ciphertext) Encapsulate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var pubKey = _publicKey ?? throw new InvalidOperationException("No public key available.");

        var encapsulator = new MLKemEncapsulator(_bcParams);
        encapsulator.Init(pubKey);

        var ciphertext = new byte[encapsulator.EncapsulationLength];
        var sharedSecret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);

        return (sharedSecret, ciphertext);
    }

    public byte[] Decapsulate(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var privKey = _privateKey ?? throw new InvalidOperationException("No decapsulation key available.");

        var decapsulator = new MLKemDecapsulator(_bcParams);
        decapsulator.Init(privKey);

        var sharedSecret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);

        return sharedSecret;
    }

    public byte[] ExportEncapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_publicKey is not null) return _publicKey.GetEncoded();
        if (_privateKey is not null) return _privateKey.GetPublicKeyEncoded();
        throw new InvalidOperationException("No key available.");
    }

    public byte[] ExportDecapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var privKey = _privateKey ?? throw new InvalidOperationException("No decapsulation key available.");
        return privKey.GetEncoded();
    }

    public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParams)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var privKey = _privateKey ?? throw new InvalidOperationException("No decapsulation key available.");

        // Use our own AES-256-GCM encryption for cross-platform consistency
        var rawKey = privKey.GetEncoded();
        var algName = MlKemAlgorithms.ToAlgorithmString(_bcParams);

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
        _disposed = true;
    }

    private static BcMLKemParameters MapToBcParams(string algorithmName) => algorithmName.ToUpperInvariant() switch
    {
        "ML-KEM-512" => BcMLKemParameters.ml_kem_512,
        "ML-KEM-768" => BcMLKemParameters.ml_kem_768,
        "ML-KEM-1024" => BcMLKemParameters.ml_kem_1024,
        _ => throw new ArgumentException($"Unsupported ML-KEM algorithm: {algorithmName}")
    };
}

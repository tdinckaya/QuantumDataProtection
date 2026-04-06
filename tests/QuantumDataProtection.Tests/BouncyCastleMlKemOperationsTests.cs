using Xunit;

namespace QuantumDataProtection.Tests;

/// <summary>
/// These tests run on ALL platforms (including macOS) because BouncyCastle
/// does not depend on OS crypto libraries.
/// </summary>
public class BouncyCastleMlKemOperationsTests
{
    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void Generate_AllVariants_CreatesValidKey(string algName)
    {
        using var ops = BouncyCastleMlKemOperations.Generate(algName);

        Assert.NotEmpty(ops.KeyId);
        Assert.True(ops.HasDecapsulationKey);
        Assert.Equal("BouncyCastle", ops.ProviderName);
    }

    [Fact]
    public void EncapsulateAndDecapsulate_RoundTrip()
    {
        using var ops = BouncyCastleMlKemOperations.Generate("ML-KEM-768");

        var (sharedSecret, ciphertext) = ops.Encapsulate();
        var decapsulated = ops.Decapsulate(ciphertext);

        Assert.Equal(sharedSecret, decapsulated);
        Assert.Equal(32, sharedSecret.Length);
    }

    [Fact]
    public void ExportEncapsulationKey_ReturnsNonEmpty()
    {
        using var ops = BouncyCastleMlKemOperations.Generate("ML-KEM-768");

        var encapKey = ops.ExportEncapsulationKey();
        Assert.NotEmpty(encapKey);
    }

    [Fact]
    public void ExportDecapsulationKey_ReturnsNonEmpty()
    {
        using var ops = BouncyCastleMlKemOperations.Generate("ML-KEM-512");

        var decapKey = ops.ExportDecapsulationKey();
        Assert.NotEmpty(decapKey);
    }

    [Fact]
    public void FromEncapsulationKey_CanEncapsulate()
    {
        using var original = BouncyCastleMlKemOperations.Generate("ML-KEM-768");
        var encapKeyBytes = original.ExportEncapsulationKey();

        using var pubOnly = BouncyCastleMlKemOperations.FromEncapsulationKey(encapKeyBytes, "ML-KEM-768");

        Assert.False(pubOnly.HasDecapsulationKey);

        var (sharedSecret, ciphertext) = pubOnly.Encapsulate();
        Assert.Equal(32, sharedSecret.Length);

        // Original can decapsulate
        var decapsulated = original.Decapsulate(ciphertext);
        Assert.Equal(sharedSecret, decapsulated);
    }

    [Fact]
    public void ExportEncryptedPkcs8_AndReimport()
    {
        using var original = BouncyCastleMlKemOperations.Generate("ML-KEM-768");
        var (sharedSecret, ciphertext) = original.Encapsulate();

        var encrypted = original.ExportEncryptedPkcs8PrivateKey("test-password",
            new System.Security.Cryptography.PbeParameters(
                System.Security.Cryptography.PbeEncryptionAlgorithm.Aes256Cbc,
                System.Security.Cryptography.HashAlgorithmName.SHA256, 100_000));

        using var restored = BouncyCastleMlKemOperations.FromEncryptedPkcs8("test-password", encrypted);

        var decapsulated = restored.Decapsulate(ciphertext);
        Assert.Equal(sharedSecret, decapsulated);
    }

    [Fact]
    public void InvalidAlgorithm_Throws()
    {
        Assert.Throws<ArgumentException>(() => BouncyCastleMlKemOperations.Generate("RSA-2048"));
    }
}

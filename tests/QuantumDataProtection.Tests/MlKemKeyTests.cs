using System.Security.Cryptography;
using Xunit;

namespace QuantumDataProtection.Tests;

public class MlKemKeyTests
{
    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void Generate_AllVariants_CreatesValidKey(string algName)
    {
        var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
        using var key = MlKemKey.Generate(algorithm);

        Assert.NotNull(key);
        Assert.True(key.HasDecapsulationKey);
        Assert.NotEmpty(key.KeyId);
        Assert.NotEmpty(key.ProviderName);
    }

    [Fact]
    public void Generate_Default_UsesMlKem768()
    {
        using var key = MlKemKey.Generate();
        Assert.NotEmpty(key.KeyId);
    }

    [Fact]
    public void EncapsulateAndDecapsulate_RoundTrip()
    {
        using var key = MlKemKey.Generate(MLKemAlgorithm.MLKem768);

        var (sharedSecret, ciphertext) = key.Encapsulate();
        var decapsulated = key.Decapsulate(ciphertext);

        Assert.Equal(sharedSecret, decapsulated);
        Assert.Equal(32, sharedSecret.Length);
    }

    [Fact]
    public void ExportEncapsulationKey_RoundTrip()
    {
        using var original = MlKemKey.Generate(MLKemAlgorithm.MLKem768);
        var encapKeyBytes = original.ExportEncapsulationKey();

        using var publicOnly = MlKemKey.FromEncapsulationKey(encapKeyBytes, MLKemAlgorithm.MLKem768);

        Assert.False(publicOnly.HasDecapsulationKey);
        Assert.Equal(original.ExportEncapsulationKey(), publicOnly.ExportEncapsulationKey());
    }

    [Fact]
    public void ExportDecapsulationKey_RoundTrip()
    {
        using var original = MlKemKey.Generate(MLKemAlgorithm.MLKem768);
        var (sharedSecret, ciphertext) = original.Encapsulate();

        var decapKeyBytes = original.ExportDecapsulationKey();
        using var restored = MlKemKey.FromDecapsulationKey(decapKeyBytes, MLKemAlgorithm.MLKem768);

        var decapsulated = restored.Decapsulate(ciphertext);
        Assert.Equal(sharedSecret, decapsulated);
    }

    [Fact]
    public void HasDecapsulationKey_WhenEncapsulationOnly_ReturnsFalse()
    {
        using var full = MlKemKey.Generate(MLKemAlgorithm.MLKem512);
        var encapBytes = full.ExportEncapsulationKey();
        using var pubOnly = MlKemKey.FromEncapsulationKey(encapBytes, MLKemAlgorithm.MLKem512);

        Assert.False(pubOnly.HasDecapsulationKey);
        Assert.Throws<InvalidOperationException>(() => pubOnly.ExportDecapsulationKey());
        Assert.Throws<InvalidOperationException>(() => pubOnly.Decapsulate(new byte[32]));
    }

    [Fact]
    public void KeyId_IsDeterministic()
    {
        using var key = MlKemKey.Generate();
        Assert.NotNull(key.KeyId);
        Assert.NotEmpty(key.KeyId);
    }

    [Fact]
    public void ProviderName_IsSet()
    {
        using var key = MlKemKey.Generate();
        Assert.True(
            key.ProviderName == "Native (.NET 10)" || key.ProviderName == "BouncyCastle",
            $"Unexpected provider: {key.ProviderName}");
    }

    [Fact]
    public void DoubleDispose_DoesNotThrow()
    {
        var key = MlKemKey.Generate(MLKemAlgorithm.MLKem512);
        key.Dispose();
        key.Dispose(); // Should not throw
    }

    [Fact]
    public void Encapsulate_AfterDispose_ThrowsObjectDisposed()
    {
        var key = MlKemKey.Generate();
        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => key.Encapsulate());
    }
}

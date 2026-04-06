using Xunit;

namespace QuantumDataProtection.Tests;

public class MlKemAlgorithmsTests
{
    [Fact]
    public void All_ContainsAllThreeAlgorithms()
    {
        Assert.Equal(3, MlKemAlgorithms.All.Count);
        Assert.Contains("ML-KEM-512", MlKemAlgorithms.All);
        Assert.Contains("ML-KEM-768", MlKemAlgorithms.All);
        Assert.Contains("ML-KEM-1024", MlKemAlgorithms.All);
    }

    [Fact]
    public void Validate_ValidAlgorithms_DoesNotThrow()
    {
        MlKemAlgorithms.Validate(MlKemAlgorithms.MlKem512);
        MlKemAlgorithms.Validate(MlKemAlgorithms.MlKem768);
        MlKemAlgorithms.Validate(MlKemAlgorithms.MlKem1024);
    }

    [Fact]
    public void Validate_InvalidAlgorithm_Throws()
    {
        Assert.Throws<ArgumentException>(() => MlKemAlgorithms.Validate("RSA-2048"));
    }

    [Theory]
    [InlineData("ml-kem-512")]
    [InlineData("ml-kem-768")]
    [InlineData("ml-kem-1024")]
    public void All_CaseInsensitive(string algName)
    {
        Assert.Contains(algName, MlKemAlgorithms.All);
    }

#if NET10_0_OR_GREATER
    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void ToMLKemAlgorithm_ValidStrings_ReturnsCorrectAlgorithm(string algName)
    {
        var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
        Assert.NotNull(algorithm);
    }

    [Fact]
    public void ToMLKemAlgorithm_InvalidString_Throws()
    {
        Assert.Throws<ArgumentException>(() => MlKemAlgorithms.ToMLKemAlgorithm("RSA-2048"));
    }

    [Fact]
    public void ToAlgorithmString_AllVariants_ReturnCorrectStrings()
    {
        Assert.Equal("ML-KEM-512", MlKemAlgorithms.ToAlgorithmString(System.Security.Cryptography.MLKemAlgorithm.MLKem512));
        Assert.Equal("ML-KEM-768", MlKemAlgorithms.ToAlgorithmString(System.Security.Cryptography.MLKemAlgorithm.MLKem768));
        Assert.Equal("ML-KEM-1024", MlKemAlgorithms.ToAlgorithmString(System.Security.Cryptography.MLKemAlgorithm.MLKem1024));
    }
#endif
}

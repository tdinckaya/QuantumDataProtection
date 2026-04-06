using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace QuantumDataProtection.Tests;

public class HybridXmlDecryptorTests : IDisposable
{
    private readonly string _testDir;

    public HybridXmlDecryptorTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"qdp-hybrid-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
            Directory.Delete(_testDir, recursive: true);
    }

    private MlKemDataProtectionOptions CreateOptions(Type? legacyDecryptorType = null)
    {
        return new MlKemDataProtectionOptions
        {
            Algorithm = MlKemAlgorithms.MlKem768,
            KeyStoreDirectory = _testDir,
            KeyStorePassword = "hybrid-test-password",
            EnableLegacyKeyDecryption = true,
            LegacyDecryptorType = legacyDecryptorType
        };
    }

    [Fact]
    public void MlKemEncryptedXml_DecryptedByMlKem()
    {

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);
        var original = new XElement("root", new XElement("secret", "quantum-safe"));

        var encrypted = encryptor.Encrypt(original);

        // Use HybridXmlDecryptor
        var services = new ServiceCollection();
        services.AddSingleton(options);
        using var sp = services.BuildServiceProvider();

        var hybrid = new HybridXmlDecryptor(sp);
        var decrypted = hybrid.Decrypt(encrypted.EncryptedElement);

        Assert.Equal(original.ToString(), decrypted.ToString());
    }

    [Fact]
    public void NonMlKemXml_WithFallback_DecryptedByFallback()
    {

        // Create a fake legacy-encrypted XML
        var legacyXml = new XElement("encryptedKey",
            new XElement("value", "legacy-encrypted-data"));

        var options = CreateOptions(legacyDecryptorType: typeof(FakeLegacyDecryptor));

        var services = new ServiceCollection();
        services.AddSingleton(options);
        using var sp = services.BuildServiceProvider();

        var hybrid = new HybridXmlDecryptor(sp);
        var decrypted = hybrid.Decrypt(legacyXml);

        // FakeLegacyDecryptor returns a fixed element
        Assert.Equal("legacyDecrypted", decrypted.Name.LocalName);
    }

    [Fact]
    public void NonMlKemXml_NoFallback_ThrowsCryptographicException()
    {

        var legacyXml = new XElement("encryptedKey", "something");

        // No LegacyDecryptorType set
        var options = CreateOptions(legacyDecryptorType: null);

        var services = new ServiceCollection();
        services.AddSingleton(options);
        using var sp = services.BuildServiceProvider();

        var hybrid = new HybridXmlDecryptor(sp);

        var ex = Assert.Throws<CryptographicException>(() => hybrid.Decrypt(legacyXml));
        Assert.Contains("no legacy decryptor", ex.Message);
    }

    [Fact]
    public void EnableLegacyKeyDecryption_False_UsesPureMlKemDecryptor()
    {

        var options = new MlKemDataProtectionOptions
        {
            Algorithm = MlKemAlgorithms.MlKem768,
            KeyStoreDirectory = _testDir,
            KeyStorePassword = "test",
            EnableLegacyKeyDecryption = false
        };

        var encryptor = new MlKemXmlEncryptor(options);
        var original = new XElement("root", "pure-mode");
        var encrypted = encryptor.Encrypt(original);

        var services = new ServiceCollection();
        services.AddSingleton(options);
        using var sp = services.BuildServiceProvider();

        // Pure MlKemXmlDecryptor should work for ML-KEM encrypted data
        var decryptor = new MlKemXmlDecryptor(sp);
        var decrypted = decryptor.Decrypt(encrypted.EncryptedElement);

        Assert.Equal(original.ToString(), decrypted.ToString());
    }

    /// <summary>
    /// Fake legacy decryptor for testing fallback behavior.
    /// </summary>
    public class FakeLegacyDecryptor : IXmlDecryptor
    {
        public XElement Decrypt(XElement encryptedElement)
        {
            return new XElement("legacyDecrypted", "success");
        }
    }
}

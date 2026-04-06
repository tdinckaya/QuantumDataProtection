using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace QuantumDataProtection.Tests;

public class MlKemXmlEncryptorTests : IDisposable
{
    private readonly string _testDir;

    public MlKemXmlEncryptorTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"qdp-test-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
            Directory.Delete(_testDir, recursive: true);
    }

    private MlKemDataProtectionOptions CreateOptions(MLKemAlgorithm? algorithm = null)
    {
        return new MlKemDataProtectionOptions
        {
            Algorithm = algorithm ?? MLKemAlgorithm.MLKem768,
            KeyStoreDirectory = _testDir,
            KeyStorePassword = "test-password-xyz"
        };
    }

    [Fact]
    public void Encrypt_ProducesValidXmlStructure()
    {

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);
        var plaintext = new XElement("root", new XElement("secret", "hello-world"));

        var result = encryptor.Encrypt(plaintext);

        Assert.Equal(typeof(MlKemXmlDecryptor), result.DecryptorType);

        var xml = result.EncryptedElement;
        Assert.Equal("mlKemEncryptedKey", xml.Name.LocalName);
        Assert.NotNull(xml.Element("algorithm"));
        Assert.NotNull(xml.Element("keyId"));
        Assert.NotNull(xml.Element("kemCiphertext"));
        Assert.NotNull(xml.Element("nonce"));
        Assert.NotNull(xml.Element("ciphertext"));
        Assert.NotNull(xml.Element("tag"));
        Assert.Equal("ML-KEM-768", xml.Element("algorithm")!.Value);
    }

    [Fact]
    public void Encrypt_SavesDecapsulationKeyToStore()
    {

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);
        var plaintext = new XElement("root", "test");

        var result = encryptor.Encrypt(plaintext);
        var keyId = result.EncryptedElement.Element("keyId")!.Value;

        var store = options.ResolveKeyStore();
        var savedKey = store.LoadPrivateKeyAsync(keyId).GetAwaiter().GetResult();

        Assert.NotNull(savedKey);
        Assert.True(savedKey!.Length > 0);
    }

    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void EncryptDecrypt_RoundTrip_AllAlgorithms(string algName)
    {

        var algorithm = MlKemAlgorithms.ToMLKemAlgorithm(algName);
        var options = CreateOptions(algorithm);
        var encryptor = new MlKemXmlEncryptor(options);

        var original = new XElement("root",
            new XElement("key", "my-secret-key"),
            new XElement("value", "sensitive-data-12345"));

        var encrypted = encryptor.Encrypt(original);

        // Decrypt
        var services = new ServiceCollection();
        services.AddSingleton(options);
        var sp = services.BuildServiceProvider();

        var decryptor = new MlKemXmlDecryptor(sp);
        var decrypted = decryptor.Decrypt(encrypted.EncryptedElement);

        Assert.Equal(original.ToString(), decrypted.ToString());
    }

    [Fact]
    public void EncryptDecrypt_LargeXml_Works()
    {

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);

        // Simulate a realistic Data Protection XML key
        var original = new XElement("key",
            new XAttribute("id", Guid.NewGuid()),
            new XAttribute("version", 1),
            new XElement("creationDate", DateTimeOffset.UtcNow),
            new XElement("activationDate", DateTimeOffset.UtcNow),
            new XElement("expirationDate", DateTimeOffset.UtcNow.AddDays(90)),
            new XElement("descriptor",
                new XElement("secret", Convert.ToBase64String(RandomNumberGenerator.GetBytes(256)))));

        var encrypted = encryptor.Encrypt(original);

        var services = new ServiceCollection();
        services.AddSingleton(options);
        var sp = services.BuildServiceProvider();

        var decryptor = new MlKemXmlDecryptor(sp);
        var decrypted = decryptor.Decrypt(encrypted.EncryptedElement);

        Assert.Equal(original.ToString(), decrypted.ToString());
    }

    [Fact]
    public void Decrypt_MissingKeyInStore_ThrowsCryptographicException()
    {

        var options = CreateOptions();
        var encryptor = new MlKemXmlEncryptor(options);
        var original = new XElement("root", "test");

        var encrypted = encryptor.Encrypt(original);

        // Delete the stored key to simulate missing key
        var keyId = encrypted.EncryptedElement.Element("keyId")!.Value;
        var store = options.ResolveKeyStore();
        store.DeleteKeyAsync(keyId).GetAwaiter().GetResult();

        var services = new ServiceCollection();
        services.AddSingleton(options);
        using var sp = services.BuildServiceProvider();
        var decryptor = new MlKemXmlDecryptor(sp);

        Assert.Throws<CryptographicException>(() => decryptor.Decrypt(encrypted.EncryptedElement));
    }

    [Fact]
    public void Decrypt_CorruptedXml_MissingElement_ThrowsCryptographicException()
    {

        var options = CreateOptions();
        var services = new ServiceCollection();
        services.AddSingleton(options);
        using var sp = services.BuildServiceProvider();
        var decryptor = new MlKemXmlDecryptor(sp);

        var corruptedXml = new XElement("mlKemEncryptedKey",
            new XElement("algorithm", "ML-KEM-768"));
        // Missing keyId, kemCiphertext, nonce, ciphertext, tag

        Assert.Throws<CryptographicException>(() => decryptor.Decrypt(corruptedXml));
    }

    [Fact]
    public void Decrypt_UnsupportedAlgorithm_ThrowsCryptographicException()
    {

        var options = CreateOptions();
        var services = new ServiceCollection();
        services.AddSingleton(options);
        using var sp = services.BuildServiceProvider();
        var decryptor = new MlKemXmlDecryptor(sp);

        var badAlgXml = new XElement("mlKemEncryptedKey",
            new XElement("algorithm", "RSA-2048"),
            new XElement("keyId", "fake"),
            new XElement("kemCiphertext", Convert.ToBase64String(new byte[32])),
            new XElement("nonce", Convert.ToBase64String(new byte[12])),
            new XElement("ciphertext", Convert.ToBase64String(new byte[16])),
            new XElement("tag", Convert.ToBase64String(new byte[16])));

        var ex = Assert.Throws<CryptographicException>(() => decryptor.Decrypt(badAlgXml));
        Assert.Contains("Unsupported ML-KEM algorithm", ex.Message);
    }

    [Fact]
    public void Options_MissingPasswordAndStore_ThrowsInvalidOperation()
    {
        var options = new MlKemDataProtectionOptions();
        // No KeyStore, no KeyStoreDirectory, no KeyStorePassword

        Assert.Throws<InvalidOperationException>(() => options.ResolveKeyStore());
    }

    [Fact]
    public void Options_MissingPassword_ThrowsInvalidOperation()
    {
        var options = new MlKemDataProtectionOptions
        {
            KeyStoreDirectory = "/tmp/test"
            // KeyStorePassword is null
        };

        Assert.Throws<InvalidOperationException>(() => options.ResolvePkcs8Password());
    }

    [Fact]
    public void Options_ResolveKeyStore_ReturnsCachedInstance()
    {
        var options = new MlKemDataProtectionOptions
        {
            KeyStoreDirectory = Path.Combine(_testDir, "cache-test"),
            KeyStorePassword = "test"
        };

        var store1 = options.ResolveKeyStore();
        var store2 = options.ResolveKeyStore();

        Assert.Same(store1, store2);
    }
}

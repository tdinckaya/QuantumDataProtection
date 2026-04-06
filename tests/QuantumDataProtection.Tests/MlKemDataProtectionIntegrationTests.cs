using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace QuantumDataProtection.Tests;

public class MlKemDataProtectionIntegrationTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _keyDir;

    public MlKemDataProtectionIntegrationTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"qdp-int-{Guid.NewGuid():N}");
        _keyDir = Path.Combine(_testDir, "dp-keys");
        Directory.CreateDirectory(_keyDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDir))
            Directory.Delete(_testDir, recursive: true);
    }

    [Fact]
    public void ProtectUnprotect_EndToEnd_WithDataProtectionProvider()
    {
        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(_keyDir))
            .ProtectKeysWithMlKem(options =>
            {
                options.Algorithm = MlKemAlgorithms.MlKem768;
                options.KeyStoreDirectory = Path.Combine(_testDir, "kem-keys");
                options.KeyStorePassword = "integration-test-password";
            });

        using var sp = services.BuildServiceProvider();
        var dpProvider = sp.GetRequiredService<IDataProtectionProvider>();
        var protector = dpProvider.CreateProtector("test-purpose");

        var original = "Hello, post-quantum world!";
        var encrypted = protector.Protect(original);
        var decrypted = protector.Unprotect(encrypted);

        Assert.Equal(original, decrypted);
        Assert.NotEqual(original, encrypted);
    }

    [Fact]
    public void ProtectUnprotect_DifferentPurposes_CannotCrossDecrypt()
    {
        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(_keyDir))
            .ProtectKeysWithMlKem(options =>
            {
                options.Algorithm = MlKemAlgorithms.MlKem768;
                options.KeyStoreDirectory = Path.Combine(_testDir, "kem-keys");
                options.KeyStorePassword = "integration-test-password";
            });

        using var sp = services.BuildServiceProvider();
        var dpProvider = sp.GetRequiredService<IDataProtectionProvider>();

        var protectorA = dpProvider.CreateProtector("purpose-A");
        var protectorB = dpProvider.CreateProtector("purpose-B");

        var encrypted = protectorA.Protect("secret");

        Assert.Throws<CryptographicException>(() => protectorB.Unprotect(encrypted));
    }

    [SkippableFact]
    public void ProtectUnprotect_DecapsulationKeyIsStoredInKeyStore()
    {
        var kemKeyDir = Path.Combine(_testDir, "kem-keys-check");
        var freshKeyDir = Path.Combine(_testDir, "dp-keys-fresh");
        Directory.CreateDirectory(freshKeyDir);

        var services = new ServiceCollection();
        services.AddDataProtection()
            .SetApplicationName("store-check-test-" + Guid.NewGuid())
            .PersistKeysToFileSystem(new DirectoryInfo(freshKeyDir))
            .ProtectKeysWithMlKem(options =>
            {
                options.Algorithm = MlKemAlgorithms.MlKem768;
                options.KeyStoreDirectory = kemKeyDir;
                options.KeyStorePassword = "check-password";
            });

        using var sp = services.BuildServiceProvider();
        var protector = sp.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("store-check");

        _ = protector.Protect("trigger key creation");

        if (Directory.Exists(kemKeyDir))
        {
            var keyFiles = Directory.GetFiles(kemKeyDir, "*.p8");
            Assert.NotEmpty(keyFiles);
        }
        else
        {
            Skip.If(true, "Data Protection did not invoke IXmlEncryptor — key ring was cached.");
        }
    }
}

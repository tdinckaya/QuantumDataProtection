# QuantumDataProtection

> **[Turkce dokumantasyon icin tiklayiniz](README.tr.md)**

Post-quantum key wrapping for ASP.NET Core Data Protection using ML-KEM (FIPS 203).

Protects cookies, sessions, and anti-forgery tokens against **harvest-now-decrypt-later** attacks.

[![NuGet](https://img.shields.io/nuget/v/QuantumDataProtection.svg)](https://www.nuget.org/packages/QuantumDataProtection)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The Problem

ASP.NET Core Data Protection encrypts cookies, session state, and anti-forgery tokens. The payload is AES-256 encrypted (quantum-safe), but the **master key is wrapped with RSA** (not quantum-safe).

"Harvest now, decrypt later" attackers record encrypted traffic today. When quantum computers arrive, they crack the RSA key wrapping and access every cookie and session ever protected.

**AES is fine. The RSA envelope is the problem. We replace it with ML-KEM.**

---

## Quick Start

```bash
dotnet add package QuantumDataProtection
```

```csharp
builder.Services.AddDataProtection()
    .ProtectKeysWithMlKem(options =>
    {
        options.Algorithm = MLKemAlgorithm.MLKem768;      // FIPS 203
        options.KeyStoreDirectory = "/var/keys";
        options.KeyStorePassword = config["KeyPassword"];
    });
```

That's it. Cookies, sessions, anti-forgery tokens — now quantum-resistant.

---

## How It Works

```
                    Data Protection Pipeline
                    
    [Master Key XML]
           |
    ┌──────┴──────┐
    │  BEFORE     │     RSA key wrapping (quantum-vulnerable)
    │  (default)  │     AES-256 payload encryption (quantum-safe)
    └──────┬──────┘
           |
    ┌──────┴──────┐
    │  AFTER      │     ML-KEM key encapsulation (quantum-safe)
    │  (this pkg) │     AES-256-GCM payload encryption (quantum-safe)
    └─────────────┘
```

For each Data Protection master key:

1. Generate fresh ML-KEM keypair
2. `Encapsulate()` → shared secret + KEM ciphertext
3. AES-256-GCM encrypt the XML key using the shared secret
4. Store decapsulation key as encrypted PKCS#8 in `IKeyStore`
5. `CryptographicOperations.ZeroMemory()` the shared secret immediately

**Forward secrecy**: Each key gets its own ML-KEM keypair. One compromised key doesn't affect others.

---

## Platform Requirements

| Platform | Minimum Version | Status |
|----------|----------------|--------|
| Windows | Windows 11 / Server 2025 | Supported |
| Linux | OpenSSL 3.5+ | Supported |
| macOS | — | Not supported |

Requires **.NET 10** SDK.

---

## Key Storage

### Built-in FileKeyStore

Stores encrypted PKCS#8 files on disk:

```csharp
options.KeyStoreDirectory = "/secure/keys";
options.KeyStorePassword = Environment.GetEnvironmentVariable("KEY_PASSWORD")!;
```

### Custom IKeyStore

Implement for Azure Key Vault, AWS KMS, HashiCorp Vault:

```csharp
public interface IKeyStore
{
    Task<byte[]?> LoadPrivateKeyAsync(string keyId);
    Task SavePrivateKeyAsync(string keyId, byte[] encryptedKey);
    Task DeleteKeyAsync(string keyId);
    Task<IReadOnlyList<string>> ListKeyIdsAsync();
}

// Usage
options.KeyStore = new AzureKeyVaultKeyStore(vaultUri);
```

---

## ML-KEM Algorithm Variants

| Algorithm | Security Level | Shared Secret | Ciphertext | Use Case |
|-----------|---------------|---------------|------------|----------|
| ML-KEM-512 | 1 (128-bit) | 32 bytes | 768 bytes | Development, low-security |
| ML-KEM-768 | 3 (192-bit) | 32 bytes | 1,088 bytes | **Recommended** |
| ML-KEM-1024 | 5 (256-bit) | 32 bytes | 1,568 bytes | High-security, regulated |

---

## Security Notes

1. **Experimental API**: ML-KEM in .NET 10 is marked `[Experimental]` (`SYSLIB5006`). May change before GA.
2. **Shared secret zeroing**: All shared secrets are immediately cleared with `CryptographicOperations.ZeroMemory()`.
3. **Per-key isolation**: Each Data Protection key gets its own ML-KEM keypair — forward secrecy by design.
4. **AES-256-GCM**: Authenticated encryption with separate nonce and tag elements — no ambiguity.

---

## API Reference

| Class | Description |
|-------|-------------|
| `MlKemKey` | ML-KEM key wrapper with Generate/Encapsulate/Decapsulate |
| `MlKemXmlEncryptor` | `IXmlEncryptor` — ML-KEM + AES-256-GCM encryption |
| `MlKemXmlDecryptor` | `IXmlDecryptor` — decryption counterpart |
| `MlKemDataProtectionOptions` | Configuration (algorithm, key store) |
| `IKeyStore` | Key persistence abstraction |
| `FileKeyStore` | File-based encrypted key storage |
| `MlKemAlgorithms` | Algorithm identifier constants |

| Extension Method | Description |
|-----------------|-------------|
| `ProtectKeysWithMlKem(options)` | Replace RSA key wrapping with ML-KEM |

---

## License

MIT

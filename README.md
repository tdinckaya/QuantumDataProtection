# QuantumDataProtection

> **[Turkce dokumantasyon icin tiklayiniz](README.tr.md)**

Post-quantum key wrapping for ASP.NET Core Data Protection using **ML-KEM (FIPS 203)**.

The first and only NuGet package that replaces RSA key wrapping with quantum-resistant key encapsulation — protecting cookies, sessions, and anti-forgery tokens against **harvest-now-decrypt-later** attacks.

[![NuGet](https://img.shields.io/nuget/v/QuantumDataProtection.svg)](https://www.nuget.org/packages/QuantumDataProtection)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-8%20%7C%209%20%7C%2010-blue)](https://dotnet.microsoft.com/)

---

## Why This Exists

ASP.NET Core Data Protection encrypts cookies, session state, and anti-forgery tokens. The payload uses **AES-256** (quantum-safe). But the **master key is wrapped with RSA** (not quantum-safe).

"Harvest now, decrypt later" attackers record encrypted traffic today. When quantum computers arrive, they crack the RSA key envelope and access every cookie and session ever protected.

**AES is fine. The RSA envelope is the problem. We replace it with ML-KEM.**

As of this writing, no other NuGet package provides ML-KEM-based key wrapping for ASP.NET Core Data Protection. Microsoft ships the raw ML-KEM primitives in .NET 10, but not the Data Protection integration — this package fills that gap.

---

## Quick Start

```bash
dotnet add package QuantumDataProtection
```

```csharp
builder.Services.AddDataProtection()
    .ProtectKeysWithMlKem(options =>
    {
        options.Algorithm = MlKemAlgorithms.MlKem768;   // FIPS 203, recommended
        options.KeyStoreDirectory = "/var/keys";
        options.KeyStorePassword = config["KeyPassword"];
    });
```

That's it. Cookies, sessions, anti-forgery tokens — now quantum-resistant.

---

## Migrating from RSA / Certificate Protection

Already using `ProtectKeysWithCertificate()` or DPAPI? Existing keys remain readable — zero downtime:

```csharp
builder.Services.AddDataProtection()
    .ProtectKeysWithMlKem(options =>
    {
        options.Algorithm = MlKemAlgorithms.MlKem768;
        options.KeyStoreDirectory = "/var/keys";
        options.KeyStorePassword = config["KeyPassword"];

        // Tell the hybrid decryptor how to read old keys
        options.LegacyDecryptorType = typeof(CertificateXmlDecryptor);
    });
```

**What happens:**

```
Day 0:   Deploy — old cookies/sessions keep working (legacy decryptor)
         New keys are wrapped with ML-KEM (quantum-safe)
Day 90:  Old keys expire naturally
Day 91:  Set EnableLegacyKeyDecryption = false
         Fully quantum-safe, no RSA dependency
```

---

## How It Works

```
                    Data Protection Pipeline

    [Application Payload: cookies, sessions, anti-forgery tokens]
                  |
                  | Encrypted by ASP.NET Core Data Protection
                  | (AES-based, quantum-safe — unchanged by this package)
                  ↓
    [Master XML Key] ← must be protected at rest
                  |
        +---------+---------+
        |  DEFAULT           |   RSA key wrapping
        |  (ASP.NET Core)    |   (quantum-VULNERABLE)
        +---------+---------+
                  |
        +---------+---------+
        |  WITH THIS PACKAGE |   ML-KEM key encapsulation (quantum-SAFE)
        |                    |   XML key wrapped with AES-256-GCM
        +--------------------+   using shared secret from ML-KEM
```

**What this package changes:** only the *key wrapping* layer — how the Data Protection master key is protected at rest. The application payload encryption (cookies, sessions) remains handled by ASP.NET Core Data Protection's own AES-based pipeline, which is already quantum-safe for symmetric encryption.

For each Data Protection master key:

1. **Generate** fresh ML-KEM keypair (per-key isolation — each Data Protection key is cryptographically independent)
2. **Encapsulate** shared secret + KEM ciphertext
3. **Encrypt** XML key with AES-256-GCM using the shared secret
4. **Store** decapsulation key encrypted in `IKeyStore`
5. **Zero** shared secret immediately with `CryptographicOperations.ZeroMemory()`

---

## Platform Support

| Platform | .NET Version | Provider | Status |
|----------|-------------|----------|--------|
| Windows 11 / Server 2025 | .NET 10 | Native | Supported |
| Linux (OpenSSL 3.5+) | .NET 10 | Native | Supported |
| **macOS** | .NET 8/9/10 | **BouncyCastle** | **Supported** |
| **Any platform** | **.NET 8/9** | **BouncyCastle** | **Supported** |
| Older Linux | .NET 8/9/10 | BouncyCastle | Supported |

**Automatic provider selection:** On .NET 10 with native ML-KEM support, uses the OS crypto library (fastest). Otherwise, falls back to BouncyCastle (works everywhere). Same API, same results, different engine.

---

## Demo API

A live demo API is included in the repo:

```bash
cd examples/QuantumDataProtection.Demo
dotnet run
```

| Endpoint | Description |
|----------|-------------|
| `GET /` | Info + endpoint list |
| `POST /protect` | Encrypt data with ML-KEM Data Protection |
| `POST /unprotect` | Decrypt previously protected data |
| `POST /protect-cookie` | Simulate ASP.NET Core auth cookie encryption |
| `GET /key-info` | ML-KEM key store status |
| `GET /compare` | RSA vs ML-KEM side-by-side comparison |

**Example:**

```bash
# Encrypt
curl -X POST http://localhost:5000/protect \
  -H "Content-Type: application/json" \
  -d '{"data":"sensitive-data","purpose":"demo"}'

# Decrypt (paste the encrypted value)
curl -X POST http://localhost:5000/unprotect \
  -H "Content-Type: application/json" \
  -d '{"encrypted":"CfDJ8...","purpose":"demo"}'

# Cookie simulation
curl -X POST http://localhost:5000/protect-cookie \
  -H "Content-Type: application/json" \
  -d '{"userId":"tansel","role":"admin"}'
```

---

## Key Storage

### Built-in FileKeyStore

Stores encrypted decapsulation keys on disk:

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
| **ML-KEM-768** | **3 (192-bit)** | **32 bytes** | **1,088 bytes** | **Recommended** |
| ML-KEM-1024 | 5 (256-bit) | 32 bytes | 1,568 bytes | High-security, regulated |

---

## Logging

All cryptographic operations are logged via `ILogger`:

| Event | Level | Message |
|-------|-------|---------|
| Key generated | Information | ML-KEM key generated. KeyId=..., Provider=... |
| Encrypt | Debug | XML key encrypted with ML-KEM |
| Decrypt | Debug | XML key decrypted with ML-KEM |
| Legacy fallback | Warning | Legacy decryptor used. Consider re-encrypting |
| Platform fallback | Information | ML-KEM native not supported. Using BouncyCastle |

---

## Security Design

- **Per-key isolation:** Each Data Protection key gets its own ML-KEM keypair. Compromise of one key does not cascade to others. Note: this is per-key isolation, not forward secrecy in the strict cryptographic sense — forward secrecy requires ephemeral session keys, which is a different property.
- **Shared secret zeroing:** All shared secrets immediately cleared with `CryptographicOperations.ZeroMemory()`
- **AES-256-GCM:** Authenticated encryption with separate nonce and tag — no ambiguity
- **Key encryption:** Decapsulation keys stored with PBKDF2 (100K iterations) + AES-256-GCM
- **No hardcoded secrets:** User-provided password for all key encryption
- **Path traversal protection:** `FileKeyStore` sanitizes key IDs

---

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `MlKemKey` | ML-KEM key wrapper — auto-selects Native or BouncyCastle |
| `MlKemXmlEncryptor` | `IXmlEncryptor` — ML-KEM + AES-256-GCM encryption |
| `MlKemXmlDecryptor` | `IXmlDecryptor` — ML-KEM decryption |
| `HybridXmlDecryptor` | `IXmlDecryptor` — routes ML-KEM and legacy keys |
| `MlKemDataProtectionOptions` | Configuration (algorithm, key store, legacy support) |
| `IKeyStore` | Key persistence abstraction |
| `FileKeyStore` | File-based encrypted key storage |
| `MlKemAlgorithms` | Algorithm identifier constants |
| `KeyEncryptionHelper` | Cross-platform PBKDF2 + AES-256-GCM key encryption |

### Extension Methods

| Method | Description |
|--------|-------------|
| `ProtectKeysWithMlKem(options)` | Replace RSA key wrapping with ML-KEM |

### Options

| Property | Default | Description |
|----------|---------|-------------|
| `Algorithm` | `MlKemAlgorithms.MlKem768` | ML-KEM variant |
| `KeyStoreDirectory` | — | Directory for FileKeyStore |
| `KeyStorePassword` | — | Password for key encryption (required) |
| `KeyStore` | — | Custom IKeyStore (overrides directory/password) |
| `EnableLegacyKeyDecryption` | `true` | Allow reading old RSA/DPAPI-wrapped keys |
| `LegacyDecryptorType` | — | e.g. `typeof(CertificateXmlDecryptor)` |

---

## NIST / NSA Timeline

| Date | Requirement |
|------|-------------|
| **2024** | NIST published FIPS 203 (ML-KEM) |
| **2027** | NSA: all new national security systems must be quantum-safe |
| **2030** | NSA: full application migration deadline |
| **2035** | NIST: quantum-vulnerable algorithms removed from standards |

---

## Known Limitations

- ML-KEM APIs in .NET 10 are marked `[Experimental]` (`SYSLIB5006`) — may change before GA
- BouncyCastle adds ~2MB to the package size
- `IXmlEncryptor.Encrypt()` is synchronous — custom `IKeyStore` implementations with network I/O should handle this carefully
- The ML-KEM shared secret is used directly as the AES-256-GCM key without an HKDF key-derivation step. This is acceptable under authenticated encryption in the current threat model, but deviates from strict NIST SP 800-227 (draft) guidance on domain separation. HKDF-SHA256 derivation with domain-separated `info` strings is planned for a future major version (format change; will be introduced behind a version header).
- No automatic key rotation for the underlying ML-KEM keypairs yet. ASP.NET Core's own Data Protection key rotation works normally; only the ML-KEM key-encryption-keys persist for the lifetime of the wrapped Data Protection keys. Scheduled rotation is on the roadmap.

---

## License

MIT

---

## Author

**Tansel DINCKAYA**

GitHub: [github.com/tdinckaya](https://github.com/tdinckaya)

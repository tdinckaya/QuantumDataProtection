# QuantumDataProtection

> **[Click here for English documentation](README.md)**

ASP.NET Core Data Protection icin ML-KEM (FIPS 203) tabanli post-quantum anahtar sarmalama.

Cookie'leri, session'lari ve anti-forgery token'lari **harvest-now-decrypt-later** saldirilarina karsi korur.

[![NuGet](https://img.shields.io/nuget/v/QuantumDataProtection.svg)](https://www.nuget.org/packages/QuantumDataProtection)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Problem

ASP.NET Core Data Protection cookie'leri, session state'i ve anti-forgery token'lari sifreler. Payload AES-256 ile sifrelenir (kuantum-guvenli), ama **master key RSA ile sarmalanir** (kuantum-guvenli degil).

"Harvest now, decrypt later" saldirganlari sifreli trafigi bugun kaydediyor. Kuantum bilgisayarlar geldiginde RSA anahtar sarmalamasini kiracak ve korunan tum cookie ve session'lara erisecek.

**AES sorun degil. RSA zarfi sorun. Biz onu ML-KEM ile degistiriyoruz.**

---

## Hizli Baslangic

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

Bu kadar. Cookie'ler, session'lar, anti-forgery token'lar — artik kuantum-dayanikli.

---

## Nasil Calisir?

```
                    Data Protection Pipeline
                    
    [Master Key XML]
           |
    +------+------+
    |  ONCESI     |     RSA key wrapping (kuantum-savunmasiz)
    |  (varsayil) |     AES-256 payload sifreleme (kuantum-guvenli)
    +------+------+
           |
    +------+------+
    |  SONRASI    |     ML-KEM key kapsulleme (kuantum-guvenli)
    |  (bu paket) |     AES-256-GCM payload sifreleme (kuantum-guvenli)
    +-------------+
```

Her Data Protection master key icin:

1. Yeni ML-KEM keypair uret
2. `Encapsulate()` -> shared secret + KEM ciphertext
3. Shared secret ile AES-256-GCM sifreleme
4. Decapsulation key'i encrypted PKCS#8 olarak `IKeyStore`'a kaydet
5. `CryptographicOperations.ZeroMemory()` ile shared secret'i hemen sil

**Forward secrecy**: Her key kendi ML-KEM keypair'ine sahip. Bir key ele gecirilse bile digerleri etkilenmez.

---

## Platform Gereksinimleri

| Platform | Minimum Surum | Durum |
|----------|--------------|-------|
| Windows | Windows 11 / Server 2025 | Destekleniyor |
| Linux | OpenSSL 3.5+ | Destekleniyor |
| macOS | — | Desteklenmiyor |

**.NET 10** SDK gerektirir.

---

## Anahtar Saklama

### Dahili FileKeyStore

Encrypted PKCS#8 dosyalarini diske yazar:

```csharp
options.KeyStoreDirectory = "/secure/keys";
options.KeyStorePassword = Environment.GetEnvironmentVariable("KEY_PASSWORD")!;
```

### Ozel IKeyStore

Azure Key Vault, AWS KMS, HashiCorp Vault icin implement edin:

```csharp
public interface IKeyStore
{
    Task<byte[]?> LoadPrivateKeyAsync(string keyId);
    Task SavePrivateKeyAsync(string keyId, byte[] encryptedKey);
    Task DeleteKeyAsync(string keyId);
    Task<IReadOnlyList<string>> ListKeyIdsAsync();
}

// Kullanim
options.KeyStore = new AzureKeyVaultKeyStore(vaultUri);
```

---

## ML-KEM Algoritma Varyantlari

| Algoritma | Guvenlik Seviyesi | Shared Secret | Ciphertext | Kullanim |
|-----------|------------------|---------------|------------|----------|
| ML-KEM-512 | 1 (128-bit) | 32 byte | 768 byte | Gelistirme, dusuk guvenlik |
| ML-KEM-768 | 3 (192-bit) | 32 byte | 1.088 byte | **Onerilen** |
| ML-KEM-1024 | 5 (256-bit) | 32 byte | 1.568 byte | Yuksek guvenlik, regule ortam |

---

## Guvenlik Notlari

1. **Deneysel API**: .NET 10'daki ML-KEM `[Experimental]` (`SYSLIB5006`) isaretli. GA oncesinde degisebilir.
2. **Shared secret sifirlanir**: Tum shared secret'lar `CryptographicOperations.ZeroMemory()` ile hemen temizlenir.
3. **Key izolasyonu**: Her Data Protection key kendi ML-KEM keypair'ine sahip — tasarimda forward secrecy.
4. **AES-256-GCM**: Ayri nonce ve tag element'leri ile kimlik dogrulamali sifreleme.

---

## API Referansi

| Sinif | Aciklama |
|-------|---------|
| `MlKemKey` | Generate/Encapsulate/Decapsulate ile ML-KEM anahtar wrapper |
| `MlKemXmlEncryptor` | `IXmlEncryptor` — ML-KEM + AES-256-GCM sifreleme |
| `MlKemXmlDecryptor` | `IXmlDecryptor` — cozme karsiligi |
| `MlKemDataProtectionOptions` | Yapilandirma (algoritma, anahtar deposu) |
| `IKeyStore` | Anahtar kalicilik soyutlamasi |
| `FileKeyStore` | Dosya tabanli sifreli anahtar saklama |
| `MlKemAlgorithms` | Algoritma tanimlayici sabitleri |

| Extension Metod | Aciklama |
|----------------|---------|
| `ProtectKeysWithMlKem(options)` | RSA key wrapping'i ML-KEM ile degistir |

---

## Lisans

MIT

# QuantumDataProtection

> **[Click here for English documentation](README.md)**

ASP.NET Core Data Protection icin **ML-KEM (FIPS 203)** tabanli post-quantum anahtar sarmalama.

Cookie'leri, session'lari ve anti-forgery token'lari **harvest-now-decrypt-later** saldirilarina karsi koruyan ilk ve tek NuGet paketi.

[![NuGet](https://img.shields.io/nuget/v/QuantumDataProtection.svg)](https://www.nuget.org/packages/QuantumDataProtection)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-8%20%7C%209%20%7C%2010-blue)](https://dotnet.microsoft.com/)

---

## Neden Bu Paket Var?

ASP.NET Core Data Protection cookie'leri, session state'i ve anti-forgery token'lari sifreler. Payload **AES-256** kullanir (kuantum-guvenli). Ama **master key RSA ile sarmalanir** (kuantum-guvenli degil).

"Harvest now, decrypt later" saldirganlari sifreli trafigi bugun kaydediyor. Kuantum bilgisayarlar geldiginde RSA zarfini kiracak ve korunan tum cookie ve session'lara erisecek.

**AES sorun degil. RSA zarfi sorun. Biz onu ML-KEM ile degistiriyoruz.**

Bu cozumu sunan baska bir NuGet paketi, framework kutuphanesi veya acik kaynak proje yok — ne .NET'te, ne Java Spring'de, ne Python Django'da.

---

## Hizli Baslangic

```bash
dotnet add package QuantumDataProtection
```

```csharp
builder.Services.AddDataProtection()
    .ProtectKeysWithMlKem(options =>
    {
        options.Algorithm = MlKemAlgorithms.MlKem768;   // FIPS 203, onerilen
        options.KeyStoreDirectory = "/var/keys";
        options.KeyStorePassword = config["KeyPassword"];
    });
```

Bu kadar. Cookie'ler, session'lar, anti-forgery token'lar — artik kuantum-dayanikli.

---

## RSA / Sertifika Korumasindan Goc

Zaten `ProtectKeysWithCertificate()` veya DPAPI kullaniyorsaniz mevcut key'ler okunabilir kalir — sifir kesinti:

```csharp
builder.Services.AddDataProtection()
    .ProtectKeysWithMlKem(options =>
    {
        options.Algorithm = MlKemAlgorithms.MlKem768;
        options.KeyStoreDirectory = "/var/keys";
        options.KeyStorePassword = config["KeyPassword"];

        // Eski key'leri nasil okuyacagini belirt
        options.LegacyDecryptorType = typeof(CertificateXmlDecryptor);
    });
```

**Ne olur:**

```
Gun 0:   Deploy — eski cookie/session'lar calismaya devam eder (legacy decryptor)
         Yeni key'ler ML-KEM ile sarmalanir (kuantum-guvenli)
Gun 90:  Eski key'ler dogal olarak expire olur
Gun 91:  EnableLegacyKeyDecryption = false yap
         Tamamen kuantum-guvenli, RSA bagimliligi yok
```

---

## Nasil Calisir?

```
                    Data Protection Pipeline

    [Master Key XML]
           |
    +------+------+
    |  VARSAYILAN |     RSA key wrapping (kuantum-SAVUNMASIZ)
    |  (ASP.NET)  |     AES-256 payload sifreleme (kuantum-guvenli)
    +------+------+
           |
    +------+------+
    |  BU PAKET   |     ML-KEM key kapsulleme (kuantum-GUVENLI)
    |  ILE        |     AES-256-GCM payload sifreleme (kuantum-guvenli)
    +-------------+
```

Her Data Protection master key icin:

1. **Uret** — yeni ML-KEM keypair (key basina izolasyon = forward secrecy)
2. **Kapsule** — shared secret + KEM ciphertext
3. **Sifrele** — XML key'i AES-256-GCM ile shared secret kullanarak
4. **Sakla** — decapsulation key'i sifrelenmis olarak `IKeyStore`'a
5. **Sifirla** — shared secret'i hemen `CryptographicOperations.ZeroMemory()` ile

---

## Platform Destegi

| Platform | .NET Surum | Saglayici | Durum |
|----------|-----------|-----------|-------|
| Windows 11 / Server 2025 | .NET 10 | Native | Destekleniyor |
| Linux (OpenSSL 3.5+) | .NET 10 | Native | Destekleniyor |
| **macOS** | .NET 8/9/10 | **BouncyCastle** | **Destekleniyor** |
| **Her platform** | **.NET 8/9** | **BouncyCastle** | **Destekleniyor** |
| Eski Linux | .NET 8/9/10 | BouncyCastle | Destekleniyor |

**Otomatik saglayici secimi:** .NET 10'da native ML-KEM destegi varsa OS kripto kutuphanesini kullanir (en hizli). Yoksa BouncyCastle'a duser (her yerde calisir). Ayni API, ayni sonuc, farkli motor.

---

## Demo API

Repo'da canli demo API var:

```bash
cd examples/QuantumDataProtection.Demo
dotnet run
```

| Endpoint | Aciklama |
|----------|---------|
| `GET /` | Bilgi + endpoint listesi |
| `POST /protect` | ML-KEM Data Protection ile veri sifrele |
| `POST /unprotect` | Onceden korunan veriyi coz |
| `POST /protect-cookie` | ASP.NET Core auth cookie sifrelemesini simule et |
| `GET /key-info` | ML-KEM key store durumu |
| `GET /compare` | RSA vs ML-KEM yan yana karsilastirma |

**Ornek:**

```bash
# Sifrele
curl -X POST http://localhost:5000/protect \
  -H "Content-Type: application/json" \
  -d '{"data":"hassas-veri","purpose":"demo"}'

# Coz
curl -X POST http://localhost:5000/unprotect \
  -H "Content-Type: application/json" \
  -d '{"encrypted":"CfDJ8...","purpose":"demo"}'

# Cookie simulasyonu
curl -X POST http://localhost:5000/protect-cookie \
  -H "Content-Type: application/json" \
  -d '{"userId":"tansel","role":"admin"}'
```

---

## Anahtar Saklama

### Dahili FileKeyStore

Sifreli decapsulation key'leri diske yazar:

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
| ML-KEM-512 | 1 (128-bit) | 32 byte | 768 byte | Gelistirme |
| **ML-KEM-768** | **3 (192-bit)** | **32 byte** | **1.088 byte** | **Onerilen** |
| ML-KEM-1024 | 5 (256-bit) | 32 byte | 1.568 byte | Yuksek guvenlik |

---

## Loglama

Tum kriptografik operasyonlar `ILogger` ile loglanir:

| Olay | Seviye | Mesaj |
|------|--------|-------|
| Key uretildi | Information | ML-KEM key generated. KeyId=..., Provider=... |
| Sifreleme | Debug | XML key encrypted with ML-KEM |
| Cozme | Debug | XML key decrypted with ML-KEM |
| Legacy fallback | Warning | Legacy decryptor kullanildi |
| Platform fallback | Information | BouncyCastle kullaniliyor |

---

## Guvenlik Tasarimi

- **Key izolasyonu:** Her Data Protection key kendi ML-KEM keypair'ine sahip — forward secrecy
- **Shared secret sifirlama:** Tum shared secret'lar `CryptographicOperations.ZeroMemory()` ile hemen temizlenir
- **AES-256-GCM:** Ayri nonce ve tag ile kimlik dogrulamali sifreleme
- **Key sifreleme:** Decapsulation key'ler PBKDF2 (100K iterasyon) + AES-256-GCM ile saklanir
- **Hardcoded secret yok:** Tum key sifreleme kullanici sifresini kullanir
- **Path traversal korumasi:** FileKeyStore key ID'lerini temizler

---

## API Referansi

### Temel Siniflar

| Sinif | Aciklama |
|-------|---------|
| `MlKemKey` | ML-KEM anahtar wrapper — Native veya BouncyCastle otomatik secer |
| `MlKemXmlEncryptor` | `IXmlEncryptor` — ML-KEM + AES-256-GCM sifreleme |
| `MlKemXmlDecryptor` | `IXmlDecryptor` — ML-KEM cozme |
| `HybridXmlDecryptor` | `IXmlDecryptor` — ML-KEM ve legacy key'leri yonlendirir |
| `MlKemDataProtectionOptions` | Yapilandirma (algoritma, key store, legacy destek) |
| `IKeyStore` | Anahtar kalicilik soyutlamasi |
| `FileKeyStore` | Dosya tabanli sifreli anahtar saklama |
| `MlKemAlgorithms` | Algoritma tanimlayici sabitleri |
| `KeyEncryptionHelper` | Cross-platform PBKDF2 + AES-256-GCM key sifreleme |

### Extension Metodlar

| Metod | Aciklama |
|-------|---------|
| `ProtectKeysWithMlKem(options)` | RSA key wrapping'i ML-KEM ile degistir |

### Ayarlar

| Ozellik | Varsayilan | Aciklama |
|---------|-----------|---------|
| `Algorithm` | `MlKemAlgorithms.MlKem768` | ML-KEM varyanti |
| `KeyStoreDirectory` | — | FileKeyStore dizini |
| `KeyStorePassword` | — | Key sifreleme parolasi (zorunlu) |
| `KeyStore` | — | Ozel IKeyStore (dizin/parola yerine) |
| `EnableLegacyKeyDecryption` | `true` | Eski RSA/DPAPI key'leri okumaya izin ver |
| `LegacyDecryptorType` | — | Ornek: `typeof(CertificateXmlDecryptor)` |

---

## NIST / NSA Zaman Cizelgesi

| Tarih | Gereksinim |
|-------|-----------|
| **2024** | NIST, FIPS 203'u (ML-KEM) yayinladi |
| **2027** | NSA: tum yeni ulusal guvenlik sistemleri kuantum-guvenli olmali |
| **2030** | NSA: tam uygulama gocu son tarihi |
| **2035** | NIST: kuantum-savunmasiz algoritmalar standartlardan kaldirilacak |

---

## Bilinen Limitasyonlar

- .NET 10'daki ML-KEM API'leri `[Experimental]` (`SYSLIB5006`) — GA oncesinde degisebilir
- BouncyCastle paket boyutuna ~2MB ekler
- `IXmlEncryptor.Encrypt()` senkron — ag I/O yapan ozel `IKeyStore` uygulamalari dikkatli olmali

---

## Lisans

MIT

---

## Yazar

**Tansel DINCKAYA**

GitHub: [github.com/tdinckaya](https://github.com/tdinckaya)

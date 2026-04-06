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

Bu makalenin yazildigi tarih itibariyla, ASP.NET Core Data Protection icin ML-KEM tabanli anahtar sarmalama saglayan baska bir NuGet paketi bulunmuyor. Microsoft .NET 10 ile ham ML-KEM yapi taslarini sunuyor, ancak Data Protection entegrasyonunu sunmuyor — bu paket tam olarak o bosluga yaziliyor.

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

    [Uygulama Payload'u: cookie, session, anti-forgery token]
                  |
                  | ASP.NET Core Data Protection tarafindan sifrelenir
                  | (AES tabanli, kuantum-guvenli — bu paket degistirmez)
                  ↓
    [Master XML Key] ← disk uzerinde korunmasi gereken anahtar
                  |
        +---------+---------+
        |  VARSAYILAN        |   RSA key wrapping
        |  (ASP.NET Core)    |   (kuantum-SAVUNMASIZ)
        +---------+---------+
                  |
        +---------+---------+
        |  BU PAKET ILE      |   ML-KEM key kapsulleme (kuantum-GUVENLI)
        |                    |   XML key, ML-KEM'den gelen shared secret
        +--------------------+   ile AES-256-GCM kullanilarak sarmalanir
```

**Bu paket neyi degistirir:** yalnizca *anahtar sarmalama* katmanini — yani Data Protection master key'inin disk uzerinde nasil korundugunu. Uygulama payload sifrelemesi (cookie, session) ASP.NET Core Data Protection'in kendi AES tabanli boru hattinda kalir; bu katman zaten simetrik sifreleme icin kuantum-guvenlidir.

Her Data Protection master key icin:

1. **Uret** — yeni ML-KEM keypair (per-key isolation — her Data Protection anahtari kriptografik olarak birbirinden bagimsizdir)
2. **Kapsule** — shared secret + KEM ciphertext
3. **Sifrele** — XML key'i, shared secret'i AES-256 anahtari olarak kullanarak AES-256-GCM ile sifrele
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

- **Per-key isolation:** Her Data Protection key kendi ML-KEM keypair'ine sahiptir. Bir anahtarin ele gecirilmesi digerlerine sirayet etmez. Not: Bu "per-key isolation"dir, kesin kriptografik anlamda "forward secrecy" degildir — forward secrecy gecici (ephemeral) oturum anahtarlari gerektirir, bu farkli bir ozelliktir.
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
- ML-KEM shared secret, HKDF gibi bir anahtar turetme adimi olmadan dogrudan AES-256-GCM anahtari olarak kullaniliyor. Mevcut tehdit modeli ve kimlik dogrulamali sifreleme baglaminda kabul edilebilir, ancak NIST SP 800-227 (taslak) domain separation kilavuzundan sapar. HKDF-SHA256 turetimi (domain-separated `info` string'leri ile) ileri bir majr surumde planlanmaktadir (format degisikligi; surum header'i arkasinda sunulacaktir).
- Temeldeki ML-KEM keypair'leri icin henuz otomatik rotasyon yoktur. ASP.NET Core'un kendi Data Protection anahtar rotasyonu normal calisir; yalnizca ML-KEM key-encryption-key'leri, sarmaladigi Data Protection anahtarlarinin omru boyunca yasar. Zamanlanmis rotasyon yol haritasindadir.

---

## Lisans

MIT

---

## Yazar

**Tansel DINCKAYA**

GitHub: [github.com/tdinckaya](https://github.com/tdinckaya)

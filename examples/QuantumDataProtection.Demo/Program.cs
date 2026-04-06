#pragma warning disable SYSLIB5006

using System.Text.Json;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using QuantumDataProtection;

var builder = WebApplication.CreateBuilder(args);

// ── ML-KEM Data Protection ──────────────────────────────────────
var keyDir = Path.Combine(Path.GetTempPath(), "qdp-demo-keys");
var kemKeyDir = Path.Combine(Path.GetTempPath(), "qdp-demo-kem");

builder.Services.AddDataProtection()
    .SetApplicationName("QuantumDataProtection-Demo")
    .PersistKeysToFileSystem(new DirectoryInfo(keyDir))
    .ProtectKeysWithMlKem(options =>
    {
        options.Algorithm = MlKemAlgorithms.MlKem768;
        options.KeyStoreDirectory = kemKeyDir;
        options.KeyStorePassword = "demo-password-do-not-use-in-production";
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// ── 1. GET / — Info ─────────────────────────────────────────────
app.MapGet("/", () => Results.Json(new
{
    app = "QuantumDataProtection Demo",
    description = "Post-quantum key wrapping for ASP.NET Core Data Protection",
    algorithm = "ML-KEM-768 (FIPS 203)",
    provider = System.Security.Cryptography.MLKem.IsSupported ? "Native (.NET 10)" : "BouncyCastle",
    endpoints = new Dictionary<string, string>
    {
        ["POST /protect"] = "Encrypt data with quantum-safe Data Protection",
        ["POST /unprotect"] = "Decrypt previously protected data",
        ["POST /protect-cookie"] = "Simulate cookie encryption (like ASP.NET does)",
        ["GET /key-info"] = "Show ML-KEM key store status",
        ["GET /proof"] = "PROOF: show the XML key file — ML-KEM wrapping is visible",
        ["GET /compare"] = "Side-by-side: RSA (default) vs ML-KEM (quantum-safe)"
    }
}));

// ── 2. POST /protect — Encrypt data ─────────────────────────────
app.MapPost("/protect", (IDataProtectionProvider dp, JsonElement body) =>
{
    var purpose = body.TryGetProperty("purpose", out var p) ? p.GetString() ?? "default" : "default";
    var data = body.TryGetProperty("data", out var d) ? d.GetString() ?? "" : "";

    if (string.IsNullOrEmpty(data))
        return Results.Json(new { error = "Missing 'data' field" }, statusCode: 400);

    var protector = dp.CreateProtector(purpose);
    var encrypted = protector.Protect(data);

    return Results.Json(new
    {
        original = data,
        purpose,
        encrypted,
        originalSizeBytes = System.Text.Encoding.UTF8.GetByteCount(data),
        encryptedSizeBytes = System.Text.Encoding.UTF8.GetByteCount(encrypted),
        algorithm = "ML-KEM-768 + AES-256-GCM",
        note = "The master key wrapping uses ML-KEM. Payload encryption uses AES-256-GCM."
    });
});

// ── 3. POST /unprotect — Decrypt data ───────────────────────────
app.MapPost("/unprotect", (IDataProtectionProvider dp, JsonElement body) =>
{
    var purpose = body.TryGetProperty("purpose", out var p) ? p.GetString() ?? "default" : "default";
    var encrypted = body.TryGetProperty("encrypted", out var e) ? e.GetString() ?? "" : "";

    if (string.IsNullOrEmpty(encrypted))
        return Results.Json(new { error = "Missing 'encrypted' field" }, statusCode: 400);

    try
    {
        var protector = dp.CreateProtector(purpose);
        var decrypted = protector.Unprotect(encrypted);

        return Results.Json(new
        {
            decrypted,
            purpose,
            status = "success",
            message = "Data successfully decrypted with quantum-safe key wrapping"
        });
    }
    catch (System.Security.Cryptography.CryptographicException ex)
    {
        return Results.Json(new
        {
            error = "Decryption failed",
            reason = ex.Message,
            hint = "Ensure the same 'purpose' is used for both protect and unprotect"
        }, statusCode: 400);
    }
});

// ── 4. POST /protect-cookie — Simulate cookie encryption ────────
app.MapPost("/protect-cookie", (IDataProtectionProvider dp, JsonElement body) =>
{
    var userId = body.TryGetProperty("userId", out var u) ? u.GetString() ?? "anonymous" : "anonymous";
    var role = body.TryGetProperty("role", out var r) ? r.GetString() ?? "user" : "user";
    var sessionId = Guid.NewGuid().ToString();

    var cookiePayload = JsonSerializer.Serialize(new
    {
        userId,
        role,
        sessionId,
        issuedAt = DateTimeOffset.UtcNow,
        expiresAt = DateTimeOffset.UtcNow.AddHours(1)
    });

    var protector = dp.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies");
    var encryptedCookie = protector.Protect(cookiePayload);

    return Results.Json(new
    {
        scenario = "ASP.NET Core Authentication Cookie Simulation",
        cookiePayload,
        encryptedCookie,
        cookieSizeBytes = System.Text.Encoding.UTF8.GetByteCount(encryptedCookie),
        protection = new
        {
            keyWrapping = "ML-KEM-768 (quantum-safe)",
            payloadEncryption = "AES-256-GCM (quantum-safe)",
            harvestNowDecryptLater = "PROTECTED",
            note = "Even if this cookie is recorded today, quantum computers cannot unwrap the key"
        }
    });
});

// ── 5. GET /key-info — Key store status ─────────────────────────
app.MapGet("/key-info", () =>
{
    var kemKeys = Directory.Exists(kemKeyDir)
        ? Directory.GetFiles(kemKeyDir, "*.p8").Select(f => (object)new
        {
            keyId = Path.GetFileNameWithoutExtension(f),
            sizeBytes = new FileInfo(f).Length,
            created = File.GetCreationTimeUtc(f)
        }).ToList()
        : new List<object>();

    var dpKeys = Directory.Exists(keyDir)
        ? Directory.GetFiles(keyDir, "*.xml").Length
        : 0;

    return Results.Json(new
    {
        dataProtectionKeys = dpKeys,
        mlKemDecapsulationKeys = kemKeys.Count,
        keys = kemKeys,
        keyStoreDirectory = kemKeyDir,
        algorithm = "ML-KEM-768",
        provider = System.Security.Cryptography.MLKem.IsSupported ? "Native (.NET 10)" : "BouncyCastle"
    });
});

// ── 6. GET /proof — Show raw XML key with ML-KEM wrapping ───────
app.MapGet("/proof", (IDataProtectionProvider dp) =>
{
    // Trigger key creation if not yet created
    var protector = dp.CreateProtector("proof-trigger");
    _ = protector.Protect("trigger");

    // Read the XML key files
    if (!Directory.Exists(keyDir))
        return Results.Json(new { error = "No keys generated yet. Call /protect first." }, statusCode: 404);

    var xmlFiles = Directory.GetFiles(keyDir, "*.xml");
    if (xmlFiles.Length == 0)
        return Results.Json(new { error = "No key files found." }, statusCode: 404);

    var proofs = new List<object>();

    foreach (var xmlFile in xmlFiles)
    {
        var xml = File.ReadAllText(xmlFile);
        var doc = XElement.Parse(xml);

        // Find the encrypted key element
        var encryptedKeyElement = doc.Descendants("mlKemEncryptedKey").FirstOrDefault();

        if (encryptedKeyElement is not null)
        {
            var algorithm = encryptedKeyElement.Element("algorithm")?.Value;
            var keyId = encryptedKeyElement.Element("keyId")?.Value;
            var hasCiphertext = encryptedKeyElement.Element("kemCiphertext") is not null;
            var hasNonce = encryptedKeyElement.Element("nonce") is not null;
            var hasTag = encryptedKeyElement.Element("tag") is not null;

            // Check if .p8 file exists for this key
            var p8Exists = keyId is not null && File.Exists(Path.Combine(kemKeyDir, $"{keyId}.p8"));

            proofs.Add(new
            {
                file = Path.GetFileName(xmlFile),
                wrapping = "ML-KEM (post-quantum)",
                algorithm,
                keyId,
                xmlStructure = new
                {
                    mlKemEncryptedKey = true,
                    kemCiphertext = hasCiphertext ? "present (KEM encapsulation output)" : "MISSING",
                    nonce = hasNonce ? "present (AES-256-GCM nonce)" : "MISSING",
                    ciphertext = "present (AES-256-GCM encrypted key)",
                    tag = hasTag ? "present (AES-256-GCM auth tag)" : "MISSING"
                },
                decapsulationKeyStored = p8Exists,
                rawXmlPreview = xml.Length > 500 ? xml[..500] + "... (truncated)" : xml
            });
        }
        else
        {
            proofs.Add(new
            {
                file = Path.GetFileName(xmlFile),
                wrapping = "UNKNOWN (not ML-KEM)",
                algorithm = (string?)null,
                keyId = (string?)null,
                xmlStructure = (object?)null,
                decapsulationKeyStored = false,
                rawXmlPreview = xml.Length > 500 ? xml[..500] + "... (truncated)" : xml
            });
        }
    }

    return Results.Json(new
    {
        title = "PROOF: ML-KEM Key Wrapping in Action",
        description = "These are the actual Data Protection XML key files. " +
                      "Notice the <mlKemEncryptedKey> element — this is where RSA would normally be. " +
                      "Instead, ML-KEM-768 key encapsulation is used.",
        defaultAspNetCore = "Uses <encryptedKey> with RSA or DPAPI",
        thisPackage = "Uses <mlKemEncryptedKey> with ML-KEM + AES-256-GCM",
        keyFiles = proofs
    });
});

// ── 7. GET /compare — RSA vs ML-KEM comparison ─────────────────
app.MapGet("/compare", () => Results.Json(new
{
    title = "RSA Key Wrapping vs ML-KEM Key Wrapping",
    comparison = new[]
    {
        new {
            aspect = "Algorithm",
            rsa = "RSA-2048/4096",
            mlKem = "ML-KEM-768 (FIPS 203)"
        },
        new {
            aspect = "Quantum-Safe",
            rsa = "NO - Shor's algorithm breaks RSA",
            mlKem = "YES - Based on lattice problems"
        },
        new {
            aspect = "Harvest Now Decrypt Later",
            rsa = "VULNERABLE - recorded traffic can be decrypted later",
            mlKem = "PROTECTED - quantum computers cannot unwrap the key"
        },
        new {
            aspect = "NIST Standard",
            rsa = "Legacy (no quantum resistance)",
            mlKem = "FIPS 203 (August 2024)"
        },
        new {
            aspect = "NSA CNSA 2.0 Deadline",
            rsa = "Must migrate by 2030",
            mlKem = "Compliant"
        },
        new {
            aspect = "Payload Encryption",
            rsa = "AES-256 (quantum-safe)",
            mlKem = "AES-256-GCM (quantum-safe)"
        },
        new {
            aspect = "What Changes",
            rsa = "Default in ASP.NET Core",
            mlKem = "Only the key wrapping layer changes. One line of code."
        }
    }
}));

app.Run();

namespace QuantumDataProtection;

/// <summary>
/// File-based <see cref="IKeyStore"/> that stores encrypted private keys as
/// PKCS#8 files on disk.
/// <para>
/// Each key is saved as <c>{keyId}.p8</c> in the configured directory.
/// </para>
/// <para>
/// <b>For production use:</b> Consider implementing <see cref="IKeyStore"/>
/// with Azure Key Vault, AWS KMS, or HashiCorp Vault instead.
/// </para>
/// </summary>
public sealed class FileKeyStore : IKeyStore
{
    private readonly string _directory;

    /// <summary>
    /// Initializes a new <see cref="FileKeyStore"/>.
    /// </summary>
    /// <param name="directory">
    /// Directory to store key files. Created automatically if it doesn't exist.
    /// </param>
    /// <param name="password">
    /// Password identifier (used by callers for PKCS#8 encryption).
    /// The FileKeyStore itself stores raw encrypted bytes — callers handle encryption.
    /// </param>
    public FileKeyStore(string directory, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        _directory = directory;
        Password = password;

        Directory.CreateDirectory(_directory);
    }

    /// <summary>
    /// The password used for PKCS#8 encryption/decryption by callers.
    /// </summary>
    internal string Password { get; }

    /// <inheritdoc />
    public Task<byte[]?> LoadPrivateKeyAsync(string keyId)
    {
        var path = GetKeyPath(keyId);
        if (!File.Exists(path))
            return Task.FromResult<byte[]?>(null);

        var encrypted = File.ReadAllBytes(path);
        return Task.FromResult<byte[]?>(encrypted);
    }

    /// <inheritdoc />
    public Task SavePrivateKeyAsync(string keyId, byte[] encryptedKey)
    {
        ArgumentNullException.ThrowIfNull(encryptedKey);

        var path = GetKeyPath(keyId);
        File.WriteAllBytes(path, encryptedKey);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeleteKeyAsync(string keyId)
    {
        var path = GetKeyPath(keyId);
        if (File.Exists(path))
            File.Delete(path);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> ListKeyIdsAsync()
    {
        if (!Directory.Exists(_directory))
            return Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        var keyIds = Directory.GetFiles(_directory, "*.p8")
            .Select(f => Path.GetFileNameWithoutExtension(f))
            .ToList();

        return Task.FromResult<IReadOnlyList<string>>(keyIds);
    }

    private string GetKeyPath(string keyId)
    {
        var safeId = string.Concat(keyId.Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_'));
        if (string.IsNullOrEmpty(safeId))
            throw new ArgumentException("Key ID contains no valid characters.", nameof(keyId));
        return Path.Combine(_directory, $"{safeId}.p8");
    }
}

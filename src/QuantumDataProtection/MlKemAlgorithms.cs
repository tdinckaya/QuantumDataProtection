namespace QuantumDataProtection;

/// <summary>
/// Algorithm identifiers for ML-KEM (FIPS 203) key encapsulation.
/// </summary>
public static class MlKemAlgorithms
{
    /// <summary>ML-KEM-512 (FIPS 203, security level 1).</summary>
    public const string MlKem512 = "ML-KEM-512";

    /// <summary>ML-KEM-768 (FIPS 203, security level 3 — recommended).</summary>
    public const string MlKem768 = "ML-KEM-768";

    /// <summary>ML-KEM-1024 (FIPS 203, security level 5).</summary>
    public const string MlKem1024 = "ML-KEM-1024";

    internal static readonly HashSet<string> All = new(StringComparer.OrdinalIgnoreCase)
    {
        MlKem512, MlKem768, MlKem1024
    };

    /// <summary>
    /// Validates that the algorithm string is supported.
    /// </summary>
    internal static void Validate(string algorithm)
    {
        if (!All.Contains(algorithm))
            throw new ArgumentException(
                $"Unsupported ML-KEM algorithm: '{algorithm}'. Supported: {string.Join(", ", All)}",
                nameof(algorithm));
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Maps an algorithm string to its <see cref="System.Security.Cryptography.MLKemAlgorithm"/> instance.
    /// Only available on .NET 10+.
    /// </summary>
    internal static System.Security.Cryptography.MLKemAlgorithm ToMLKemAlgorithm(string algorithm) =>
        algorithm.ToUpperInvariant() switch
        {
            "ML-KEM-512" => System.Security.Cryptography.MLKemAlgorithm.MLKem512,
            "ML-KEM-768" => System.Security.Cryptography.MLKemAlgorithm.MLKem768,
            "ML-KEM-1024" => System.Security.Cryptography.MLKemAlgorithm.MLKem1024,
            _ => throw new ArgumentException($"Unsupported ML-KEM algorithm: {algorithm}", nameof(algorithm))
        };

    /// <summary>
    /// Returns the string identifier for a given <see cref="System.Security.Cryptography.MLKemAlgorithm"/>.
    /// </summary>
    internal static string ToAlgorithmString(System.Security.Cryptography.MLKemAlgorithm algorithm)
    {
        if (algorithm == System.Security.Cryptography.MLKemAlgorithm.MLKem512) return MlKem512;
        if (algorithm == System.Security.Cryptography.MLKemAlgorithm.MLKem768) return MlKem768;
        if (algorithm == System.Security.Cryptography.MLKemAlgorithm.MLKem1024) return MlKem1024;
        throw new ArgumentException($"Unknown MLKemAlgorithm: {algorithm.Name}", nameof(algorithm));
    }
#endif

    /// <summary>
    /// Returns the string identifier for a BouncyCastle MLKemParameters instance.
    /// </summary>
    internal static string ToAlgorithmString(Org.BouncyCastle.Crypto.Parameters.MLKemParameters bcParams)
    {
        if (bcParams == Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_512) return MlKem512;
        if (bcParams == Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_768) return MlKem768;
        if (bcParams == Org.BouncyCastle.Crypto.Parameters.MLKemParameters.ml_kem_1024) return MlKem1024;
        throw new ArgumentException($"Unknown BouncyCastle MLKemParameters", nameof(bcParams));
    }
}

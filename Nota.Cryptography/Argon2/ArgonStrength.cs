namespace Nota.Cryptography.Argon2;

public enum ArgonStrength
{
    /// <summary>For interactive sessions (fast: uses 32MB of RAM).</summary>
    Interactive,
    /// <summary>For medium use (medium: uses 64MB of RAM)</summary>
    Medium,
    /// <summary>For normal use (moderate: uses 128MB of RAM).</summary>
    Moderate,
    /// <summary>For highly sensitive data (slow: uses 512MB of RAM).</summary>
    Sensitive
}

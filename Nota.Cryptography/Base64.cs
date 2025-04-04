using System;

namespace Nota.Cryptography;

/// <summary>
/// Padding insensitive Base64 encoder.
/// </summary>
public static class Base64
{
    public static byte[] Decode(string encoded)
    {
        string padding = (encoded.Length % 4) switch
        {
            1 => "=",
            2 => "==",
            3 => "=",
            _ => string.Empty,
        };
        return Convert.FromBase64String(encoded + padding);
    }

    public static string Encode(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=');
    }
}

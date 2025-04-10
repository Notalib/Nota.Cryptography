/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nota.Cryptography.Argon2;

/// <summary>
/// Utility for encoding and decoding Argon2 hashes.
/// Used by Argon2PasswordEncoder.
///
/// Author: Simeon Macke.
/// </summary>
[SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1629:Documentation text should end with a period", Justification = "False positives.")]
internal static class Argon2EncodingUtils
{
    /// <summary>
    /// Encodes a raw Argon2-hash and its parameters into the standard Argon2-hash-string
    /// as specified in the reference implementation
    /// (https://github.com/P-H-C/phc-winner-argon2/blob/master/src/encoding.c#L244).
    ///
    /// <code>$argon2(T)[$v=(num)]$m=(num),t=(num),p=(num)$(bin)$(bin)</code>
    ///
    ///  where: <code>(T)</code> is either 'd', 'id', or 'i', (num) is a decimal integer
    /// (positive, fits in an 'unsigned long'), and (bin) is Base64-encoded data
    ///  (no '=' padding characters, no newline or whitespace).
    ///
    /// The last two binary chunks (encoded in Base64) are, in that order, the salt and the output.
    /// If no salt has been used, the salt will be omitted.
    /// </summary>
    /// <param name="hash">the raw Argon2 hash in binary format.</param>
    /// <param name="parameters">the Argon2 parameters that were used to create the hash.</param>
    /// <returns>the encoded Argon2-hash-string as described above.</returns>
    /// <exception cref="ArgumentException">If the Argon2Parameters are invalid.</exception>
    public static string Encode(byte[] hash, Argon2Parameters parameters)
    {
        byte[] salt = parameters.GetSalt();
        string type = parameters.Type switch
        {
            Argon2Constants.Argon2d => "$argon2d",
            Argon2Constants.Argon2i => "$argon2i",
            Argon2Constants.Argon2id => "$argon2id",
            _ => throw new ArgumentException("Invalid algorithm type: " + parameters.Type),
        };
        
        return $"{type}$v={parameters.Version}$m={parameters.Memory},t={parameters.Iterations},p={parameters.Parallelism}${Base64.Encode(salt)}${Base64.Encode(hash)}";
    }

    /// <summary>
    /// Decodes an Argon2 hash string as specified in the reference implementation
    /// (https://github.com/P-H-C/phc-winner-argon2/blob/master/src/encoding.c#L244) into
    /// the raw hash and the used parameters.
    ///
    /// The hash has to be formatted as follows:
    /// <code>$argon2(T)[$v=(num)]$m=(num),t=(num),p=(num)$(bin)$(bin)</code>
    /// where <code>(T)</code>} is either 'd', 'id', or 'i', <code>(num)</code> is a decimal integer
    /// (positive, fits in an 'unsigned long'), and <code>(bin)</code> is Base64-encoded data
    /// (no '=' padding characters, no newline or whitespace).
    ///
    /// The last two binary chunks (encoded in Base64) are, in that order, the salt and the output.
    /// Both are required. The binary salt length and the output length must be in
    /// the allowed ranges defined in argon2.h.
    /// </summary>
    /// <param name="encodedHash">the Argon2 hash string as described above.</param>
    /// <returns>An object containing the raw hash and the Argon2Hash.</returns>
    /// <exception cref="ArgumentException">If the encoded hash is malformed.</exception>
    public static Argon2Hash Decode(string encodedHash)
    {
        string[] parts = encodedHash.Split('$');
        if (parts.Length < 4)
        {
            throw new ArgumentException("Invalid encoded Argon2-hash");
        }

        int currentPart = 1;
        Argon2Parameters.Builder paramsBuilder = parts[currentPart++] switch
        {
            "argon2d" => new Argon2Parameters.Builder(Argon2Constants.Argon2d),
            "argon2i" => new Argon2Parameters.Builder(Argon2Constants.Argon2i),
            "argon2id" => new Argon2Parameters.Builder(Argon2Constants.Argon2id),
            _ => throw new ArgumentException("Invalid algorithm type: " + parts[0]),
        };

        paramsBuilder.WithCharToByteConverter(PasswordConverter.Utf8);

        if (parts[currentPart].StartsWith("v=") && int.TryParse(parts[currentPart].Substring(2), out int version))
        {
            paramsBuilder.WithVersion(version);
            currentPart++;
        }

        string[] performanceParams = parts[currentPart++].Split(',');

        if (performanceParams.Length != 3)
        {
            throw new ArgumentException("Amount of performance parameters invalid");
        }

        if (!performanceParams[0].StartsWith("m=") || !int.TryParse(performanceParams[0].Substring(2), out int memory))
        {
            throw new ArgumentException("Invalid memory parameter");
        }
        paramsBuilder.WithMemoryAsKB(memory);

        if (!performanceParams[1].StartsWith("t=") || !int.TryParse(performanceParams[1].Substring(2), out int iterations))
        {
            throw new ArgumentException("Invalid iterations parameter");
        }
        paramsBuilder.WithIterations(iterations);
        
        if (!performanceParams[2].StartsWith("p=") || !int.TryParse(performanceParams[2].Substring(2), out int parallelism))
        {
            throw new ArgumentException("Invalid parallelism parameter");
        }

        paramsBuilder.WithParallelism(parallelism);

        byte[] salt = Base64.Decode(parts[currentPart++]);
        paramsBuilder.WithSalt(salt);

        byte[] hash = Base64.Decode(parts[currentPart]);
        return new Argon2Hash(hash, paramsBuilder.Build());
    }
}

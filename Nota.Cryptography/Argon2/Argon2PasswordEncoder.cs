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

// Borrowed from spring-security and converted to C#.
// https://github.com/spring-projects/spring-security/tree/main/crypto/src/main/java/org/springframework/security/crypto/argon2
using System;
using System.Linq;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nota.Cryptography.Argon2;

/// <summary>
/// Implementation of PasswordEncoder that uses the Argon2 hashing function.
/// Clients can optionally supply the length of the salt to use,
/// the length of the generated hash, cpu cost parameter, a memory cost parameter,
/// and a parallelization parameter.
///
/// The current implementation uses Bouncy castle which does not exploit
/// parallelism/optimizations that password crackers will,
/// so there is an unnecessary asymmetry between attacker and defender.
///
/// Author: Simeon Macke.
/// </summary>
public class Argon2PasswordEncoder : IPasswordEncoder
{
    private const int DefaultSaltLength = 16;
    private const int DefaultHashLength = 32;
    private const int DefaultParallelism = 1;

    private readonly int _saltLength;
    private readonly int _hashLength;
    private readonly int _parallelism;
    private readonly int _memory;
    private readonly int _iterations;

    internal IRandomNumberGenerator SaltGenerator { get; set; }

    /// <summary>
    /// Constructs an Argon2 password encoder with the provided parameters.
    /// </summary>
    /// <param name="saltLength">the salt length (in bytes).</param>
    /// <param name="hashLength">the hash length (in bytes).</param>
    /// <param name="parallelism">the parallelism level.</param>
    /// <param name="memory">the memory cost.</param>
    /// <param name="iterations">the number of iterations.</param>
    public Argon2PasswordEncoder(int saltLength, int hashLength, int parallelism, int memory, int iterations)
    {
        _hashLength = hashLength;
        _parallelism = parallelism;
        _memory = memory;
        _iterations = iterations;
        _saltLength = saltLength;
        SaltGenerator = new RandomNumberGenerator();
    }

    /// <summary>
    /// Constructs an Argon2 password encoder with a salt length of 16 bytes, a hash length of 32 bytes,
    /// parallelism of 1, memory cost of 1 &lt;&lt; 14 and 2 iterations.
    /// </summary>
    public Argon2PasswordEncoder()
        : this(ArgonStrength.Medium)
    {
    }
    
    /// <summary>
    /// Constructs an Argon2 password encoder with a salt length of 16 bytes, a hash length of 32 bytes,
    /// parallelism of 1, memory cost of 1 &lt;&lt; 14 and 2 iterations.
    /// </summary>
    public Argon2PasswordEncoder(ArgonStrength strength)
        : this(DefaultSaltLength,
               DefaultHashLength,
               DefaultParallelism, 
               GetArgonOpsAndMemoryLimit(strength).memLimit, 
               GetArgonOpsAndMemoryLimit(strength).opsLimit)
    {
    }
    
    private static (int opsLimit, int memLimit) GetArgonOpsAndMemoryLimit(ArgonStrength limit)
    {
        return limit switch
        {
             ArgonStrength.Medium => (Argon2Constants.OpsLimit.Medium, Argon2Constants.MemoryLimit.Medium),
             ArgonStrength.Moderate => (Argon2Constants.OpsLimit.Moderate, Argon2Constants.MemoryLimit.Moderate),
             ArgonStrength.Sensitive => (Argon2Constants.OpsLimit.Sensitive, Argon2Constants.MemoryLimit.Sensitive),
            _ => (Argon2Constants.OpsLimit.Interactive, Argon2Constants.MemoryLimit.Interactive),
        };
    }
    /// <inheritdoc cref="IPasswordEncoder"/>
    public string Encode(string rawPassword)
    {
        byte[] salt = SaltGenerator.GetBytes(_saltLength);
        byte[] hash = new byte[_hashLength];

        Argon2Parameters argon2Parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithSalt(salt)
            .WithParallelism(_parallelism)
            .WithMemoryAsKB(_memory)
            .WithIterations(_iterations)
            .WithCharToByteConverter(PasswordConverter.Utf8)
            .Build();

        Argon2BytesGenerator generator = new();

        generator.Init(argon2Parameters);
        generator.GenerateBytes(rawPassword.ToCharArray(), hash);

        return Argon2EncodingUtils.Encode(hash, argon2Parameters);
    }

    /// <inheritdoc cref="IPasswordEncoder"/>
    public bool Matches(string rawPassword, string? encodedPassword)
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(encodedPassword);
#else
        if (encodedPassword is null)
        {
            throw new ArgumentNullException(nameof(encodedPassword));
        }
#endif
        Argon2Hash decoded = Argon2EncodingUtils.Decode(encodedPassword);

        byte[] hashBytes = new byte[decoded.Hash.Length];

        Argon2BytesGenerator generator = new();
        generator.Init(decoded.Parameters);
        generator.GenerateBytes(rawPassword.ToArray(), hashBytes);

        return SecureComparison.ConstantTimeEquality(decoded.Hash, hashBytes);
    }

    /// <inheritdoc cref="IPasswordEncoder"/>
    public bool UpgradeEncoding(string? encodedPassword)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(encodedPassword);
#else        
        if (encodedPassword is null)
        {
            throw new ArgumentNullException(nameof(encodedPassword));
        }
        else if (encodedPassword.Length == 0)
        {
            throw new ArgumentException(nameof(encodedPassword));
        }
#endif
        Argon2Parameters parameters = Argon2EncodingUtils.Decode(encodedPassword!).Parameters;
        return parameters.Memory < _memory || parameters.Iterations < _iterations;
    }
}

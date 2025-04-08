/*
 * Copyright 2024-2025 the original author or authors.
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
using System.Linq;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nota.Cryptography;

/// <summary>
/// Implementation of the Sodium SecretBox algorithm using primitives from BouncyCastle.NET.
/// Made by Topaco (https://stackoverflow.com/a/78742619),
/// </summary>
public static class SecretBox
{
    public const int NonceBytes = 192 / 8;

    public const int KeyBytes = 256 / 8;

    // Poly1305 implementation uses a 128 bit MAC.
    public const int MacBytes = 128 / 8;

    internal static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext)
    {
        XSalsa20Engine xSalsa20Engine = new();
        xSalsa20Engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        // generate mac key
        byte[] macKey = new byte[KeyBytes];
        xSalsa20Engine.ProcessBytes(macKey, 0, macKey.Length, macKey, 0);

        // encrypt plaintext
        byte[] ciphertext = new byte[plaintext.Length];
        xSalsa20Engine.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

        // generate mac
        Poly1305 poly1305 = new();
        poly1305.Init(new KeyParameter(macKey));

        byte[] mac = new byte[MacBytes];
        poly1305.BlockUpdate(ciphertext, 0, plaintext.Length); // ciphertext size = plaintext size
        poly1305.DoFinal(mac, 0);

        // concatenate, e.g. nonce|mac|ciphertext
        return nonce.Concat(mac).Concat(ciphertext).ToArray();
    }
    
    public static byte[] Encrypt(byte[] key, byte[] plaintext)
    {
        using RandomNumberGenerator rng = new();

        // generate random nonce
        byte[] nonce = rng.GetBytes(NonceBytes);

        return Encrypt(key, nonce, plaintext);
    }

    public static byte[]? Decrypt(byte[] key, byte[] nonceMacCiphertext)
    {
        // separate nonce, mac and ciphertext
        Poly1305 poly1305 = new();

        byte[] nonce = new byte[NonceBytes];
        byte[] mac = new byte[MacBytes];
        byte[] ciphertext = new byte[nonceMacCiphertext.Length - MacBytes - NonceBytes];

        Array.Copy(nonceMacCiphertext, 0, nonce, 0, nonce.Length);
        Array.Copy(nonceMacCiphertext, NonceBytes, mac, 0, MacBytes);
        Array.Copy(nonceMacCiphertext, NonceBytes + MacBytes, ciphertext, 0, nonceMacCiphertext.Length - NonceBytes - MacBytes);

        XSalsa20Engine xSalsa20Engine = new();
        xSalsa20Engine.Init(false, new ParametersWithIV(new KeyParameter(key), nonce));

        // generate mac key
        byte[] macKey = new byte[KeyBytes];
        xSalsa20Engine.ProcessBytes(macKey, 0, macKey.Length, macKey, 0);

        // calculate Mac
        byte[] macCalculated = new byte[MacBytes];
        poly1305.Init(new KeyParameter(macKey));
        poly1305.BlockUpdate(ciphertext, 0, ciphertext.Length);
        poly1305.DoFinal(macCalculated, 0);

        // decrypt on successful authentication
        if (!SecureComparison.ConstantTimeEquality(macCalculated, mac))
        {
            return null;
        }

        byte[] decrypted = new byte[ciphertext.Length];
        xSalsa20Engine.ProcessBytes(ciphertext, 0, ciphertext.Length, decrypted, 0);

        return decrypted;
    }
}

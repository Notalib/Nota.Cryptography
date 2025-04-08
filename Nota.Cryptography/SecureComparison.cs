/*
 * Copyright 2025 the original author or authors.
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

namespace Nota.Cryptography;

public static class SecureComparison
{
    /// <summary>
    /// Compares two byte arrays in length-constant time. This comparison method is used so that key information cannot be extracted from on-line systems using a timing attack and then attacked off-line.
    ///
    /// Note: This method will leak information about the length of the hashed message.
    /// </summary>
    /// <param name="a">First byte array.</param>
    /// <param name="b">Second byte array.</param>
    /// <returns>Whether the two byte arrays are equal.</returns>
    public static bool ConstantTimeEquality(byte[] a, byte[] b)
    {
        uint diff = (uint)a.Length ^ (uint)b.Length;
        for (int i = 0; i < a.Length && i < b.Length; i++)
        {
            diff |= (uint)(a[i] ^ b[i]);
        }

        return diff == 0;
    }

    /// <summary>
    /// Compares two string in length-constant time. This comparison method is used so that key information cannot be extracted from on-line systems using a timing attack and then attacked off-line.
    ///
    /// Note: This method will leak information about the length of the hashed message.
    /// </summary>
    /// <param name="a">First string.</param>
    /// <param name="b">Second strings.</param>
    /// <returns>Whether the two strings are equal.</returns>
    public static bool ConstantTimeEquality(string a, string b)
    {
        uint diff = (uint)a.Length ^ (uint)b.Length;
        for (int i = 0; i < a.Length && i < b.Length; i++)
        {
            diff |= (uint)(a[i] ^ b[i]);
        }

        return diff == 0;
    }
}

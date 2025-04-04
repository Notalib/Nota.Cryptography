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
using System;

namespace Nota.Cryptography;

/// <summary>
/// Padding insensitive Base64 de/encoder.
/// </summary>
public static class Base64
{
    // .NET's base64 decoder does NOT accept unpadded base64 data, so add it.
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

    // Trim off any padding.
    public static string Encode(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=');
    }
}

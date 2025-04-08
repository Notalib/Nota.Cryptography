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

public interface IPasswordEncoder
{
    /// <summary>
    /// Encode the raw password.
    /// </summary>
    /// <param name="rawPassword">Password to encode.</param>
    /// <returns>One way encoded password.</returns>
    string Encode(string rawPassword);

    /// <summary>
    /// Verify the encoded password obtained from storage matches the submitted raw
    /// password after it too is encoded. Returns true if the passwords match,
    /// false if they do not. The stored password itself is never decoded.
    /// </summary>
    /// <param name="rawPassword"></param>
    /// <param name="encodedPassword"></param>
    /// <returns></returns>
    bool Matches(string rawPassword, string? encodedPassword);

    /// <summary>
    /// Returns true if the encoded password should be encoded again for better security,
    /// else false. The default implementation always returns false.
    /// </summary>
    /// <param name="encodedPassword">The encoded password to check.</param>
    /// <returns>true if the encoded password should be encoded again for better security, else false.</returns>
    bool UpgradeEncoding(string? encodedPassword);
}

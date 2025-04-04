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
using Nota.Cryptography.Argon2;

namespace Nota.Cryptography.Test;

public class SodiumCompatibilty
{
    [Theory]
    [InlineData("lol", "$argon2id$v=19$m=32768,t=4,p=1$hpzXc4WKvufO8pLbVp5SAQ$9PnUVB2tJVKyPTKDUkq+vqKxvK7QEkR0K8zDnu62hSI")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "$argon2id$v=19$m=32768,t=4,p=1$H4Wf53/lD567l1TbH/74TQ$XaIlqaqEWIZgPqfWVz2lFSFlxiHIwAWM6+6y9fha59U")]
    [InlineData("也称乱数假文或者哑元文本", "$argon2id$v=19$m=32768,t=4,p=1$LZQ6b8tlce4Ev4VTCbzZSg$5HqdMSyNnGNJxa4sAGA85dufnpPjp4ZKFWzHbTuARvw")]
    public void ValidatesSodiumArgonHashes(string password, string hash)
    {
        IPasswordEncoder encoder = new Argon2PasswordEncoder();

        Assert.True(encoder.Matches(password, hash));
    }
}

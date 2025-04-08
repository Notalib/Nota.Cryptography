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

using System.Text;

using Microsoft.IdentityModel.Tokens;

using Nota.Cryptography.Argon2;

namespace Nota.Cryptography.Test;

public class SodiumCompatibilty
{
    private static readonly byte[] KnownSecretBoxKey = Convert.FromBase64String("RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUU=");

    [Theory]
    [InlineData("lol", "$argon2id$v=19$m=32768,t=4,p=1$hpzXc4WKvufO8pLbVp5SAQ$9PnUVB2tJVKyPTKDUkq+vqKxvK7QEkR0K8zDnu62hSI")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "$argon2id$v=19$m=32768,t=4,p=1$H4Wf53/lD567l1TbH/74TQ$XaIlqaqEWIZgPqfWVz2lFSFlxiHIwAWM6+6y9fha59U")]
    [InlineData("也称乱数假文或者哑元文本", "$argon2id$v=19$m=32768,t=4,p=1$LZQ6b8tlce4Ev4VTCbzZSg$5HqdMSyNnGNJxa4sAGA85dufnpPjp4ZKFWzHbTuARvw")]
    public void ValidatesSodiumArgonHashes(string password, string hash)
    {
        IPasswordEncoder encoder = new Argon2PasswordEncoder();

        Assert.True(encoder.Matches(password, hash));
    }
    
    [Theory]
    [InlineData("{\"subject\":\"10140345\",\"url\":\"https://localhost/test\"}", "xl-AFb_8LBIZaOumRxULIENXr0zBtQ2V.Wb47ADHfqCdBwEWras7ENXhEYqYtCCHyO3r9XP0GyVYSTJ76ygTDbXZClDKKeN0nA2LEyKP0m4vJKKa5RUqjOdJbimoN")]
    [InlineData("{\"subject\":\"10140345\",\"url\":\"https://localhost/\\u4E5F\\u79F0\\u4E71\\u6570\\u5047\\u6587\\u6216\\u8005\\u54D1\\u5143\\u6587\\u672C\"}", "4U652KEgQb6_wR6GbvQuYgJDfgOtQNuP.Wc9Ut6qeCyCUtFhBqHScXIqnaCe3bQr8fIxhxkOzEUBMz3_hylVgsdfDj-am7e8bmoK1BYu7V4XPcgVo0slFqbOr1Lwekkqk7RNCt4AUHB3o8wwd2Kf4SYchkG1vA-gpBbZHh69q-XPKsT-YRWj8AzW0cmtsNVP8Z6zuohcNoyzguLMfiNigWvE")]
    public void DecryptsSodiumSecretBoxes(string expectedPlainText, string boxed)
    {
        byte[] ciphertext = Base64UrlEncoder.DecodeBytes(boxed.Replace(".", ""));

        byte[]? decrypted = SecretBox.Decrypt(KnownSecretBoxKey, ciphertext);

        Assert.NotNull(decrypted);
        
        string decryptedString = Encoding.UTF8.GetString(decrypted);
        Assert.Equal(expectedPlainText, decryptedString);
    }
}

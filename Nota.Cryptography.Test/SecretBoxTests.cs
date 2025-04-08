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

namespace Nota.Cryptography.Test;

public class SecretBoxTests
{
    private static readonly byte[] Key;

    static SecretBoxTests()
    {
        using RandomNumberGenerator rng = new();
        Key = rng.GetBytes(SecretBox.KeyBytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")]
    [InlineData("也称乱数假文或者哑元文本")]
    public void SecretBoxIsReopenable(string input)
    {
        byte[] encrypted = SecretBox.Encrypt(Key, Encoding.UTF8.GetBytes(input));
        byte[]? decrypted = SecretBox.Decrypt(Key, encrypted);

        Assert.NotNull(decrypted);
        Assert.Equal(input, Encoding.UTF8.GetString(decrypted));
    }
    
    [Fact]
    public void CipheredTextDiffersWithDifferentNonce()
    {
        string input = "छप\u093eई और अक\u094dषर य\u094bजन उद\u094dय\u094bग क\u093e एक स\u093eध\u093eरण डम\u0940 प\u093eठ ह\u0948";
        byte[] encrypted = SecretBox.Encrypt(Key, Encoding.UTF8.GetBytes(input));
        byte[] encrypted2 = SecretBox.Encrypt(Key, Encoding.UTF8.GetBytes(input));

        Assert.NotEqual(encrypted, encrypted2);
    }
    
    [Fact]
    public void CipheredTextDoesNotDifferWithSameNonce()
    {
        using RandomNumberGenerator rng = new();
        
        byte[] nonce = rng.GetBytes(SecretBox.NonceBytes);
        string input = "це текст-\"риба\", що використовується в друкарстві та дизайні";
        
        byte[] encrypted = SecretBox.Encrypt(Key, nonce, Encoding.UTF8.GetBytes(input));
        byte[] encrypted2 = SecretBox.Encrypt(Key, nonce, Encoding.UTF8.GetBytes(input));

        Assert.Equal(encrypted, encrypted2);
    }
}

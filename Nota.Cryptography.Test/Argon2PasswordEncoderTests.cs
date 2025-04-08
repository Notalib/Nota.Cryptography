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

using Nota.Cryptography.Argon2;

namespace Nota.Cryptography.Test;

// Author: Simeon Macke.
// Translated to C# by Nota.
public class Argon2PasswordEncoderTests
{
    private Argon2PasswordEncoder _encoder = new Argon2PasswordEncoder();

    [Fact]
    public void EncodeDoesNotEqualPassword()
    {
        string result = _encoder.Encode("password");
        Assert.NotEqual("password", result);
    }

    [Fact]
    public void EncodeWhenEqualPasswordThenMatches()
    {
        string result = _encoder.Encode("password");

        Assert.True(_encoder.Matches("password", result));
    }

    [Fact]
    public void EncodeWhenEqualWithUnicodeThenMatches()
    {
        string result = _encoder.Encode("passw\u9292rd");

        Assert.False(_encoder.Matches("pass\u9292\u9292rd", result));
        Assert.True(_encoder.Matches("passw\u9292rd", result));
    }

    [Fact]
    public void EncodeWhenNotEqualThenNotMatches()
    {
        string result = _encoder.Encode("password");

        Assert.False(_encoder.Matches("bogus", result));
    }

    [Fact]
    public void EncodeWhenEqualPasswordWithCustomParamsThenMatches()
    {
        _encoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);
        string result = _encoder.Encode("password");

        Assert.True(_encoder.Matches("password", result));
    }

    [Fact]
    public void EncodeWhenRanTwiceThenResultsNotEqual()
    {
        string password = "secret";

        Assert.NotEqual(_encoder.Encode(password), _encoder.Encode(password));
    }

    [Fact]
    public void EncodeWhenRanTwiceWithCustomParamsThenNotEquals()
    {
        string password = "secret";
        _encoder = new Argon2PasswordEncoder(20, 64, 4, 256, 4);

        Assert.NotEqual(_encoder.Encode(password), _encoder.Encode(password));
    }

    [Fact]
    public void MatchesWhenGeneratedWithDifferentEncoderThenTrue()
    {
        string password = "secret";
        Argon2PasswordEncoder oldEncoder = new(20, 64, 4, 256, 4);
        Argon2PasswordEncoder newEncoder = new();

        string oldEncodedPassword = oldEncoder.Encode(password);

        Assert.True(newEncoder.Matches(password, oldEncodedPassword));
    }

    [Fact]
    public void MatchesWhenEncodedPassIsNullThenFalse()
    {
        Assert.Throws<ArgumentNullException>(() => _encoder.Matches("password", null));
    }

    [Fact]
    public void MatchesWhenEncodedPassIsEmptyThenFalse()
    {
        Assert.Throws<ArgumentException>(() => _encoder.Matches("password", string.Empty));
    }

    [Fact]
    public void MatchesWhenEncodedPassIsBogusThenFalse()
    {
        Assert.Throws<ArgumentException>(() => _encoder.Matches("password",  "012345678901234567890123456789"));
    }

    [Fact]
    public void EncodeWhenUsingPredictableSaltThenEqualTestHash()
    {
        string expectedHash = "$argon2id$v=19$m=16384,t=2,p=1$QUFBQUFBQUFBQUFBQUFBQQ$zGt5MiNPSUOo4/7jBcJMayCPfcsLJ4c0WUxhwGDIYPw";

        _encoder = new Argon2PasswordEncoder(16, 32, 1, 16384, 2)
        {
            SaltGenerator = new MockPredictableNumberGenerator(0x41),
        };
        string hash = _encoder.Encode("sometestpassword");

        Assert.Equal(expectedHash, hash);
    }

    [Fact]
    public void EncodeWhenUsingPredictableSaltWithCustomParamsThenEqualTestHash()
    {
        string expectedHash = "$argon2id$v=19$m=512,t=5,p=4$QUFBQUFBQUFBQUFBQUFBQQ$PNv4C3K50bz3rmON+LtFpdisD7ePieLNq+l5iUHgc1k";

        _encoder = new Argon2PasswordEncoder(16, 32, 4, 512, 5)
        {
            SaltGenerator = new MockPredictableNumberGenerator(0x41),
        };

        string hash = _encoder.Encode("sometestpassword");

        Assert.Equal(expectedHash, hash);
    }

    [Fact]
    public void UpgradeEncodingWhenSameEncodingThenFalse()
    {
        string hash = _encoder.Encode("password");

        Assert.False(_encoder.UpgradeEncoding(hash));
    }

    [Fact]
    public void UpgradeEncodingWhenSameStandardParamsThenFalse()
    {
        Argon2PasswordEncoder newEncoder = new();

        string hash = _encoder.Encode("password");

        Assert.False(newEncoder.UpgradeEncoding(hash));
    }

    [Fact]
    public void UpgradeEncodingWhenSameCustomParamsThenFalse()
    {
        Argon2PasswordEncoder oldEncoder = new(20, 64, 4, 256, 4);
        Argon2PasswordEncoder newEncoder = new(20, 64, 4, 256, 4);

        string hash = oldEncoder.Encode("password");

        Assert.False(newEncoder.UpgradeEncoding(hash));
    }

    [Fact]
    public void UpgradeEncodingWhenHashHasLowerMemoryThenTrue()
    {
        Argon2PasswordEncoder oldEncoder = new(20, 64, 4, 256, 4);
        Argon2PasswordEncoder newEncoder = new(20, 64, 4, 512, 4);

        string hash = oldEncoder.Encode("password");

        Assert.True(newEncoder.UpgradeEncoding(hash));
    }

    [Fact]
    public void UpgradeEncodingWhenHashHasLowerIterationsThenTrue()
    {
        Argon2PasswordEncoder oldEncoder = new(20, 64, 4, 256, 4);
        Argon2PasswordEncoder newEncoder = new(20, 64, 4, 256, 5);

        string hash = oldEncoder.Encode("password");

        Assert.True(newEncoder.UpgradeEncoding(hash));
    }

    [Fact]
    public void UpgradeEncodingWhenHashHasHigherParamsThenFalse()
    {
        Argon2PasswordEncoder oldEncoder = new(20, 64, 4, 256, 4);
        Argon2PasswordEncoder newEncoder = new(20, 64, 4, 128, 3);

        string hash = oldEncoder.Encode("password");

        Assert.False(newEncoder.UpgradeEncoding(hash));
    }

    [Fact]
    public void UpgradeEncodingWhenEncodedPassIsNullThenFalse()
    {
        Assert.Throws<ArgumentNullException>(() => _encoder.UpgradeEncoding(null));
    }

    [Fact]
    public void UpgradeEncodingWhenEncodedPassIsEmptyThenFalse()
    {
        Assert.Throws<ArgumentException>(() => _encoder.UpgradeEncoding(string.Empty));
    }

    [Fact]
    public void UpgradeEncodingWhenEncodedPassIsBogusThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => _encoder.UpgradeEncoding("thisIsNoValidHash"));
    }
}

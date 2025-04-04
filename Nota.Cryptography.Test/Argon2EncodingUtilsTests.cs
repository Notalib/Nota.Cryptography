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

using Org.BouncyCastle.Crypto.Parameters;

namespace Nota.Cryptography.Test;

// Author: Simeon Macke.
// Translated to C# by Nota.
public class Argon2EncodingUtilsTests
{
    private TestDataEntry _testDataEntry1 = new(
        "$argon2i$v=19$m=1024,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs",
        new Argon2Hash(Base64.Decode("cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"),
            (new Argon2Parameters.Builder(Argon2Parameters.Argon2i)).WithVersion(19)
            .WithMemoryAsKB(1024)
            .WithIterations(3)
            .WithParallelism(2)
            .WithSalt(Base64.Decode("cRdFbCw23gz2Mlxk"))
            .Build()));

    private TestDataEntry _testDataEntry2 = new(
        "$argon2id$v=19$m=333,t=5,p=2$JDR8N3k1QWx0$+PrEoHOHsWkU9lnsxqnOFrWTVEuOh7ZRIUIbe2yUG8FgTYNCWJfHQI09JAAFKzr2JAvoejEpTMghUt0WsntQYA",
        new Argon2Hash(
            Base64.Decode(
                "+PrEoHOHsWkU9lnsxqnOFrWTVEuOh7ZRIUIbe2yUG8FgTYNCWJfHQI09JAAFKzr2JAvoejEpTMghUt0WsntQYA"),
            (new Argon2Parameters.Builder(Argon2Parameters.Argon2id)).WithVersion(19)
            .WithMemoryAsKB(333)
            .WithIterations(5)
            .WithParallelism(2)
            .WithSalt(Base64.Decode("$4|7y5Alt"))
            .Build()));

    [Fact]
    public void DecodeWhenValidEncodedHashWithIThenDecodeCorrectly()
    {
        AssertArgon2HashEquals(_testDataEntry1.Decoded, Argon2EncodingUtils.Decode(_testDataEntry1.Encoded));
    }

    [Fact]
    public void DecodeWhenValidEncodedHashWithIdThenDecodeCorrectly()
    {
        AssertArgon2HashEquals(_testDataEntry2.Decoded, Argon2EncodingUtils.Decode(_testDataEntry2.Encoded));
    }

    [Fact]
    public void EncodeWhenValidArgumentsWithIThenEncodeToCorrectHash()
    {
        Assert.Equal(_testDataEntry1.Encoded, Argon2EncodingUtils.Encode(_testDataEntry1.Decoded.Hash,
            _testDataEntry1.Decoded.Parameters));
    }

    [Fact]
    public void EncodeWhenValidArgumentsWithId2ThenEncodeToCorrectHash()
    {
        Assert.Equal(_testDataEntry2.Encoded, Argon2EncodingUtils.Encode(_testDataEntry2.Decoded.Hash,
            _testDataEntry2.Decoded.Parameters));
    }

    [Fact]
    public void EncodeWhenNonexistingAlgorithmThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils.Encode([0, 1, 2, 3],
            (new Argon2Parameters.Builder(3)).WithVersion(19)
            .WithMemoryAsKB(333)
            .WithIterations(5)
            .WithParallelism(2)
            .Build()));
    }

    [Fact]
    public void DecodeWhenNotAnArgon2HashThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils.Decode("notahash"));
    }

    [Fact]
    public void DecodeWhenNonexistingAlgorithmThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2x$v=19$m=1024,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenIllegalVersionParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$v=x$m=1024,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenIllegalMemoryParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$v=19$m=x,t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenIllegalIterationsParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$v=19$m=1024,t=x,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenIllegalParallelityParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$v=19$m=1024,t=3,p=x$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenMissingVersionParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$m=1024,t=3,p=x$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenMissingMemoryParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$v=19$t=3,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenMissingIterationsParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$v=19$m=1024,p=2$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    [Fact]
    public void DecodeWhenMissingParallelityParameterThenThrowException()
    {
        Assert.Throws<ArgumentException>(() => Argon2EncodingUtils
            .Decode("$argon2i$v=19$m=1024,t=3$Y1JkRmJDdzIzZ3oyTWx4aw$cGE5Cbd/cx7micVhXVBdH5qTr66JI1iUyuNNVAnErXs"));
    }

    private void AssertArgon2HashEquals(Argon2Hash expected,
        Argon2Hash actual)
    {
        Assert.Equal(expected.Hash, actual.Hash);
        Assert.Equal(expected.Parameters.GetSalt(), actual.Parameters.GetSalt());
        Assert.Equal(expected.Parameters.Type, actual.Parameters.Type);
        Assert.Equal(expected.Parameters.Version, actual.Parameters.Version);
        Assert.Equal(expected.Parameters.Memory, actual.Parameters.Memory);
        Assert.Equal(expected.Parameters.Iterations, actual.Parameters.Iterations);
        Assert.Equal(expected.Parameters.Parallelism, actual.Parameters.Parallelism);
    }

    private class TestDataEntry
    {
        public string Encoded { get; set; }

        public Argon2Hash Decoded { get; set; }

        public TestDataEntry(string encoded, Argon2Hash decoded)
        {
            Encoded = encoded;
            Decoded = decoded;
        }
    }
}

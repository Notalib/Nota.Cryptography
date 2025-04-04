namespace Nota.Cryptography.Test;

public class MockPredictableNumberGenerator : IRandomNumberGenerator
{
    private readonly byte _value;

    public MockPredictableNumberGenerator(byte value)
    {
        _value = value;
    }

    public byte[] GetBytes(int length)
    {
        byte[] bytes = new byte[length];
        Array.Fill(bytes, _value);

        return bytes;
    }
}

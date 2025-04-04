using System;

namespace Nota.Cryptography;

public class RandomNumberGenerator : IRandomNumberGenerator, IDisposable
{
#if !NET6_0_OR_GREATER
    private readonly System.Security.Cryptography.RandomNumberGenerator _randomNumberGenerator;

    public RandomNumberGenerator()
    {
        _randomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator.Create();
    }

    public byte[] GetBytes(int length)
    {
        byte[] bytes = new byte[length];
        _randomNumberGenerator.GetBytes(bytes);

        return bytes;
    }
    
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            _randomNumberGenerator.Dispose();
        }
    }
#else
    public byte[] GetBytes(int length)
    {
        return System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);
    }

    protected virtual void Dispose(bool disposing)
    {
    }
#endif

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}


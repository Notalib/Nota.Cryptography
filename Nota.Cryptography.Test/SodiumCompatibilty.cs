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

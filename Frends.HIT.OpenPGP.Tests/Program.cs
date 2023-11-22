using System.Text;
using Frends.HIT.OpenPGP;
namespace Frends.HIT.OpenPGP.Tests;

public class Program
{
    public static void Main()
    {
        var encInput = new OpenPGP.Definitions.PgpEncryptInput()
        {
            InputData = "Hello World",
            PublicKey = LocalSettings.GetHoglandetPublic(),
            ArmorResult = true,
            EncryptionType = Definitions.PgpEncryptionType.AES256,
        };

        var encBytesInput = new OpenPGP.Definitions.PgpEncryptBytesInput()
        {
            InputData = Encoding.UTF8.GetBytes("Hello World"),
            PublicKey = LocalSettings.GetHoglandetPublic(),
            ArmorResult = false,
            EncryptionType = Definitions.PgpEncryptionType.AES256,
            Compression = false
        };
        
        var encResult = FrendsInterface.Encrypt(encInput);
        var encBytesResult = FrendsInterface.EncryptBytes(encBytesInput);
        
        var decrInput = new OpenPGP.Definitions.PgpDecryptInput()
        {
            InputData = encResult.EncryptedText,
            PrivateKey = LocalSettings.GetHoglandetPrivate().Replace("\n", "\r\n"),
            PrivateKeyPassword = LocalSettings.HoglandetPassword
        };

        var decrBytesInput = new OpenPGP.Definitions.PgpDecryptBytesInput()
        {
            InputData = encBytesResult.EncryptedBytes,
            PrivateKey = LocalSettings.GetHoglandetPrivate().Replace("\n", "\r\n"),
            PrivateKeyPassword = LocalSettings.HoglandetPassword
        };
        
        var decrBytesResult = FrendsInterface.DecryptBytes(decrBytesInput);
        var decrResult = FrendsInterface.Decrypt(decrInput);
        
        Console.WriteLine(decrBytesResult.DecryptedText);
        Console.WriteLine(decrResult.DecryptedText);
    }
}


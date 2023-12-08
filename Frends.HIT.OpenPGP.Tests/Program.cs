using System.Diagnostics;
using System.Linq.Expressions;
using System.Text;
using System.Text.Unicode;
using Frends.HIT.OpenPGP;
namespace Frends.HIT.OpenPGP.Tests;

public class Program
{
    internal static Definitions.PgpEncryptResult EncryptBytes(byte[] inputData)
    {
        var encBytesInput = new OpenPGP.Definitions.PgpEncryptInput()
        {
            InputDataFormat = Definitions.DataFormat.Bytes,
            InputDataBytes = inputData,
            PublicKey = LocalSettings.GetHoglandetPublic(),
            ArmorResult = false,
            EncryptionType = Definitions.PgpEncryptionType.AES256,
            Compression = false
        };
        
        return FrendsInterface.Encrypt(encBytesInput);
    }

    internal static Definitions.PgpEncryptResult EncryptString(string inputData)
    {
        var encInput = new OpenPGP.Definitions.PgpEncryptInput()
        {
            InputDataFormat = Definitions.DataFormat.String,
            InputDataString = inputData,
            PublicKey = LocalSettings.GetHoglandetPublic(),
            ArmorResult = true,
            EncryptionType = Definitions.PgpEncryptionType.AES256,
            Compression = true,
            CompressionType = Definitions.PgpCompressionType.ZIP
        };
      
       return FrendsInterface.Encrypt(encInput);
    }

    internal static Definitions.PgpDecryptResult DecryptBytes(byte[] inputData)
    {
        var decInput = new OpenPGP.Definitions.PgpDecryptInput()
        {
            InputDataFormat = Definitions.DataFormat.Bytes,
            InputDataBytes = inputData,
            PrivateKey = LocalSettings.GetHoglandetPrivate().ReplaceLineEndings(),
            PrivateKeyPassword = LocalSettings.HoglandetPassword
        };
        
        return FrendsInterface.Decrypt(decInput);
    }

    internal static Definitions.PgpDecryptResult Decrypt(string inputData)
    {
        var decInput = new OpenPGP.Definitions.PgpDecryptInput()
        {
            InputDataFormat = Definitions.DataFormat.String,
            InputDataString = inputData,
            PrivateKey = LocalSettings.GetHoglandetPrivate().ReplaceLineEndings(),
            PrivateKeyPassword = LocalSettings.HoglandetPassword
        };
        
        return FrendsInterface.Decrypt(decInput);
    }

    internal static void TestEncryptDecrypt(string inputData)
    {
        var byteInputData = Encoding.UTF8.GetBytes(inputData);

        var encryptedString = EncryptString(inputData);
        var encryptedBytes = EncryptBytes(byteInputData);

        var decryptStringText = Decrypt(encryptedString.EncryptedText);
        var decryptStringBytes = DecryptBytes(encryptedString.EncryptedBytes);

        var decryptByteString = Decrypt(encryptedBytes.EncryptedText);
        var decryptByteBytes = DecryptBytes(encryptedBytes.EncryptedBytes);

        List<KeyValuePair<string, string>> allText = new List<KeyValuePair<string, string>>()
        {
            new KeyValuePair<string, string>("byteInputData", inputData),
            new KeyValuePair<string, string>("decryptStringText", decryptStringText.DecryptedText),
            new KeyValuePair<string, string>("decryptStringBytes", decryptStringBytes.DecryptedText),
            new KeyValuePair<string, string>("decryptByteBytes", decryptByteBytes.DecryptedText),
            new KeyValuePair<string, string>("decryptByteString", decryptByteString.DecryptedText)
        };
        
        List<KeyValuePair<string, byte[]>> allBytes = new List<KeyValuePair<string, byte[]>>()
        {
            new KeyValuePair<string, byte[]>("byteInputData", byteInputData),
            new KeyValuePair<string, byte[]>("decryptStringText", decryptStringText.DecryptedBytes),
            new KeyValuePair<string, byte[]>("decryptStringBytes", decryptStringBytes.DecryptedBytes),
            new KeyValuePair<string, byte[]>("decryptByteBytes", decryptByteBytes.DecryptedBytes),
            new KeyValuePair<string, byte[]>("decryptByteString", decryptByteString.DecryptedBytes)
        };

        foreach (var item in allText)
        {
            Debug.Assert(item.Value == inputData, "Failed to assert equality for one of the DecryptedText members: " + item.Key);
        }

        foreach (var item in allBytes)
        {
            Debug.Assert(byteInputData.SequenceEqual(item.Value), "Failed to assert equality for one of the DecryptedBytes members: " + item.Key);
        }
    }

    internal static void TestSignVerify(string inputData)
    {
        var signInput = new Definitions.PgpSignatureInput()
        {
            InputDataFormat = Definitions.DataFormat.String,
            InputDataString = "Hello World",
            InputDataIdentifier = "data.txt",
            ArmorResult = true,
            HashFunction = Definitions.PgpHashFunctionType.SHA256,
            PrivateKey = LocalSettings.GetHoglandetPrivate(),
            PrivateKeyPassword = LocalSettings.HoglandetPassword
        };

        var signResult = FrendsInterface.Sign(signInput);

        var verifyInput = new Definitions.PgpVerifySignatureInput()
        {
            InputDataFormat = Definitions.DataFormat.String,
            InputDataString = signResult.SignatureText + "x",
            PublicKey = LocalSettings.GetHoglandetPublic(),
        };

        var verifyResult = FrendsInterface.VerifySignature(verifyInput);
        Console.WriteLine("Verified: " + verifyResult.ValidatedDataText);
        Console.WriteLine("Signature: " + signResult.SignatureText);
    }
    
    public static void Main()
    {
        // TestEncryptDecrypt("Hello World!");
        TestSignVerify("Hello World");
    }
}


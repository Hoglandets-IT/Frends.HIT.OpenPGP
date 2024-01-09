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

    internal static void TestSwedbankSignEncrypt() 
    {
        string Filename = "data";
        // string Data = "Hello World";
        byte[] Data = File.ReadAllBytes("testfile.xml");

        var signInput = new Definitions.PgpSignatureInput(){
            InputDataFormat = Definitions.DataFormat.Bytes,
            InputDataBytes = Data,
            InputDataIdentifier = Filename,
            ArmorResult = false,
            HashFunction = Definitions.PgpHashFunctionType.SHA256,
            PrivateKey = LocalSettings.GetHoglandetPrivate(),
            PrivateKeyPassword = LocalSettings.HoglandetPassword,
        };

        var signResult = FrendsInterface.Sign(signInput);

        var encryptInput = new Definitions.PgpEncryptInput() {
            InputDataBytes = signResult.SignatureBytes,
            Compression = true,
            CompressionType = Definitions.PgpCompressionType.ZLIB,
            InputDataFormat = Definitions.DataFormat.Bytes,
            IntegrityCheck = true,
            PublicKey = LocalSettings.GetSwedbankPublic(),
            EncryptionType = Definitions.PgpEncryptionType.AES256,
            ArmorResult = false
        };

        var encryptResult = FrendsInterface.Encrypt(encryptInput);
        File.WriteAllBytes("062220001412F001.PAIN001.P240108.T161111.GPG", encryptResult.EncryptedBytes);
        Console.WriteLine(encryptResult);
    }

    internal static void TestLocalSignEncrypt() 
    {
        string Filename = "data";
        // string Data = "Hello World";
        byte[] Data = File.ReadAllBytes("testfile.xml");

        var signInput = new Definitions.PgpSignatureInput(){
            InputDataFormat = Definitions.DataFormat.Bytes,
            InputDataBytes = Data,
            InputDataIdentifier = Filename,
            ArmorResult = false,
            HashFunction = Definitions.PgpHashFunctionType.SHA256,
            PrivateKey = LocalSettings.GetHoglandetPrivate(),
            PrivateKeyPassword = LocalSettings.HoglandetPassword,
        };

        var signResult = FrendsInterface.Sign(signInput);

        var encryptInput = new Definitions.PgpEncryptInput() {
            InputDataBytes = signResult.SignatureBytes,
            Compression = true,
            CompressionType = Definitions.PgpCompressionType.ZLIB,
            InputDataFormat = Definitions.DataFormat.Bytes,
            IntegrityCheck = true,
            PublicKey = LocalSettings.GetTestSwedbankPublic(),
            EncryptionType = Definitions.PgpEncryptionType.AES256,
            ArmorResult = false
        };

        var encryptResult = FrendsInterface.Encrypt(encryptInput);
        File.WriteAllBytes("TESTPGP-062220001412F001.PAIN001.P240108.T161111.GPG", encryptResult.EncryptedBytes);
        Console.WriteLine(encryptResult);
    }
    
    public static void Main()
    {
        TestLocalSignEncrypt();
        TestSwedbankSignEncrypt();

        var signandencrypt = new Definitions.PgpSignAndEncryptInput(){
            InputDataFormat = Definitions.DataFormat.String,
            InputDataString = "Hello World",
            InputDataIdentifier = "data",
            SignaturePrivateKey = LocalSettings.GetHoglandetPrivate(),
            SignaturePrivateKeyPassword = LocalSettings.HoglandetPassword,
            EncryptionPublicKey = LocalSettings.GetSwedbankPublic(),
            SignatureHashFunction = Definitions.PgpHashFunctionType.SHA256,
            ArmorSignatureResult = false,
            ArmorEncryptionResult = true,
            EncryptionIntegrityCheck = true,
            EncryptionCompression = true,
            EncryptionCompressionType = Definitions.PgpCompressionType.BZIP2,
            EncryptionType = Definitions.PgpEncryptionType.AES256
        // TestSwedbankSignEncrypt();
        };

        var res = FrendsInterface.SignAndEncrypt(signandencrypt);

        Console.WriteLine(res.EncryptedText);
        Console.WriteLine(res);

        var decryptinput = new Definitions.PgpDecryptInput(){
            InputDataFormat = Definitions.DataFormat.String,
            InputDataString = res.EncryptedText,
            PrivateKey = LocalSettings.GetHoglandetPrivate(),
            PrivateKeyPassword = LocalSettings.HoglandetPassword
        };

        var decrypt = FrendsInterface.Decrypt(decryptinput);

        var validateinput = new Definitions.PgpVerifySignatureInput(){
            InputDataFormat = Definitions.DataFormat.Bytes,
            InputDataBytes = decrypt.DecryptedBytes,
            PublicKey = LocalSettings.GetHoglandetPublic()
        };

        var validate = FrendsInterface.VerifySignature(validateinput);

        Console.WriteLine(validate);




    }
}


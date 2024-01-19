using System.Diagnostics;
using System.Linq.Expressions;
using System.Text;
using System.Text.Unicode;
using Frends.HIT.OpenPGP;
using PgpCore;
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

    


    internal static void DecryptSwedbank()
    {
        string[] files = new string[]
        {
            "\\\\HVFS01\\EkonomiInt02$\\to_raindance\\Inkorg\\Swedbank\\062220001412F001.CAMT054.CRNA.240115160933.GPG",
            "\\\\HVFS01\\EkonomiInt02$\\to_raindance\\Inkorg\\Swedbank\\062220001412F001.CAMT054.CRNA.240115160947.GPG",
            "\\\\HVFS01\\EkonomiInt02$\\to_raindance\\Inkorg\\Swedbank\\062220001412F001.CAMT054.CRNA.240115161001.GPG",
            "\\\\HVFS01\\EkonomiInt02$\\to_raindance\\Inkorg\\Swedbank\\062220001412F001.CAMT054.CRNA.240116153451.GPG",
            "\\\\HVFS01\\EkonomiInt02$\\to_raindance\\Inkorg\\Swedbank\\062220001412F001.CAMT054.CRNA.240116153503.GPG",
        };

        foreach (var file in files)
        {
            var content = File.ReadAllBytes(file);
            var decryptInput = new Definitions.PgpDecryptInput()
            {
                InputDataBytes = content,
                InputDataFormat = Definitions.DataFormat.Bytes,
                PrivateKey = LocalSettings.GetHoglandetPrivate(),
                PrivateKeyPassword = LocalSettings.HoglandetPassword
            };

            var decrypt = FrendsInterface.Decrypt(decryptInput);
            
            File.WriteAllBytes(file + ".xml", decrypt.DecryptedBytes);
        }
    }
    
    
    internal static void TestLocalSignEncrypt() 
    {
        string Filename = "data";
        byte[] Data = File.ReadAllBytes("D:\\GIT\\github\\Hoglandets-IT\\Frends.HIT.OpenPGP\\Frends.HIT.OpenPGP.Tests\\testfile.xml");

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
            ArmorResult = true
        };

        var encryptResult = FrendsInterface.Encrypt(encryptInput);
        File.WriteAllBytes("D:\\GIT\\github\\Hoglandets-IT\\Frends.HIT.OpenPGP\\Frends.HIT.OpenPGP.Tests\\TESTPGP.GPG", encryptResult.EncryptedBytes);
        Console.WriteLine(encryptResult);
    }
    
    internal static void TestSwedbankSignEncrypt()
    {
        var input = new Definitions.SwedbankSignEncryptInput()
        {
            // EncryptionPublicKey = LocalSettings.GetSwedbankPublic(),
            EncryptionPublicKey = LocalSettings.GetTestSwedbankPublic(),
            InputData = File.ReadAllBytes(
                "\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\300L95_240118125935_sent_failed.xml"),
            SignaturePrivateKey = LocalSettings.GetHoglandetPrivate(),
            SignaturePrivateKeyPassword = LocalSettings.HoglandetPassword
        };
        
        var signInput = new Definitions.PgpSignatureInput(){
            InputDataFormat = Definitions.DataFormat.Bytes,
            InputDataBytes = input.InputData,
            InputDataIdentifier = "data",
            ArmorResult = false,
            // ArmorResult = true,
            HashFunction = Definitions.PgpHashFunctionType.SHA256,
            PrivateKey = input.SignaturePrivateKey,
            PrivateKeyPassword = input.SignaturePrivateKeyPassword
        };
        
        var signResult = FrendsInterface.Sign(signInput);
        File.WriteAllBytes("\\\\wsl.localhost\\Ubuntu\\home\\larsch\\pgp\\EncSigned\\SignedFirst.GPG", signResult.SignatureBytes);
        
        var encryptInput = new Definitions.PgpEncryptInput() {
            InputDataBytes = signResult.SignatureBytes,
            // InputDataString = File.ReadAllText("\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\300L95_240118125935_sent_failed.xml"),
            Compression = false,
            CompressionType = Definitions.PgpCompressionType.ZLIB,
            InputDataFormat = Definitions.DataFormat.Bytes,
            // InputDataFormat = Definitions.DataFormat.String,
            IntegrityCheck = true,
            PublicKey = input.EncryptionPublicKey,
            EncryptionType = Definitions.PgpEncryptionType.AES256,
            ArmorResult = false
        };
        
        var encryptResult = FrendsInterface.Encrypt(encryptInput);
        
        File.WriteAllBytes("\\\\wsl.localhost\\Ubuntu\\home\\larsch\\pgp\\EncSigned\\SignedFirstThenEncrypted.GPG", encryptResult.EncryptedBytes);
        
        // File.WriteAllBytes("\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\FRIDAY1-encsig-062220001412F001.PAIN001.P240117.T180300.GPG", signResult.SignatureBytes);
        Console.WriteLine(signResult);
    }
    
    internal static void TestSwedbankEncryptSign()
    {
        var input = new Definitions.SwedbankSignEncryptInput()
        {
            // EncryptionPublicKey = LocalSettings.GetSwedbankPublic(),
            EncryptionPublicKey = LocalSettings.GetTestSwedbankPublic(),
            InputData = File.ReadAllBytes(
                "\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\400L95_20240118130233_sent_late.xml"),
            SignaturePrivateKey = LocalSettings.GetHoglandetPrivate(),
            SignaturePrivateKeyPassword = LocalSettings.HoglandetPassword
        };
        
        var encryptInput = new Definitions.PgpEncryptInput() {
            InputDataBytes = input.InputData,
            // InputDataString = File.ReadAllText("\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\300L95_240118125935_sent_failed.xml"),
            Compression = false,
            CompressionType = Definitions.PgpCompressionType.ZLIB,
            InputDataFormat = Definitions.DataFormat.Bytes,
            // InputDataFormat = Definitions.DataFormat.String,
            IntegrityCheck = true,
            PublicKey = input.EncryptionPublicKey,
            EncryptionType = Definitions.PgpEncryptionType.AES256,
            ArmorResult = false
        };
        var encryptResult = FrendsInterface.Encrypt(encryptInput);
        File.WriteAllBytes("\\\\wsl.localhost\\Ubuntu\\home\\larsch\\pgp\\EncSigned\\EncryptedFirst.GPG", encryptResult.EncryptedBytes);
        
        var signInput = new Definitions.PgpSignatureInput(){
            InputDataFormat = Definitions.DataFormat.Bytes,
            InputDataBytes = encryptResult.EncryptedBytes,
            InputDataIdentifier = "data",
            ArmorResult = false,
            // ArmorResult = true,
            HashFunction = Definitions.PgpHashFunctionType.SHA256,
            PrivateKey = input.SignaturePrivateKey,
            PrivateKeyPassword = input.SignaturePrivateKeyPassword
        };

        var signResult = FrendsInterface.Sign(signInput);

        
        // File.WriteAllBytes("\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\FRIDAY1-encsig-062220001412F001.PAIN001.P240117.T180300.GPG", signResult.SignatureBytes);
        File.WriteAllBytes("\\\\wsl.localhost\\Ubuntu\\home\\larsch\\pgp\\EncSigned\\EncryptedThenSigned.GPG", signResult.SignatureBytes);
        Console.WriteLine(signResult);
    }
    
    public static async Task Main()
    {
        var INPUT = "330L95_240118130120_sent_failed.xml";
        var OUTPUT = "062220001412F001.PAIN001.P240119.T102611.GPG";
        
        
        var input = new Definitions.SwedbankSignEncryptInput()
        {
            EncryptionPublicKey = LocalSettings.GetSwedbankPublic(),
            // EncryptionPublicKey = LocalSettings.GetTestSwedbankPublic(),
            InputData = File.ReadAllBytes(
                "\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\" + INPUT),
            SignaturePrivateKey = LocalSettings.GetHoglandetPrivate(),
            SignaturePrivateKeyPassword = LocalSettings.HoglandetPassword
        };

        // using var privkeyStream = Helpers.StreamFromString(input.SignaturePrivateKey)
        // using var pubkeyStream = Helpers.StreamFromString(input.EncryptionPublicKey)
        //     encryptionKeys = new PgpCore.En
            
        // var outputStream = new MemoryStream();
        // var passwd = input.SignaturePrivateKeyPassword;
        
        
        EncryptionKeys encryptionKeys;
        
        using (Stream pubkeyStream = Helpers.StreamFromString(input.EncryptionPublicKey))
        using (Stream privkeyStream = Helpers.StreamFromString(input.SignaturePrivateKey))
        {
            encryptionKeys = new EncryptionKeys(pubkeyStream, privkeyStream, input.SignaturePrivateKeyPassword);
        }

        PGP pgp = new PGP(encryptionKeys);
        Stream outputStream;

        using (Stream inputStream = Helpers.StreamFromBytearray(input.InputData))
        using (outputStream = new MemoryStream())
        {
            
            await pgp.EncryptStreamAndSignAsync(inputStream, outputStream, false, true, OUTPUT, null, false);
        }
        
        var byteResp = ((MemoryStream)outputStream).ToArray();
        
        File.WriteAllBytes("\\\\HVFS01\\EkonomiInt02$\\from_raindance\\Swedbank\\" + OUTPUT, byteResp);



        // TestSwedbankSignEncrypt();
        // TestSwedbankEncryptSign();
        // DecryptSwedbank();
        // TestLocalSignEncrypt();
        // TestSwedbankSignEncrypt();

        // var signandencrypt = new Definitions.PgpSignAndEncryptInput(){
        //     InputDataFormat = Definitions.DataFormat.String,
        //     InputDataString = "Hello World",
        //     InputDataIdentifier = "data",
        //     SignaturePrivateKey = LocalSettings.GetHoglandetPrivate(),
        //     SignaturePrivateKeyPassword = LocalSettings.HoglandetPassword,
        //     EncryptionPublicKey = LocalSettings.GetSwedbankPublic(),
        //     SignatureHashFunction = Definitions.PgpHashFunctionType.SHA256,
        //     ArmorSignatureResult = false,
        //     ArmorEncryptionResult = true,
        //     EncryptionIntegrityCheck = true,
        //     EncryptionCompression = true,
        //     EncryptionCompressionType = Definitions.PgpCompressionType.BZIP2,
        //     EncryptionType = Definitions.PgpEncryptionType.AES256
        // // TestSwedbankSignEncrypt();
        // };
        //
        // var res = FrendsInterface.SignAndEncrypt(signandencrypt);
        //
        // Console.WriteLine(res.EncryptedText);
        // Console.WriteLine(res);
        //
        // var decryptinput = new Definitions.PgpDecryptInput(){
        //     InputDataFormat = Definitions.DataFormat.String,
        //     InputDataString = res.EncryptedText,
        //     PrivateKey = LocalSettings.GetHoglandetPrivate(),
        //     PrivateKeyPassword = LocalSettings.HoglandetPassword
        // };
        //
        // var decrypt = FrendsInterface.Decrypt(decryptinput);
        //
        // var validateinput = new Definitions.PgpVerifySignatureInput(){
        //     InputDataFormat = Definitions.DataFormat.Bytes,
        //     InputDataBytes = decrypt.DecryptedBytes,
        //     PublicKey = LocalSettings.GetHoglandetPublic()
        // };
        //
        // var validate = FrendsInterface.VerifySignature(validateinput);
        //
        // Console.WriteLine(validate);




    }
}


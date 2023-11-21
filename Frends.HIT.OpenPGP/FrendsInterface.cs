using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Frends.HIT.OpenPGP;

public class FrendsInterface
{
    internal const int EncryptBufferSize = 1 << 16;
    public static Definitions.PgpDecryptResult DecryptBytes(Definitions.PgpDecryptBytesInput input)
    {
        var outputStream = new MemoryStream();
        
        using (var inputStream = Helpers.StreamFromBytearray(input.InputData))
        {
            using (var keyStream = Helpers.StreamFromString(input.PrivateKey))
            {
                Encryption.Decrypt(inputStream, keyStream, input.PrivateKeyPassword, outputStream);
            }
        }
        
        var decryptedBytes = outputStream.ToArray();

        var output = new Definitions.PgpDecryptResult()
        {
            DecryptedBytes = decryptedBytes,
            DecryptedText = Encoding.UTF8.GetString(decryptedBytes)
        };

        return output;
    }
    public static Definitions.PgpDecryptResult Decrypt(Definitions.PgpDecryptInput input)
    {
        var outputStream = new MemoryStream();
        
        using (var inputStream = Helpers.StreamFromString(input.InputData))
        {
            using (var keyStream = Helpers.StreamFromString(input.PrivateKey))
            {
                Encryption.Decrypt(inputStream, keyStream, input.PrivateKeyPassword, outputStream);
            }
        }
        
        var decryptedBytes = outputStream.ToArray();

        var output = new Definitions.PgpDecryptResult()
        {
            DecryptedBytes = decryptedBytes,
            DecryptedText = Encoding.UTF8.GetString(decryptedBytes)
        };

        return output;
    }

    public static Definitions.PgpEncryptResult EncryptBytes(Definitions.PgpEncryptBytesInput input)
    {
        var outputStream = new MemoryStream();
        
        using (var inputStream = Helpers.StreamFromBytearray(input.InputData))
        using (var encryptedOut = Helpers.GetEncryptionStream(input.ArmorResult ? new ArmoredOutputStream(outputStream) : outputStream, input))
        using (var compressedOut = Helpers.GetCompressionStream(encryptedOut, input))
        {
            var literalDataGenerator = new PgpLiteralDataGenerator();
            
            using (var literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, "data", inputStream.Length, DateTime.Now))
            {
                var buffer = new byte[EncryptBufferSize];
                int len;
                while ((len = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    literalOut.Write(buffer, 0, len);
                }
            }
        }

        var encBytes = outputStream.ToArray();
        var encString = Encoding.UTF8.GetString(encBytes);
        
        return new Definitions.PgpEncryptResult()
        {
            EncryptedBytes = encBytes,
            EncryptedText = encString
        };
    } 
    
    public static Definitions.PgpEncryptResult Encrypt(Definitions.PgpEncryptInput input)
    {
        var outputStream = new MemoryStream();
        
        using (var inputStream = Helpers.StreamFromString(input.InputData))
        using (var encryptedOut = Helpers.GetEncryptionStream(input.ArmorResult ? new ArmoredOutputStream(outputStream) : outputStream, input))
        using (var compressedOut = Helpers.GetCompressionStream(encryptedOut, input))
        {
            var literalDataGenerator = new PgpLiteralDataGenerator();
            
            using (var literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Utf8, "data", inputStream.Length, DateTime.Now))
            {
                var buffer = new byte[EncryptBufferSize];
                int len;
                while ((len = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    literalOut.Write(buffer, 0, len);
                }
            }

            compressedOut.Flush();
            encryptedOut.Flush();
        }

        
        
        var encBytes = outputStream.ToArray();
        var encString = Encoding.UTF8.GetString(encBytes);

        return new Definitions.PgpEncryptResult()
        {
            EncryptedBytes = encBytes,
            EncryptedText = encString
        };
    }
    
}
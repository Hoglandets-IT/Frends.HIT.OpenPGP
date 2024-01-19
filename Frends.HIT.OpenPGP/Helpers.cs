using System.Text.RegularExpressions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
namespace Frends.HIT.OpenPGP;

public static class Helpers
{
    public static Stream StreamFromBytearray(byte[] ba)
    {
        var stream = new MemoryStream();
        stream.Write(ba, 0, ba.Length);
        stream.Position = 0;
        return stream;
    }
    public static Stream StreamFromString(string s)
    {
        var stream = new MemoryStream();
        var writer = new StreamWriter(stream);
        writer.Write(s);
        writer.Flush();
        
        stream.Position = 0;
        return stream;
    }

    internal static TEnum ConvertEnum<TEnum>(Enum source)
    {
        return (TEnum)Enum.Parse(typeof(TEnum), source.ToString(), true);
    }

    internal static PgpPublicKey ReadPublicKey(string publicKey)
    {
        using (Stream keyStream = StreamFromString(publicKey))
        using (Stream decoderStream = PgpUtilities.GetDecoderStream(keyStream))
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(decoderStream);
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in kRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey) return key;
                }
            }
        }

        throw new ArgumentException("Can't find encryption key in key ring.");
    }
    
    internal static Stream GetEncryptionStream(Stream stream, Definitions.PgpEncryptInput input)
    {
        SymmetricKeyAlgorithmTag algorithmTag = Helpers.ConvertEnum<SymmetricKeyAlgorithmTag>(input.EncryptionType);
        PgpPublicKey publicKey = ReadPublicKey(input.PublicKey);
        PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(algorithmTag, input.IntegrityCheck, new SecureRandom());
        encryptedDataGenerator.AddMethod(publicKey);
        return encryptedDataGenerator.Open(stream, new byte[FrendsInterface.EncryptBufferSize]);
    }

    internal static Stream GetCompressionStream(Stream stream, Definitions.PgpEncryptInput input)
    {
        if (input.ArmorResult)
        {
            CompressionAlgorithmTag compressionTag =
                Helpers.ConvertEnum<CompressionAlgorithmTag>(input.CompressionType);
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(compressionTag);
            return compressedDataGenerator.Open(stream);
        }

        return stream;
    }

    internal static PgpSecretKeyRingBundle GetSecretKeyringBundle(string privateKey)
    {
        Stream privateKeyStream = StreamFromString(privateKey);
        
        PgpSecretKeyRingBundle pgpKeyring;
        Stream pgpDecoderStream;
        
        try
        {
            pgpDecoderStream = PgpUtilities.GetDecoderStream(privateKeyStream); 
            pgpKeyring = new PgpSecretKeyRingBundle(pgpDecoderStream);

        } catch (Exception er)
        {
            // Failed to decrypt key, try insering additional newline at first line
            privateKeyStream.Position = 0;
            var reader = new StreamReader(privateKeyStream);
            var newPrivateKey = reader.ReadToEnd();
            
            var newPkStream = new MemoryStream();
            var writer = new StreamWriter(newPkStream);
            var regex = new Regex(Regex.Escape("--\r\n"));
            writer.Write(regex.Replace(newPrivateKey.ReplaceLineEndings(), "--\r\n\r\n"), 1);
            writer.Flush();
            
            newPkStream.Position = 0;
            
            pgpDecoderStream = PgpUtilities.GetDecoderStream(newPkStream);
            pgpKeyring = new PgpSecretKeyRingBundle(pgpDecoderStream);
        }

        return pgpKeyring;
    }
}
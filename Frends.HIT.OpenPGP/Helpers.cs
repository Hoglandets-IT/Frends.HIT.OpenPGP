using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
namespace Frends.HIT.OpenPGP;

public class Helpers
{
    internal static Stream StreamFromBytearray(byte[] ba)
    {
        var stream = new MemoryStream();
        stream.Write(ba, 0, ba.Length);
        stream.Position = 0;
        return stream;
    }
    internal static Stream StreamFromString(string s)
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
    internal static Stream GetEncryptionStream(Stream stream, Definitions.PgpEncryptBytesInput input)
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
    internal static Stream GetCompressionStream(Stream stream, Definitions.PgpEncryptBytesInput input)
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
}
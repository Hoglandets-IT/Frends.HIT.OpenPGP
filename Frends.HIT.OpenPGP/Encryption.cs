using System.Text.RegularExpressions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Frends.HIT.OpenPGP;

public static class Encryption
{
    internal static bool Decrypt(Stream inputStream, string privateKey, string password, Stream outputStream)
    {
        PgpPrivateKey sKey = null;
        PgpPublicKeyEncryptedData pbe = null;
        PgpEncryptedDataList encData;
        
        
        var pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
        var pgpKeyring = Helpers.GetSecretKeyringBundle(privateKey);
        // PgpSecretKeyRingBundle pgpKeyring;
        // Stream pgpDecoderStream;
        // try
        // {
        //     pgpDecoderStream = PgpUtilities.GetDecoderStream(privateKeyStream); 
        //     pgpKeyring = new PgpSecretKeyRingBundle(pgpDecoderStream);
        //
        // } catch (Exception er)
        // {
        //     // Failed to decrypt key, try insering additional newline at first line
        //     privateKeyStream.Position = 0;
        //     var reader = new StreamReader(privateKeyStream);
        //     var newPrivateKey = reader.ReadToEnd();
        //     
        //     var newPkStream = new MemoryStream();
        //     var writer = new StreamWriter(newPkStream);
        //     var regex = new Regex(Regex.Escape("--\r\n"));
        //     writer.Write(regex.Replace(newPrivateKey, "--\r\n\r\n"), 1);
        //     writer.Flush();
        //     
        //     newPkStream.Position = 0;
        //     
        //     pgpDecoderStream = PgpUtilities.GetDecoderStream(newPkStream);
        //     pgpKeyring = new PgpSecretKeyRingBundle(pgpDecoderStream);
        // }

        var o = pgpFactory.NextPgpObject();

        if (o is PgpEncryptedDataList list) encData = list;
        else encData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();

        PgpObjectFactory plainFact;
        
        foreach (PgpPublicKeyEncryptedData pkEncData in encData.GetEncryptedDataObjects())
        {
            var tsKey = pgpKeyring.GetSecretKey(pkEncData.KeyId);
            if (tsKey == null) continue;
            sKey = tsKey.ExtractPrivateKey(password.ToCharArray());
            pbe = pkEncData;
        }
        
        if (sKey == null) throw new ArgumentException("Secret key for message not found.");

        using var clear = pbe.GetDataStream(sKey);
        plainFact = new PgpObjectFactory(clear);
                
        var message = plainFact.NextPgpObject();

        if (message is PgpSignatureList)
        {
            message = plainFact.NextPgpObject();
        }
      
        switch (message)
        {
            case PgpCompressedData cData:
                PgpObjectFactory of;

                using (var compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                    
                    message = of.NextPgpObject();
                    if (message is PgpOnePassSignatureList) message = of.NextPgpObject();

                    var llitData = (PgpLiteralData)message;
                    var lunc = llitData.GetInputStream();
                    Streams.PipeAll(lunc, outputStream);
                }
                break;
            
            case PgpLiteralData litData:
                using (var unc = litData.GetInputStream())
                    Streams.PipeAll(unc, outputStream);
                
                break;
            
            case PgpOnePassSignatureList _:
                throw new PgpException("Encrypted message contains a signed message, not literal data");
            default:
                throw new PgpException("Message is not a simple encrypted file - type unknown");
        }


        return true;
    }
    

    // public static Stream ChainCompressedOut(Stream encryptedOut)
    // {
    //     PgpCompressedDataGenerator compressedDataGenerator =
    //         new PgpCompressedDataGenerator(CompressionAlgorithmTag.ZLib);
    //     return compressedDataGenerator.Open(encryptedOut);
    // }
    //
    // public static Stream ChainEncryptedOut(Stream outputStream, Stream privkeyStream, string privkeyPass, bool withIntegrityCheck)
    // {
    //     var encryptedDataGenerator =
    //         new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, withIntegrityCheck, new SecureRandom());
    //
    //     foreach (PgpPublicKeyRingWithPreferredKey publicKeyRing in EncryptionKeys.PublicKeyRings)
    //     {
    //         PgpPublicKey publicKey = publicKeyRing.PreferredEncryptionKey ?? publicKeyRing.DefaultEncryptionKey;
    //         encryptedDataGenerator.AddMethod(publicKey);
    //     }
    //
    //     return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
    // }
    //
    //
    // public static void OutputEncrypted(
    //     Stream inputStream, 
    //     Stream outputStream,
    //     Stream pubkeyStream,
    //     Stream privkeyStream,
    //     string privkeyPass,
    //     bool withIntegrityCheck, 
    //     string name, 
    //     bool oldFormat
    // )
    // {
    //     using (Stream encryptedOut = ChainEncryptedOut(outputStream,  privkeyStream, privkeyPass, withIntegrityCheck))
    //     {
    //         using (Stream compressedOut = ChainCompressedOut(encryptedOut))
    //         {
    //             PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
    //             using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream, name, oldFormat))
    //             {
    //                 WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
    //             }
    //         }
    //     }
    // }
    //
    //
    // public static void EncryptAndSign(
    //     Stream inputStream,
    //     Stream outputStream,
    //     Stream pubkeyStream,
    //     Stream privkeyStream,
    //     string privkeyPass,
    //     bool armor,
    //     bool integrityCheck,
    //     string name,
    //     bool oldFormat,
    //     IDictionary<string, string> headers = null
    // )
    // {
    //     headers ??= new Dictionary<string, string>();
    //
    //     if (armor)
    //     {
    //         using var armoredOutputStream = new ArmoredOutputStream(outputStream, headers);
    //         OutputEncrypted(inputStream, armoredOutputStream, pubkeyStream, privkeyStream, privkeyPass, integrityCheck, name, oldFormat);
    //     }
    //     OutputEncrypted(inputStream, outputStream, pubkeyStream, privkeyStream, privkeyPass, integrityCheck, name, oldFormat);
    // }
    
    
}

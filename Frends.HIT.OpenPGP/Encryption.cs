using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

namespace Frends.HIT.OpenPGP;

public class Encryption
{
    internal static bool Decrypt(Stream inputStream, Stream privateKeyStream, string password, Stream outputStream)
    {
        PgpPrivateKey sKey = null;
        PgpPublicKeyEncryptedData pbe = null;
        PgpEncryptedDataList encData;
        var pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
        var pgpKeyring = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
        
        try
        {
            var o = pgpFactory.NextPgpObject();

            if (o is PgpEncryptedDataList list) encData = list;
            else encData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
        }
        catch (Exception er)
        {
            throw new Exception("Section 1", er.InnerException);
        }
        PgpObjectFactory plainFact;

        try {
            foreach (PgpPublicKeyEncryptedData pkEncData in encData.GetEncryptedDataObjects())
            {
                var tsKey = pgpKeyring.GetSecretKey(pkEncData.KeyId);
                if (tsKey == null) continue;
                sKey = tsKey.ExtractPrivateKey(password.ToCharArray());
                pbe = pkEncData;
            }
            
            if (sKey == null) throw new ArgumentException("Secret key for message not found.");


            using (var clear = pbe.GetDataStream(sKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }
        }
        catch (Exception er)
        {
            throw new Exception("Section 2", er.InnerException);
        }
        
        var message = plainFact.NextPgpObject();
        
        try {
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
                    }

                    message = of.NextPgpObject();
                    if (message is PgpOnePassSignatureList) message = of.NextPgpObject();
                    
                    var llitData = (PgpLiteralData)message;
                    var lunc = llitData.GetInputStream();
                    Streams.PipeAll(lunc, outputStream);

                    break;
                
                case PgpLiteralData litData:
                    var unc = litData.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                
                    break;
                
                case PgpOnePassSignatureList _:
                    throw new PgpException("Encrypted message contains a signed message, not literal data");
                default:
                    throw new PgpException("Message is not a simple encrypted file - type unknown");
            }
        }
        catch (Exception er)
        {
            throw new Exception("Section 3", er.InnerException);
        }

        return true;
    }
}
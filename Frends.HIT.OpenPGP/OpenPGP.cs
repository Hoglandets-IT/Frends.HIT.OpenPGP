using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Frends.HIT.OpenPGP
{
    public class FrendsInterface
    {
        internal const int EncryptBufferSize = 1 << 16;

        /// <summary>
        /// Decrypts PGP encrypted data. This can be provided via string or byte array.
        /// </summary>
        /// <returns>Frends.HIT.OpenPGP.Definitions.PgpDecryptResult</returns>
        public static Definitions.PgpDecryptResult Decrypt(Definitions.PgpDecryptInput input)
        {
            var outputStream = new MemoryStream();

            using (var inputStream = input.GetInputStream())
                Encryption.Decrypt(inputStream, input.PrivateKey, input.PrivateKeyPassword, outputStream);

            var decryptedBytes = outputStream.ToArray();

            var output = new Definitions.PgpDecryptResult()
            {
                DecryptedBytes = decryptedBytes,
                DecryptedText = Encoding.UTF8.GetString(decryptedBytes)
            };

            return output;
        }

        /// <summary>
        /// Encrypts data using PGP encryption. The data can be provided via string or byte array.
        /// </summary>
        /// <returns>Object { Frends.HIT.OpenPGP.Definitions.PgpEncryptResult } </returns>
        public static Definitions.PgpEncryptResult Encrypt(Definitions.PgpEncryptInput input)
        {
            var outputStream = new MemoryStream();
            using (var inputStream = input.GetInputStream())
            using (Stream armorStream = input.ArmorResult ? new ArmoredOutputStream(outputStream) : outputStream)
            using (var encryptedOut = Helpers.GetEncryptionStream(armorStream, input))
            using (var compressedOut = Helpers.GetCompressionStream(encryptedOut, input))
            {
                var literalDataGenerator = new PgpLiteralDataGenerator();
                using (var literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, input.InputDataIdentifier,
                           inputStream.Length,
                           DateTime.Now))
                {
                    var buffer = new byte[EncryptBufferSize];
                    int len;
                    while ((len = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        literalOut.Write(buffer, 0, len);
                    }
                }
            };

            var encBytes = outputStream.ToArray();
            var encString = Encoding.UTF8.GetString(encBytes);

            return new Definitions.PgpEncryptResult()
            {
                EncryptedBytes = encBytes,
                EncryptedText = encString
            };
        }

        /// <summary>
        /// Signs data using PGP signature. The data can be provided via string or byte array.
        /// </summary>
        /// <param name="input">The input parameters</param>
        /// <returns>Frends.HIT.OpenPGP.Definitions.PgpSignatureResult</returns>
        /// <exception cref="ArgumentException">Invalid Argument</exception>
        public static Definitions.PgpSignatureResult Sign(Definitions.PgpSignatureInput input)
        {
            var outputStream = new MemoryStream();

            HashAlgorithmTag digest = Helpers.ConvertEnum<HashAlgorithmTag>(input.HashFunction);

            using (var inputStream = input.GetInputStream())
            {
                var pgpKeyring = Helpers.GetSecretKeyringBundle(input.PrivateKey);
                PgpSecretKey pgpSecretKey = null;

                foreach (PgpSecretKeyRing keyring in pgpKeyring.GetKeyRings())
                {
                    foreach (PgpSecretKey key in keyring.GetSecretKeys())
                    {
                        if (key.IsSigningKey)
                        {
                            pgpSecretKey = key;
                            break;
                        }
                    }
                }

                if (pgpSecretKey == null) throw new ArgumentException("Secret key for signing not found.");
                var pgpPrivateKey = pgpSecretKey.ExtractPrivateKey(input.PrivateKeyPassword.ToCharArray());

                var signatureGenerator = new PgpSignatureGenerator(pgpSecretKey.PublicKey.Algorithm, digest);
                var signatureSubpacketGenerator = new PgpSignatureSubpacketGenerator();

                signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivateKey);

                var enumerator = pgpSecretKey.PublicKey.GetUserIds().GetEnumerator();
                if (enumerator.MoveNext())
                {
                    signatureSubpacketGenerator.AddSignerUserId(false, (string)enumerator.Current);
                    signatureGenerator.SetHashedSubpackets(signatureSubpacketGenerator.Generate());
                }

                using Stream armoredStream = input.ArmorResult ? new ArmoredOutputStream(outputStream) : outputStream;
                using var bcpgOutputStream = new BcpgOutputStream(armoredStream);
                signatureGenerator.GenerateOnePassVersion(false).Encode(bcpgOutputStream);
                var literalDataGenerator = new PgpLiteralDataGenerator();

                using var literalDataOut = literalDataGenerator.Open(bcpgOutputStream, PgpLiteralData.Binary,
                    input.InputDataIdentifier, inputStream.Length, DateTime.Now);

                int ch;
                while ((ch = inputStream.ReadByte()) >= 0)
                {
                    literalDataOut.WriteByte((byte)ch);
                    signatureGenerator.Update((byte)ch);
                }

                signatureGenerator.Generate().Encode(bcpgOutputStream);
            }

            var encBytes = outputStream.ToArray();
            var encString = Encoding.UTF8.GetString(encBytes);

            return new Definitions.PgpSignatureResult()
            {
                SignatureBytes = encBytes,
                SignatureText = encString
            };
        }

        /// <summary>
        /// Verifies a PGP signature. The data can be provided via string or byte array.
        /// </summary>
        /// <param name="input">The input parameters</param>
        /// <returns>Frends.HIT.OpenPGP.Definitions.PgpVerifySignatureResult</returns>
        public static Definitions.PgpVerifySignatureResult VerifySignature(Definitions.PgpVerifySignatureInput input)
        {
            var outputStream = new MemoryStream();
            var outResult = new Definitions.PgpVerifySignatureResult();

            using (var inputStream = input.GetInputStream())
            using (var pubkeyStream = Helpers.StreamFromString(input.PublicKey))
            using (var inputDecoderStream = PgpUtilities.GetDecoderStream(inputStream))
            using (var pubkeyDecoderStream = PgpUtilities.GetDecoderStream(pubkeyStream))
            {
                var pgpFactory = new PgpObjectFactory(inputDecoderStream);
                var signatureList = (PgpOnePassSignatureList)pgpFactory.NextPgpObject();
                var onePassSignature = signatureList[0];

                var p2 = (PgpLiteralData)pgpFactory.NextPgpObject();
                var dataIn = p2.GetInputStream();
                var pgpRing = new PgpPublicKeyRingBundle(pubkeyDecoderStream);
                var key = pgpRing.GetPublicKey(onePassSignature.KeyId);

                onePassSignature.InitVerify(key);

                int ch;
                while ((ch = dataIn.ReadByte()) >= 0)
                {
                    outputStream.WriteByte((byte)ch);
                    onePassSignature.Update((byte)ch);
                }

                bool verified;

                try
                {
                    var p3 = (PgpSignatureList)pgpFactory.NextPgpObject();
                    var firstSig = p3[0];
                    verified = onePassSignature.Verify(firstSig);
                    outResult.Valid = true;
                }
                catch (Exception)
                {
                    outResult.Valid = false;
                }

            }

            outResult.ValidatedDataBytes = outputStream.ToArray();
            outResult.ValidatedDataText = Encoding.UTF8.GetString(outResult.ValidatedDataBytes);

            return outResult;
        }

        /// <summary>
        /// First signs, then encrypts the given data with sensible defaults
        /// </summary>
        /// <param name="input">Parameters for signature and encryption</param>
        /// <returns>
        /// PgpEncryptResult { 
        ///     EncryptedBytes byte[] The bytearray with the encryption result
        ///     EncryptedText string The string with the encryption result
        /// } 
        /// </returns>
        public static Definitions.PgpEncryptResult SignAndEncrypt(Definitions.PgpSignAndEncryptInput input)
        {
            var signatureInput = new Definitions.PgpSignatureInput()
            {
                InputDataFormat = input.InputDataFormat,
                InputDataString = input.InputDataString,
                InputDataBytes = input.InputDataBytes,
                InputDataIdentifier = input.InputDataIdentifier,
                ArmorResult = input.ArmorSignatureResult,
                HashFunction = input.SignatureHashFunction,
                PrivateKey = input.SignaturePrivateKey,
                PrivateKeyPassword = input.SignaturePrivateKeyPassword
            };

            var signResult = Sign(signatureInput);

            var encryptionInput = new Definitions.PgpEncryptInput()
            {
                InputDataFormat = Definitions.DataFormat.Bytes,
                InputDataBytes = signResult.SignatureBytes,
                Compression = input.EncryptionCompression,
                CompressionType = input.EncryptionCompressionType,
                InputDataIdentifier = input.InputDataIdentifier,
                PublicKey = input.EncryptionPublicKey,
                EncryptionType = input.EncryptionType,
                ArmorResult = input.ArmorEncryptionResult
            };

            var encryptionResult = Encrypt(encryptionInput);

            return encryptionResult;
        }

        /// <summary>
        /// First signs, then encrypts the given data with settings for Swedbank
        /// </summary>
        /// <param name="input">Parameters for signature and encryption</param>
        /// <returns>
        /// PgpEncryptResult { 
        ///     EncryptedBytes byte[] The bytearray with the encryption result
        ///     EncryptedText string The string with the encryption result
        /// } 
        /// </returns>
        public static byte[] SwedbankSignEncrypt(Definitions.SwedbankSignEncryptInput input)
        {
            var signInput = new Definitions.PgpSignatureInput(){
                InputDataFormat = Definitions.DataFormat.Bytes,
                InputDataBytes = input.InputData,
                InputDataIdentifier = "data",
                ArmorResult = false,
                HashFunction = Definitions.PgpHashFunctionType.SHA256,
                PrivateKey = input.SignaturePrivateKey,
                PrivateKeyPassword = input.SignaturePrivateKeyPassword
            };

            var signResult = Sign(signInput);

            var encryptInput = new Definitions.PgpEncryptInput() {
                InputDataBytes = signResult.SignatureBytes,
                Compression = true,
                CompressionType = Definitions.PgpCompressionType.ZLIB,
                InputDataFormat = Definitions.DataFormat.Bytes,
                IntegrityCheck = true,
                PublicKey = input.EncryptionPublicKey,
                EncryptionType = Definitions.PgpEncryptionType.AES256,
                ArmorResult = false
            };

            var encryptResult = Encrypt(encryptInput);

            return encryptResult.EncryptedBytes;
        }
    }
}
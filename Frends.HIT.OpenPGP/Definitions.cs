using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.HIT.OpenPGP;

/// <summary>
/// Definitions for inputs and outputs for the OpenPGP tasks
/// </summary>
public static class Definitions
{
    /// <summary>
    /// The hash function type to use for the signature
    /// </summary>
    public enum PgpHashFunctionType
    {
        [Display(Name = "MD5")]
        MD5,
        
        [Display(Name = "SHA-1")]
        SHA1,
        
        [Display(Name = "RIPE MD-160")]
        RIPEMD160,
        
        [Display(Name = "SHA-224")]
        SHA224,
        
        [Display(Name = "SHA-256")]
        SHA256,
        
        [Display(Name = "SHA-384")]
        SHA384,
        
        [Display(Name = "SHA-512")]
        SHA512
    }

    /// <summary>
    /// The compression type to use for the data
    /// </summary>
    public enum PgpCompressionType
    {
        [Display(Name = "BZIP2")]
        BZIP2,
        
        [Display(Name = "Don't Compress")]
        UNCOMPRESSED,
        
        [Display(Name = "ZIP")]
        ZIP,
        
        [Display(Name = "ZLIB")]
        ZLIB
    }

    /// <summary>
    /// The encryption type to use for file encryption
    /// </summary>
    public enum PgpEncryptionType
    {
        [Display(Name = "AES 128")]
        AES128,
        
        [Display(Name = "AES 192")]
        AES192,
        
        [Display(Name = "AES 256")]
        AES256,
        
        [Display(Name = "Blowfish")]
        BLOWFISH,
        
        [Display(Name = "Camellia 128")]
        CAMELLIA128,
        
        [Display(Name = "Camellia 192")]
        CAMELLIA192,
        
        [Display(Name = "Camellia 256")]
        CAMELLIA256,
        
        [Display(Name = "CAST 5")]
        CAST5,
        
        [Display(Name = "DES")]
        DES,
        
        [Display(Name = "IDEA")]
        IDEA,
        
        [Display(Name = "TDES")]
        TRIPLEDES,
        
        [Display(Name = "TWOFISH")]
        TWOFISH
    }
    
    /// <summary>
    /// The format of the input data
    /// </summary>
    public enum DataFormat
    {
        String,
        Bytes
    }
    
    /// <summary>
    /// The input for cleartext signatures
    /// </summary>
    public class PgpCleartextSignatureInput
    {
        /// <summary>
        /// The format of the input data
        /// </summary>
        [DefaultValue(DataFormat.Bytes)]
        public DataFormat InputDataFormat { get; set; }
        
        /// <summary>
        /// The input data as a string
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.String)]
        public string InputDataString { get; set; }
        
        /// <summary>
        /// The input data as bytes
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.Bytes)]
        public byte[] InputDataBytes { get; set; }

        /// <summary>
        /// Fetch a memory string from the input data
        /// </summary>
        /// <returns></returns>
        public Stream GetInputStream()
        {
            if (InputDataFormat == DataFormat.String)
            {
                return Helpers.StreamFromString(InputDataString);
            }

            return Helpers.StreamFromBytearray(InputDataBytes);
        }
        
        /// <summary>
        /// The private key used to sign the data
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [PasswordPropertyText]
        public string PrivateKey { get; set; }

        /// <summary>
        /// The password for the private key
        /// </summary>
        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }
    }
    
    /// <summary>
    /// The output from the cleartext signature task
    /// </summary>
    public class PgpCleartextSignatureResult
    {
        /// <summary>
        /// The contents of the armored signed message in bytes
        /// </summary>
        public byte[] SignatureBytes { get; set; }
        
        /// <summary>
        /// The armored signature
        /// </summary>
        public string ArmoredSignature { get; set; }
    }

    /// <summary>
    /// Parameters for the PGP Decryption task
    /// </summary>
    public class PgpDecryptInput
    {
        /// <summary>
        /// The data format of the input data
        /// </summary>
        [DefaultValue(DataFormat.Bytes)]
        public DataFormat InputDataFormat { get; set; }
        
        /// <summary>
        /// The input data as a string
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.String)]
        public string InputDataString { get; set; }
        
        /// <summary>
        /// The input data as bytes
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.Bytes)]
        public byte[] InputDataBytes { get; set; }

        /// <summary>
        /// Get a memory stream containing the input data
        /// </summary>
        /// <returns></returns>
        public Stream GetInputStream()
        {
            if (InputDataFormat == DataFormat.String)
            {
                return Helpers.StreamFromString(InputDataString);
            }

            return Helpers.StreamFromBytearray(InputDataBytes);
        }

        /// <summary>
        /// The private key used to decrypt the data
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [PasswordPropertyText]
        public string PrivateKey { get; set; }

        /// <summary>
        /// The password for the private key
        /// </summary>
        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }
    }

    /// <summary>
    /// The result of the DecryptFile step
    /// </summary>
    public class PgpDecryptResult
    {
        public byte[] DecryptedBytes { get; set; }
        public string DecryptedText { get; set; }
    }

    /// <summary>
    /// Parameters for the PGP Encryption task
    /// </summary>
    public class PgpEncryptInput
    {
        /// <summary>
        /// The format of the input data
        /// </summary>
        [DefaultValue(DataFormat.Bytes)]
        public DataFormat InputDataFormat { get; set; }
        
        /// <summary>
        /// The input data as a string
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.String)]
        public string InputDataString { get; set; }
        
        /// <summary>
        /// The input data as bytes
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.Bytes)]
        public byte[] InputDataBytes { get; set; }

        /// <summary>
        /// Get a memory stream containing the input data
        /// </summary>
        /// <returns></returns>
        public Stream GetInputStream()
        {
            if (InputDataFormat == DataFormat.String)
            {
                return Helpers.StreamFromString(InputDataString);
            }

            return Helpers.StreamFromBytearray(InputDataBytes);
        }
        
        /// <summary>
        /// The identifier for the input data, normally the previous filename
        /// </summary>
        [DefaultValue("data")] 
        public string InputDataIdentifier { get; set; } = "data";
        
        /// <summary>
        /// PublicKey used to encrypt the data
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        public string PublicKey { get; set; }
        
        /// <summary>
        /// Whether to armor the result
        /// </summary>
        [DefaultValue(true)]
        public bool ArmorResult { get; set; }
        
        /// <summary>
        /// Whether to perform an integrity check once encryption has finished
        /// </summary>
        [DefaultValue(true)]
        public bool IntegrityCheck { get; set; }
        
        /// <summary>
        /// Whether to compress the data before encryption
        /// </summary>
        [DefaultValue(true)]
        public bool Compression { get; set; }
        
        /// <summary>
        /// The compression type to use for the data
        /// </summary>
        [DefaultValue(PgpCompressionType.ZIP)]
        [UIHint(nameof(Compression), "", true)]
        public PgpCompressionType CompressionType { get; set; }
        
        /// <summary>
        /// The type of encryption to use
        /// </summary>
        [DefaultValue(PgpEncryptionType.AES256)]
        public PgpEncryptionType EncryptionType { get; set; }
    }
 
    /// <summary>
    /// The result from the Encrypt step
    /// </summary>
    public class PgpEncryptResult
    {
        public byte[] EncryptedBytes { get; set; }
        public string EncryptedText { get; set; }
    }


/// <summary>
/// Input for the Swedbank-specific Sign and Encrypt function
/// </summary>
public class SwedbankSignEncryptInput {

    /// <summary>
    /// The input data to be signed
    /// </summary>
    /// <value></value>
    [Display(Name = "Input Data")]
    [DisplayFormat(DataFormatString = "Expression")]
    public byte[] InputData { get; set; }

    /// <summary>
    /// The private key for the signature
    /// </summary>
    /// <value></value>
    [Display(Name = "Hoglandet Private Key")]
    [PasswordPropertyText]
    [DisplayFormat(DataFormatString = "Expression")]
    public string SignaturePrivateKey { get; set; }

    /// <summary>
    /// The password for the signature private key
    /// </summary>
    /// <value></value>
    [Display(Name = "Hoglandet Private Key Password")]
    [PasswordPropertyText]
    [DisplayFormat(DataFormatString = "Expression")]
    public string SignaturePrivateKeyPassword { get; set; }

    /// <summary>
    /// The public key to use for encryption
    /// </summary>
    /// <value></value>
    [Display(Name = "Swedbank Public Key")]
    public string EncryptionPublicKey { get; set; }
}


    /// <summary>
    /// Input configuration for Sign and Encrypt
    /// </summary>
    public class PgpSignAndEncryptInput {
        /// <summary>
        /// The format of the input data
        /// </summary>
        [DefaultValue(DataFormat.Bytes)]
        public DataFormat InputDataFormat { get; set; }
        
        /// <summary>
        /// The input data as a string
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.String)]
        public string InputDataString { get; set; }
        
        /// <summary>
        /// The input data as bytes
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.Bytes)]
        public byte[] InputDataBytes { get; set; }

        /// <summary>
        /// Get a memory stream containing the input data
        /// </summary>
        /// <returns></returns>
        public Stream GetInputStream()
        {
            if (InputDataFormat == DataFormat.String)
            {
                return Helpers.StreamFromString(InputDataString);
            }

            return Helpers.StreamFromBytearray(InputDataBytes);
        }

        /// <summary>
        /// The identifier for the input data, normally the previous filename
        /// </summary>
        [DefaultValue("data")]
        public string InputDataIdentifier { get; set; } = "data";

        /// <summary>
        /// The private key used to sign the data
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [PasswordPropertyText]
        public string SignaturePrivateKey { get; set; }

        /// <summary>
        /// The password for the private key
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [PasswordPropertyText]
        public string SignaturePrivateKeyPassword { get; set; }

        /// <summary>
        /// PublicKey used to encrypt the data
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        public string EncryptionPublicKey { get; set; }

        /// <summary>
        /// What hash function to use for the signature
        /// </summary>
        [DefaultValue(PgpHashFunctionType.SHA256)]
        public PgpHashFunctionType SignatureHashFunction { get; set; }
        
        /// <summary>
        /// Whether to armor the result
        /// </summary>
        [DefaultValue(false)]
        public bool ArmorSignatureResult { get; set; }

        /// <summary>
        /// Whether to armor the result
        /// </summary>
        [DefaultValue(true)]
        public bool ArmorEncryptionResult { get; set; }
        
        /// <summary>
        /// Whether to perform an integrity check once encryption has finished
        /// </summary>
        [DefaultValue(true)]
        public bool EncryptionIntegrityCheck { get; set; }
        
        /// <summary>
        /// Whether to compress the data before encryption
        /// </summary>
        [DefaultValue(true)]
        public bool EncryptionCompression { get; set; }
        
        /// <summary>
        /// The compression type to use for the data
        /// </summary>
        [DefaultValue(PgpCompressionType.ZLIB)]
        [UIHint(nameof(EncryptionCompression), "", true)]
        public PgpCompressionType EncryptionCompressionType { get; set; }
        
        /// <summary>
        /// The type of encryption to use
        /// </summary>
        [DefaultValue(PgpEncryptionType.AES256)]
        public PgpEncryptionType EncryptionType { get; set; }

    }
    
    /// <summary>
    /// The input for the Sign step
    /// </summary>
    public class PgpSignatureInput
    {
        /// <summary>
        /// The format of the input data
        /// </summary>
        [DefaultValue(DataFormat.Bytes)]
        public DataFormat InputDataFormat { get; set; }
        
        /// <summary>
        /// The input data as a string
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.String)]
        public string InputDataString { get; set; }
        
        /// <summary>
        /// The input data as bytes
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.Bytes)]
        public byte[] InputDataBytes { get; set; }

        /// <summary>
        /// Get a memory stream containing the input data
        /// </summary>
        /// <returns></returns>
        public Stream GetInputStream()
        {
            if (InputDataFormat == DataFormat.String)
            {
                return Helpers.StreamFromString(InputDataString);
            }

            return Helpers.StreamFromBytearray(InputDataBytes);
        }
        
        /// <summary>
        /// The identifier for the input data, normally the previous filename
        /// </summary>
        [DefaultValue("data")]
        public string InputDataIdentifier { get; set; } = "data";

        /// <summary>
        /// The private key used to sign the data
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [PasswordPropertyText]
        public string PrivateKey { get; set; }

        /// <summary>
        /// The password for the private key
        /// </summary>
        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }
        
        /// <summary>
        /// Whether to armor the result
        /// </summary>
        [DefaultValue(true)]
        public bool ArmorResult { get; set; }

        /// <summary>
        /// What hash function to use for the signature
        /// </summary>
        [DefaultValue(PgpHashFunctionType.SHA256)]
        public PgpHashFunctionType HashFunction { get; set; }
    }
    
   /// <summary>
   /// The result from the Sign step
   /// </summary>
    public class PgpSignatureResult
    {
        /// <summary>
        /// The contents of the armored signed message in bytes
        /// </summary>
        public byte[] SignatureBytes { get; set; }
        
        /// <summary>
        /// The armored signature
        /// </summary>
        public string SignatureText { get; set; }
    }

   
    public class PgpVerifyCleartextSignatureInput
    {
        [DefaultValue(DataFormat.Bytes)]
        public DataFormat InputDataFormat { get; set; }
        
        [UIHint(nameof(InputDataFormat), "", DataFormat.String)]
        public string InputDataString { get; set; }
        
        [UIHint(nameof(InputDataFormat), "", DataFormat.Bytes)]
        public byte[] InputDataBytes { get; set; }

        public Stream GetInputStream()
        {
            if (InputDataFormat == DataFormat.String)
            {
                return Helpers.StreamFromString(InputDataString);
            }

            return Helpers.StreamFromBytearray(InputDataBytes);
        }
        
        [DisplayFormat(DataFormatString = "Expression")]
        public string PublicKey { get; set; }
    }
    
    public class PgpVerifyCleartextSignatureResult
    {
        public bool Valid { get; set; }
        public byte[] ValidatedDataBytes { get; set; }
        public string ValidatedDataText { get; set; }
    }
    
    /// <summary>
    /// Input for the VerifySignature step
    /// </summary>
    public class PgpVerifySignatureInput
    {
        /// <summary>
        /// The format of the input data
        /// </summary>
        [DefaultValue(DataFormat.Bytes)]
        public DataFormat InputDataFormat { get; set; }
        
        /// <summary>
        /// The input data as a string
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.String)]
        public string InputDataString { get; set; }
        
        /// <summary>
        /// The input data as bytes
        /// </summary>
        [UIHint(nameof(InputDataFormat), "", DataFormat.Bytes)]
        public byte[] InputDataBytes { get; set; }

        /// <summary>
        /// Get a memory stream containing the input data
        /// </summary>
        /// <returns></returns>
        public Stream GetInputStream()
        {
            if (InputDataFormat == DataFormat.String)
            {
                return Helpers.StreamFromString(InputDataString);
            }

            return Helpers.StreamFromBytearray(InputDataBytes);
        }
        
        /// <summary>
        /// The public key used to verify the signature
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        public string PublicKey { get; set; }
    }
    
    /// <summary>
    /// The result from the VerifySignature step
    /// </summary>
    public class PgpVerifySignatureResult
    {
        /// <summary>
        /// If the signature is valid
        /// </summary>
        public bool Valid { get; set; }
        
        /// <summary>
        /// The contents of the signed message in bytes
        /// </summary>
        public byte[] ValidatedDataBytes { get; set; }
        
        /// <summary>
        /// The contents of the signed message as a string
        /// </summary>
        public string ValidatedDataText { get; set; }
    }
}
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.HIT.OpenPGP;

public class Definitions
{
    public enum PgpHashFunctionType
    {
        MD5,
        SHA1,
        RIPEMD160,
        SHA224,
        SHA256,
        SHA384,
        SHA512
    }

    public enum PgpCompressionType
    {
        BZIP2,
        UNCOMPRESSED,
        ZIP,
        ZLIB
    }

    public enum PgpEncryptionType
    {
        AES128,
        AES192,
        AES256,
        BLOWFISH,
        CAMELLIA128,
        CAMELLIA192,
        CAMELLIA256,
        CAST5,
        DES,
        IDEA,
        TRIPLEDES,
        TWOFISH
    }
    
    public class PgpCleartextSignatureInput
    {
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputData { get; set; }

        [DisplayFormat(DataFormatString = "Expression")]
        public string PrivateKey { get; set; }

        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }
    }
    
    public class PgpCleartextSignatureResult
    {
        public byte[] SignatureBytes { get; set; }
        public string ArmoredSignature { get; set; }
    }

    public class PgpDecryptInput
    {
        [DisplayFormat(DataFormatString = "Expression")]
        public string InputData { get; set; }

        [DisplayFormat(DataFormatString = "Expression")]
        public string PrivateKey { get; set; }

        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }
    }
    public class PgpDecryptBytesInput
    {
        [DisplayFormat(DataFormatString = "Expression")]
        public byte[] InputData { get; set; }

        [DisplayFormat(DataFormatString = "Expression")]
        public string PrivateKey { get; set; }

        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }
    }

    public class PgpDecryptResult
    {
        public byte[] DecryptedBytes { get; set; }
        public string DecryptedText { get; set; }
    }

    public class PgpEncryptInput
    {
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputData { get; set; }
        
        [DisplayFormat(DataFormatString = "Expression")]
        public string PublicKey { get; set; }
        
        [DefaultValue(true)]
        public bool ArmorResult { get; set; }
        
        [DefaultValue(true)]
        public bool IntegrityCheck { get; set; }
        
        [DefaultValue(true)]
        public bool Compression { get; set; }
        
        [DefaultValue(PgpCompressionType.ZIP)]
        [UIHint(nameof(Compression), "", true)]
        public PgpCompressionType CompressionType { get; set; }
        
        [DefaultValue(PgpEncryptionType.AES256)]
        public PgpEncryptionType EncryptionType { get; set; }
    }
    public class PgpEncryptBytesInput
    {
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public byte[] InputData { get; set; }
        
        [DisplayFormat(DataFormatString = "Expression")]
        public string PublicKey { get; set; }
        
        [DefaultValue(true)]
        public bool ArmorResult { get; set; }
        
        [DefaultValue(true)]
        public bool IntegrityCheck { get; set; }
        
        [DefaultValue(true)]
        public bool Compression { get; set; }
        
        [DefaultValue(PgpCompressionType.ZIP)]
        [UIHint(nameof(Compression), "", true)]
        public PgpCompressionType CompressionType { get; set; }
        
        [DefaultValue(PgpEncryptionType.AES256)]
        public PgpEncryptionType EncryptionType { get; set; }
    }
    
    public class PgpEncryptResult
    {
        public byte[] EncryptedBytes { get; set; }
        public string EncryptedText { get; set; }
    }
    
    public class PgpSignatureInput
    {
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputData { get; set; }

        [DisplayFormat(DataFormatString = "Expression")]
        public string PrivateKey { get; set; }

        [PasswordPropertyText]
        public string PrivateKeyPassword { get; set; }

        [DefaultValue(PgpHashFunctionType.SHA256)]
        public PgpHashFunctionType HashFunction { get; set; }
    }
    
    public class PgpSignatureResult
    {
        public byte[] Signature { get; set; }
        public string ArmoredSignature { get; set; }
    }

    public class PgpVerifyCleartextSignatureInput
    {
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputData { get; set; }
        
        [DisplayFormat(DataFormatString = "Expression")]
        public string PublicKey { get; set; }
    }
    
    public class PgpVerifyCleartextSignatureResult
    {
        public bool Valid { get; set; }
        public byte[] ValidatedDataBytes { get; set; }
        public string ValidatedDataText { get; set; }
    }
    
    public class PgpVerifySignatureInput
    {
        [DefaultValue("")]
        [DisplayFormat(DataFormatString = "Text")]
        public string InputData { get; set; }
        
        [DisplayFormat(DataFormatString = "Expression")]
        public string PublicKey { get; set; }
    }
    
    public class PgpVerifySignatureResult
    {
        public bool Valid { get; set; }
        public byte[] ValidatedDataBytes { get; set; }
        public string ValidatedDataText { get; set; }
    }
}
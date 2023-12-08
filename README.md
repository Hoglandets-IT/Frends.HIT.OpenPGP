# Frends.HIT.OpenPGP
This task can encrypt, decrypt, sign and verify files/content using OpenPGP. Relative to Frends.Community.PGP,
this task enables user to pass the data in and out of the function using variables instead of reading from/writing to files.

## Roadmap
- Add DataFormat.Base64

## Frends.HIT.OpenPGP.FrendsInteface.EncryptFile
### Input
| Property             | Type | Description                                               | Example |
|----------------------| ---- |-----------------------------------------------------------| ------- |
| InputDataFormat      | string/enum | Data format of the input data, either 'String' or 'Bytes'. | Bytes |
| InputDataString      | string | Input data as string (used when DataFormat is string)     | "Hello World!" |
| InputDataBytes       | byte[] | Input data as bytes. (used when DataFormat is bytes)      | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| InputDataIdentifier  | string | Identifier of the input data, normally the original file name | "hello.txt" |
| PublicKey            | string | Public key to encrypt the data with. | -----BEGIN PGP PUBLIC KEY BLOCK ... |
| ArmorResult          | bool | Should the result be armored (ASCII armored) | true |
| IntegrityCheck       | bool | Should integrity check be included in the result | true |
| CompressionAlgorithm | string/enum | Compression algorithm to use. | Uncompressed |
| EncryptionType       | string/enum | Encryption algorithm to use. | Aes256 |

### Output
| Property             | Type | Description                                               | Example                                                  |
|----------------------| ---- |-----------------------------------------------------------|----------------------------------------------------------|
| EncryptedBytes       | byte[] | Encrypted data as bytes. | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| EncryptedString      | string | Encrypted data as string. | string |                                                  |

## Frends.HIT.OpenPGP.FrendsInteface.DecryptFile
### Input
| Property             | Type | Description                                               | Example |
|----------------------| ---- |-----------------------------------------------------------| ------- |
| InputDataFormat     | string/enum | Data format of the input data, either 'String' or 'Bytes'. | Bytes |
| InputDataString      | string | Input data as string (used when DataFormat is string)     | "Hello World!" |
| InputDataBytes       | byte[] | Input data as bytes. (used when DataFormat is bytes)      | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| PrivateKey           | string | Private key to decrypt the data with. | -----BEGIN PGP PRIVATE KEY BLOCK ... |
| PrivateKeyPassword   | string | Password for the private key. | "password" |

### Output
| Property             | Type | Description                                               | Example |
|----------------------| ---- |-----------------------------------------------------------| ------- |
| DecryptedBytes       | byte[] | Decrypted data as bytes. | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| DecryptedString      | string | Decrypted data as string. | "Hello World!" |

## Frends.HIT.OpenPGP.FrendsInteface.Sign
### Input
| Property            | Type | Description                                               | Example |
|---------------------| ---- |-----------------------------------------------------------| ------- |
| InputDataFormat     | string/enum | Data format of the input data, either 'String' or 'Bytes'. | Bytes |
| InputDataString     | string | Input data as string (used when DataFormat is string)     | "Hello World!" |
| InputDataBytes      | byte[] | Input data as bytes. (used when DataFormat is bytes)      | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| InputDataIdentifier | string | Identifier of the input data, normally the original file name | "hello.txt" |
| PrivateKey          | string | Private key to sign the data with. | -----BEGIN PGP PRIVATE KEY BLOCK ... |
| PrivateKeyPassword  | string | Password for the private key. | "password" |
| ArmorResult         | bool | Should the result be armored (ASCII armored) | true |
| HashFunction        | string/enum | Hash algorithm to use. | Sha256 |

### Output
| Property             | Type | Description                                               | Example |
|----------------------| ---- |-----------------------------------------------------------| ------- |
| SignatureBytes       | byte[] | Signature data as bytes. | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| SignatureString      | string | Signature data as string. | "Hello World!" |

## Frends.HIT.OpenPGP.FrendsInteface.VerifySignature
### Input
| Property             | Type | Description                                               | Example |
|----------------------| ---- |-----------------------------------------------------------| ------- |
| InputDataFormat      | string/enum | Data format of the input data, either 'String' or 'Bytes'. | Bytes |
| InputDataString      | string | Input data as string (used when DataFormat is string)     | "Hello World!" |
| InputDataBytes       | byte[] | Input data as bytes. (used when DataFormat is bytes)      | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| PublicKey | string | Public key to verify the signature with. | -----BEGIN PGP PUBLIC KEY BLOCK ... |

### Output
| Property             | Type | Description                                               | Example |
|----------------------| ---- |-----------------------------------------------------------| ------- |
| Valid               | bool | Is the signature valid | true |
| ValidatedDataBytes  | byte[] | Validated data as bytes. | [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33] |
| ValidatedDataString | string | Validated data as string. | "Hello World!" |

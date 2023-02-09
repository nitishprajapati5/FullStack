using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using portfolio.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace portfolio.Shared
{
    //No Use In Projects
    /*
    public static class AESEncryptDecrypt
    {
        /// <summary>
        /// AES encryption decryption class to encrypt and decrypt request/response.
        /// </summary>
        public static class AESEncryptDecrypt
        {
            private static string encryptionMode = "AES/OFB/PKCS5PADDING";
            private static string algorithm = "AES";

            /// <summary>
            /// This method is used to encrypt the data with the password
            /// </summary>
            /// <param name="data">Data to be encrypted</param>
            /// <param name="password">Password which will be used to encrypt the data</param>
            /// <returns>encrypted value in string format</returns>
            public static string Encrypt(string data, string password)
            {
                try
                {
                    // Get UTF8 byte array of input string for encryption
                    byte[] inputBytes = ASCIIEncoding.UTF8.GetBytes(data);

                    // Again, get UTF8 byte array of key for use in encryption
                    byte[] keyBytes = ASCIIEncoding.UTF8.GetBytes(password);

                    // Initialize AES OFB (counter) mode cipher from the BouncyCastle cryptography library
                    IBufferedCipher cipher = CipherUtilities.GetCipher(encryptionMode);

                    // Set cipher parameters to use the encryption key we defined above for encryption
                    // Since we are encrypting using the CTR mode / algorithm, the cipher is operating as a stream cipher.
                    // For perfect secrecy with a stream cipher, we should be generating a stream of pseudorandom characters called a keystream,
                    // then XOR'ing that with the plaintext. Instead, for convenience we are just XOR'ing the first [blocksize] bytes of null values.
                    // While convenient, as we only need a single key for two way encryption/decryption, this method is vulnerable to a simple known-plaintext attack
                    // As such, it should not be relied upon for true secrecy, only for security through obscurity.
                    cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter(algorithm, keyBytes), new byte[16]));

                    // As this is a stream cipher, you can process bytes chunk by chunk until complete, then close with DoFinal.
                    // In our case we don't need a stream, so we simply call DoFinal() to encrypt the entire input at once.
                    byte[] encryptedBytes = cipher.DoFinal(inputBytes);

                    // The encryption is complete, however we still need to get the encrypted byte array into a useful form for passing as a URL parameter
                    // First, we convert the encrypted byte array to a Base64 string to make it use ASCII characters
                    string base64EncryptedOutputString = Convert.ToBase64String(encryptedBytes);

                    // Lastly, we replace the 2 characters from Base64 which are not URL safe ( + and / ) with ( - and _ ) as recommended in IETF RFC4648
                    //string urlEncodedBase64EncryptedOutputString = base64EncryptedOutputString.Replace("+", "-").Replace("/", "_");

                    // This final string is now safe to be passed around, into our web service by URL, etc.
                    return base64EncryptedOutputString;
                }
                catch (Exception)
                {
                    throw;
                }
            }

            /// <summary>
            /// This method is used to decrypt the data with the password
            /// </summary>
            /// <param name="encryptedData">encryptedData Data to be decrypted</param>
            /// <param name="password">Password which will be used to decrypt the data</param>
            /// <returns>Decrypted plain text in string format</returns>
            public static string Decrypt(object encryptedData, string password, string reqEncryptionMode = null, byte[] IV = null)
            {
                try
                {
                    // Initialize AES OFB (counter) mode cipher from the BouncyCastle cryptography library
                    IBufferedCipher cipher = reqEncryptionMode == null ? CipherUtilities.GetCipher(encryptionMode) :
                        CipherUtilities.GetCipher(reqEncryptionMode);

                    // Set cipher parameters to use the encryption key we defined above for encryption
                    // Since we are encrypting using the OFB mode / algorithm, the cipher is operating as a stream cipher.
                    // For perfect secrecy with a stream cipher, we should be generating a stream of pseudorandom characters called a keystream,
                    // then XOR'ing that with the plaintext. Instead, for convenience we are just XOR'ing the first [blocksize] bytes of null values.
                    // While convenient, as we only need a single key for two way encryption/decryption, this method is vulnerable to a simple known-plaintext attack
                    // As such, it should not be relied upon for true secrecy, only for security through obscurity.
                    cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter(algorithm, ASCIIEncoding.UTF8.GetBytes(password)), IV == null ? new byte[16] : IV));
                    // As this is a stream cipher, you can process bytes chunk by chunk until complete, then close with DoFinal.
                    // In our case we don't need a stream, so we simply call DoFinal() to encrypt the entire input at once.
                    byte[] decryptedBytes = cipher.DoFinal(Convert.FromBase64String(Encoding.UTF8.GetString(ASCIIEncoding.UTF8.GetBytes(Convert.ToString(encryptedData)))));

                    string plainTextOutputString = Encoding.UTF8.GetString(decryptedBytes);

                    // Lastly, we replace the 2 characters from Base64 which are not URL safe ( + and / ) with ( - and _ ) as recommended in IETF RFC4648
                    //string urlEncodedBase64EncryptedOutputString = plainTextOutputString.Replace("+", "-").Replace("/", "_");

                    return plainTextOutputString;
                }
                catch (Exception)
                {
                    throw;
                }
            }

            /// <summary>
            /// This method is used to create a password from the master key and index
            /// </summary>
            /// <param name="masterKey">masterKey master key which will be used to create the master key</param>
            /// <param name="index">index value</param>
            /// <returns>created password in string format</returns>
            public static string CreatePassword(string masterKey, int index)
            {
                try
                {
                    string finalKey = string.Empty;

                    masterKey = Convert.ToBase64String(ASCIIEncoding.UTF8.GetBytes(masterKey));

                    int finalKeyLength = 32;
                    int totalLength = masterKey.Length;
                    int chunkSize = finalKeyLength / 4;

                    int tempChunkStartIndex = index;
                    int tempChunkEndIndex = 0;

                    String[] tempKey = new String[4];
                    for (int step = 0; step < 4; step++)
                    {
                        tempChunkEndIndex = tempChunkStartIndex + chunkSize;
                        if (tempChunkEndIndex < totalLength)
                        {
                            tempKey[step] = masterKey.Substring(tempChunkStartIndex, (tempChunkEndIndex - tempChunkStartIndex));
                            tempChunkStartIndex = tempChunkEndIndex;
                        }
                        else
                        {
                            tempKey[step] = masterKey.Substring(tempChunkStartIndex, (totalLength - tempChunkStartIndex)) + masterKey.Substring(0, tempChunkEndIndex - totalLength);
                            tempChunkStartIndex = tempChunkEndIndex - totalLength;
                        }
                    }

                    char[] chartempKey = tempKey[3].ToCharArray(); Array.Reverse(chartempKey);
                    char[] chartempKey1 = tempKey[2].ToCharArray(); Array.Reverse(chartempKey1);

                    //get final result key - sequence -  3120
                    finalKey = new StringBuilder(new string(chartempKey) + tempKey[1].ToString() + new string(chartempKey1) + tempKey[0].ToString()).ToString();

                    return finalKey;
                }
                catch (Exception)
                {
                    throw;
                }
            }

            /// <summary>
            /// This method is used to generate the index from the master key
            /// </summary>
            /// <returns>Generated random index</returns>
            public static int GenerateIndex()
            {
                try
                {
                    return new Random().Next(0, 15);
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }

        /// <summary>
        /// AES 256 CBC encryption decryption class to encrypt and decrypt ESB request/response.
        /// </summary>
        public static class ESBEncryptDecrypt
        {
            //static int iterations = 65556;

            public static string Encrypt(string plainText, string password, int iterations)
            {
                try
                {
                    if (!string.IsNullOrEmpty(plainText.IsNullString()))
                    {

                        //Get random Salt
                        byte[] salt = new byte[20];
                        new Random().NextBytes(salt);

                        // Derive the key
                        var rfc2898 = new Rfc2898DeriveBytes(password, salt, iterations);
                        byte[] key = rfc2898.GetBytes(32);

                        // Set up AES Cipher
                        AesManaged aesCipher = new AesManaged
                        {
                            KeySize = 256,
                            BlockSize = 128,
                            Mode = CipherMode.CBC,
                            Padding = PaddingMode.PKCS7,
                            Key = key
                        };

                        //Get initialized IV
                        byte[] IV = aesCipher.IV;

                        // Encrypt the message
                        byte[] b = System.Text.Encoding.UTF8.GetBytes(plainText);
                        ICryptoTransform encryptTransform = aesCipher.CreateEncryptor();
                        byte[] cipherText = encryptTransform.TransformFinalBlock(b, 0, b.Length);

                        //prepend salt and vi
                        byte[] buffer = new byte[salt.Length + IV.Length + cipherText.Length];
                        Array.Copy(salt, 0, buffer, 0, salt.Length);
                        Array.Copy(IV, 0, buffer, salt.Length, IV.Length);
                        Array.Copy(cipherText, 0, buffer, salt.Length + IV.Length, cipherText.Length);

                        return Convert.ToBase64String(buffer);
                    }
                    return null;
                }
                catch (Exception)
                {
                    throw;
                }
            }

            public static string Decrypt(string cipherText, string password, int iterations)
            {
                try
                {
                    byte[] buffer;

                    using (MemoryStream stream = new MemoryStream())
                    {
                        using (BinaryWriter writer = new BinaryWriter(stream))
                        {
                            try
                            {
                                writer.Write(Convert.FromBase64String(cipherText));
                                buffer = stream.ToArray();
                            }
                            catch (Exception)
                            {
                                return string.Empty;
                            }
                        }
                    }

                    //strip off the salt and iv
                    byte[] saltByte = new byte[20];
                    Array.Copy(buffer, 0, saltByte, 0, saltByte.Length);

                    byte[] ivByte = new byte[16];
                    Array.Copy(buffer, saltByte.Length, ivByte, 0, ivByte.Length);

                    byte[] cipherTextBytes = new byte[buffer.Length - saltByte.Length - ivByte.Length];
                    Array.Copy(buffer, saltByte.Length + ivByte.Length, cipherTextBytes, 0, cipherTextBytes.Length);

                    //Derive
                    var rfc2898 = new Rfc2898DeriveBytes(password, saltByte, iterations);
                    byte[] key = rfc2898.GetBytes(32);

                    // Set up AES Cipher
                    AesManaged aesCipher = new AesManaged
                    {
                        KeySize = 256,
                        BlockSize = 128,
                        Mode = CipherMode.CBC,
                        Padding = PaddingMode.PKCS7,
                        Key = key,
                        IV = ivByte
                    };

                    // Decrypt message
                    ICryptoTransform decryptTransform = aesCipher.CreateDecryptor();
                    byte[] plainText = decryptTransform.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);

                    //get string
                    return Encoding.UTF8.GetString(plainText);
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }

        #region BharatQR Encrypt request
        public static class BharatQREncryptRequest
        {
            #region Encrypt
            //generate key for AES algorithm
            public static byte[] GenerateToken()
            {
                byte[] symmetricKey = null;
                try
                {
                    AesManaged objAesKey = new AesManaged();
                    objAesKey.KeySize = 128;
                    objAesKey.Mode = CipherMode.CBC;
                    objAesKey.Padding = PaddingMode.PKCS7;

                    objAesKey.GenerateKey();
                    symmetricKey = objAesKey.Key;
                }
                catch
                {
                    throw;
                }

                return symmetricKey;
            }

            //AES encryption
            public static string EncryptData(string requestData, byte[] sessionKey,
                                      string messageRefNo)
            {
                string encryptedText = null;
                try
                {
                    AesManaged objAesKey = new AesManaged();
                    objAesKey.KeySize = 128;
                    objAesKey.Mode = CipherMode.CBC;
                    objAesKey.Padding = PaddingMode.PKCS7;

                    objAesKey.Key = sessionKey;
                    objAesKey.IV = Encoding.ASCII.GetBytes(messageRefNo);

                    byte[] requestDataBytes = Encoding.ASCII.GetBytes(requestData);

                    MemoryStream ms = new MemoryStream();
                    CryptoStream cs = new CryptoStream(ms, objAesKey.CreateEncryptor(), CryptoStreamMode.Write);
                    cs.Write(requestDataBytes, 0, requestDataBytes.Length);
                    if (cs != null)
                    {
                        cs.Close();
                    }
                    byte[] encryptedTextBytes = ms.ToArray();

                    encryptedText = Convert.ToBase64String(encryptedTextBytes);

                }
                catch
                {
                    throw;
                }
                return encryptedText;
            }

            //RSA encryption
            public static string EncryptKey(byte[] sessionKey, string fileName)
            {
                string encryptedKey = null;
                try
                {
                    RSACryptoServiceProvider rsa = ReadPublicKeyFromFile(CommonLib.HostingEnvironment.WebRootPath + "\\" + fileName);
                    byte[] encryptedKeyBytes = rsa.Encrypt(sessionKey, false);
                    encryptedKey = Convert.ToBase64String(encryptedKeyBytes);
                }
                catch (Exception ex)
                {
                    throw;
                }

                return encryptedKey;
            }

            //Sign body content with private key and SHA1withRSA
            public static string GenerateDigitalSignedToken(string requestData, string fileName)
            {
                string signedToken = null;
                try
                {
                    byte[] requestDataBytes = Encoding.ASCII.GetBytes(requestData);

                    RSACryptoServiceProvider rsa = ReadPrivateKeyFromFile(CommonLib.HostingEnvironment.WebRootPath + "\\" + fileName);
                    SHA1Managed sha = new SHA1Managed();
                    byte[] signedTokenBytes = rsa.SignData(requestDataBytes, sha);

                    signedToken = Convert.ToBase64String(signedTokenBytes);
                }
                catch (Exception ex)
                {
                    throw;
                }
                return signedToken;
            }

            //Read DER public key from file
            private static RSACryptoServiceProvider ReadPublicKeyFromFile(String keyFileName)
            {
                RSACryptoServiceProvider rsa = null;
                try
                {

                    byte[] keyblob = GetFileBytes(keyFileName);
                    if (keyblob != null)
                    {
                        rsa = DecodeX509PublicKey(keyblob);
                    }
                }
                catch
                {
                    throw;
                }
                return rsa;
            }

            public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
            {
                // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
                byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
                byte[] seq = new byte[15];
                // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
                MemoryStream mem = new MemoryStream(x509key);
                BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
                byte bt = 0;
                ushort twobytes = 0;

                try
                {

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    seq = binr.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x00)     //expect null byte next
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte(); //advance 2 bytes
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    byte firstbyte = binr.ReadByte();
                    binr.BaseStream.Seek(-1, SeekOrigin.Current);

                    if (firstbyte == 0x00)
                    {   //if first byte (highest order) of modulus is zero, don't include it
                        binr.ReadByte();    //skip this null byte
                        modsize -= 1;   //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                    if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                        return null;
                    int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binr.ReadBytes(expbytes);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSAParameters RSAKeyInfo = new RSAParameters();
                    RSAKeyInfo.Modulus = modulus;
                    RSAKeyInfo.Exponent = exponent;
                    RSA.ImportParameters(RSAKeyInfo);
                    return RSA;
                }
                catch (Exception)
                {
                    return null;
                }

                finally { binr.Close(); }

            }

            //Read private key from file
            static RSACryptoServiceProvider ReadPrivateKeyFromFile(String keyFileName)
            {
                RSACryptoServiceProvider rsa = null;
                try
                {

                    byte[] keyblob = GetFileBytes(keyFileName);
                    if (keyblob != null)
                    {
                        rsa = DecodeRSAPrivateKey(keyblob);
                    }
                }
                catch
                {
                    throw;
                }
                return rsa;
            }

            //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
            public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
            {
                // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
                // this byte[] includes the sequence byte and terminal encoded null 
                byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
                byte[] seq = new byte[15];
                // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
                MemoryStream mem = new MemoryStream(privkey);
                int lenstream = (int)mem.Length;
                BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
                byte bt = 0;
                ushort twobytes = 0;

                try
                {

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;


                    bt = binr.ReadByte();
                    if (bt != 0x02)
                        return null;

                    twobytes = binr.ReadUInt16();

                    if (twobytes != 0x0001)
                        return null;

                    seq = binr.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x04) //expect an Octet string 
                        return null;

                    bt = binr.ReadByte();       //read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
                    if (bt == 0x81)
                        binr.ReadByte();
                    else
                     if (bt == 0x82)
                        binr.ReadUInt16();
                    //------ at this stage, the remaining sequence should be the RSA private key

                    byte[] rsaprivkey = binr.ReadBytes((int)(lenstream - mem.Position));
                    RSACryptoServiceProvider rsacsp = GetRSAPrivateKeyParam(rsaprivkey);
                    return rsacsp;
                }

                catch (Exception)
                {
                    return null;
                }

                finally { binr.Close(); }

            }

            //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
            public static RSACryptoServiceProvider GetRSAPrivateKeyParam(byte[] privkey)
            {
                byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

                // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
                MemoryStream mem = new MemoryStream(privkey);
                BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
                byte bt = 0;
                ushort twobytes = 0;
                int elems = 0;
                try
                {
                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes != 0x0102) //version number
                        return null;
                    bt = binr.ReadByte();
                    if (bt != 0x00)
                        return null;


                    //------  all private key components are Integer sequences ----
                    elems = GetIntegerSize(binr);
                    MODULUS = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    E = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    D = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    P = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    Q = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    DP = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    DQ = binr.ReadBytes(elems);

                    elems = GetIntegerSize(binr);
                    IQ = binr.ReadBytes(elems);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSAParameters RSAparams = new RSAParameters();
                    RSAparams.Modulus = MODULUS;
                    RSAparams.Exponent = E;
                    RSAparams.D = D;
                    RSAparams.P = P;
                    RSAparams.Q = Q;
                    RSAparams.DP = DP;
                    RSAparams.DQ = DQ;
                    RSAparams.InverseQ = IQ;
                    RSA.ImportParameters(RSAparams);
                    return RSA;
                }
                catch (Exception)
                {
                    return null;
                }
                finally { binr.Close(); }
            }

            private static int GetIntegerSize(BinaryReader binr)
            {
                byte bt = 0;
                byte lowbyte = 0x00;
                byte highbyte = 0x00;
                int count = 0;
                bt = binr.ReadByte();
                if (bt != 0x02)     //expect integer
                    return 0;
                bt = binr.ReadByte();

                if (bt == 0x81)
                    count = binr.ReadByte();    // data size in next byte
                else
                    if (bt == 0x82)
                {
                    highbyte = binr.ReadByte(); // data size in next 2 bytes
                    lowbyte = binr.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;     // we already have the data size
                }
                while (binr.ReadByte() == 0x00)
                {   //remove high order zeros in data
                    count -= 1;
                }
                binr.BaseStream.Seek(-1, SeekOrigin.Current);
                //last ReadByte wasn't a removed zero, so back up a byte
                return count;
            }

            public static byte[] GetFileBytes(String filename)
            {
                if (!File.Exists(filename))
                    return null;
                Stream stream = new FileStream(filename, FileMode.Open);
                int datalen = (int)stream.Length;
                byte[] filebytes = new byte[datalen];
                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(filebytes, 0, datalen);
                stream.Close();
                return filebytes;
            }

            private static bool CompareBytearrays(byte[] a, byte[] b)
            {
                if (a.Length != b.Length)
                    return false;
                int i = 0;
                foreach (byte c in a)
                {
                    if (c != b[i])
                        return false;
                    i++;
                }
                return true;
            }

            #endregion

            #region Decode
            public static byte[] Decryptkey(byte[] sessionKeyBytes, string fileName)
            {
                string decrytedKey = null;
                byte[] decryptedKeyBytes;
                try
                {
                    RSACryptoServiceProvider rsa = ReadPrivateKeyFromFile(CommonLib.HostingEnvironment.WebRootPath + "\\" + fileName);

                    decryptedKeyBytes = rsa.Decrypt(sessionKeyBytes, false);
                    decrytedKey = Convert.ToBase64String(decryptedKeyBytes);
                }
                catch (Exception ex)
                {
                    throw;
                }

                return decryptedKeyBytes;
            }

            public static string DecodeResponse(string data, byte[] key, string messageRefNo)
            {
                string decrytedData = null;
                try
                {
                    byte[] requestDataBytes = Convert.FromBase64String(data);
                    AesManaged objAesKey = new AesManaged();
                    objAesKey.KeySize = 128;
                    objAesKey.Mode = CipherMode.CBC;
                    objAesKey.Padding = PaddingMode.PKCS7;

                    objAesKey.Key = key;
                    objAesKey.IV = Encoding.ASCII.GetBytes(messageRefNo);

                    MemoryStream ms = new MemoryStream();
                    CryptoStream cs = new CryptoStream(ms, objAesKey.CreateDecryptor(), CryptoStreamMode.Write);
                    cs.Write(requestDataBytes, 0, requestDataBytes.Length);
                    if (cs != null)
                    {
                        cs.Close();
                    }
                    byte[] encryptedTextBytes = ms.ToArray();
                    Encoding encoding = Encoding.UTF8;
                    decrytedData = encoding.GetString(ms.ToArray());
                }
                catch
                {
                    throw;
                }
                return decrytedData;
            }

            public static bool VerifySignature(string clearInput, string responseHash, string fileName)
            {
                bool isVerified;
                byte[] hash = Convert.FromBase64String(responseHash);

                RSACryptoServiceProvider rsa = ReadPublicKeyFromFile(CommonLib.HostingEnvironment.WebRootPath + "\\" + fileName); ;

                SHA1 sha = new SHA1CryptoServiceProvider();
                byte[] signature = sha.ComputeHash(Encoding.ASCII.GetBytes(clearInput));

                isVerified = rsa.VerifyHash(signature, CryptoConfig.MapNameToOID("SHA1"), hash);
                return isVerified;
            }
            #endregion
        }
        #endregion
    }

    */
}

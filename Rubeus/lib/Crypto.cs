using System;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace Rubeus
{
    public class Crypto
    {
        // Adapted from Kevin-Robertson powershell Get-KerberosAESKey: https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372
        // References:
        // * [MS-KILE] open spec' https://msdn.microsoft.com/library/cc233855.aspx?f=255&MSPPError=-2147217396
        // * RFC regarding AES in Kerberos https://www.rfc-editor.org/rfc/pdfrfc/rfc3962.txt.pdf
        public static byte[] ComputeAES256KerberosKey(byte[] password, byte[] salt)
        {
            byte[] AES256_CONSTANT = { 0x6B, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6F, 0x73, 0x7B, 0x9B, 0x5B, 0x2B, 0x93, 0x13, 0x2B, 0x93, 0x5C, 0x9B, 0xDC, 0xDA, 0xD9, 0x5C, 0x98, 0x99, 0xC4, 0xCA, 0xE4, 0xDE, 0xE6, 0xD6, 0xCA, 0xE4 };
            const int rounds = 4096;
            var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(password, salt, rounds);
            byte[] pbkdf2_aes256_key = pbkdf2.GetBytes(32);

            string pbkdf2_aes256_key_string = System.BitConverter.ToString(pbkdf2_aes256_key).Replace("-", "");

            var aes = new System.Security.Cryptography.AesManaged();
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.None;
            aes.KeySize = 256;
            aes.Key = pbkdf2_aes256_key;
            aes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var encryptor = aes.CreateEncryptor();
            byte[] aes256_key_part_1 = encryptor.TransformFinalBlock(AES256_CONSTANT, 0, AES256_CONSTANT.Length);
            byte[] aes256_key_part_2 = encryptor.TransformFinalBlock(aes256_key_part_1, 0, aes256_key_part_1.Length);
            byte[] aes256_key = aes256_key_part_1.Take(16).Concat(aes256_key_part_2.Take(16)).ToArray();
            return aes256_key;
        }

        public static byte[] ComputeRC4KerberosKey(string password)
        {
            // RC4 Kerberos Key is NTLM
            byte[] password_byte = System.Text.Encoding.Unicode.GetBytes(password);
            return ComputeMD4(password_byte);
        }

        // source: https://rosettacode.org/wiki/MD4#C.23
        private static byte[] ComputeMD4(byte[] plain)
        {
            // get padded uints from bytes
            List<byte> bytes = plain.ToList();
            uint bitCount = (uint)(bytes.Count) * 8;
            bytes.Add(128);
            while (bytes.Count % 64 != 56) bytes.Add(0);
            var uints = new List<uint>();
            for (int i = 0; i + 3 < bytes.Count; i += 4)
                uints.Add(bytes[i] | (uint)bytes[i + 1] << 8 | (uint)bytes[i + 2] << 16 | (uint)bytes[i + 3] << 24);
            uints.Add(bitCount);
            uints.Add(0);

            // run rounds
            uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
            Func<uint, uint, uint> rol = (x, y) => x << (int)y | x >> 32 - (int)y;
            for (int q = 0; q + 15 < uints.Count; q += 16)
            {
                var chunk = uints.GetRange(q, 16);
                uint aa = a, bb = b, cc = c, dd = d;
                Action<Func<uint, uint, uint, uint>, uint[]> round = (f, y) =>
                {
                    foreach (uint i in new[] { y[0], y[1], y[2], y[3] })
                    {
                        a = rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                        d = rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                        c = rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                        b = rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                    }
                };
                round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
                round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
                round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
                a += aa; b += bb; c += cc; d += dd;
            }

            // return hex encoded string
            byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
            return outBytes;
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        public static byte[] KerberosChecksum(byte[] key, byte[] data)
        {
            Interop.KERB_CHECKSUM pCheckSum;
            IntPtr pCheckSumPtr;
            int status = Interop.CDLocateCheckSum(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5, out pCheckSumPtr);
            pCheckSum = (Interop.KERB_CHECKSUM)Marshal.PtrToStructure(pCheckSumPtr, typeof(Interop.KERB_CHECKSUM));
            if (status != 0)
            {
                throw new Win32Exception(status, "CDLocateCheckSum failed");
            }

            IntPtr Context;
            Interop.KERB_CHECKSUM_InitializeEx pCheckSumInitializeEx = (Interop.KERB_CHECKSUM_InitializeEx)Marshal.GetDelegateForFunctionPointer(pCheckSum.InitializeEx, typeof(Interop.KERB_CHECKSUM_InitializeEx));
            Interop.KERB_CHECKSUM_Sum pCheckSumSum = (Interop.KERB_CHECKSUM_Sum)Marshal.GetDelegateForFunctionPointer(pCheckSum.Sum, typeof(Interop.KERB_CHECKSUM_Sum));
            Interop.KERB_CHECKSUM_Finalize pCheckSumFinalize = (Interop.KERB_CHECKSUM_Finalize)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finalize, typeof(Interop.KERB_CHECKSUM_Finalize));
            Interop.KERB_CHECKSUM_Finish pCheckSumFinish = (Interop.KERB_CHECKSUM_Finish)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finish, typeof(Interop.KERB_CHECKSUM_Finish));

            // initialize the checksum
            // KERB_NON_KERB_CKSUM_SALT = 17
            int status2 = pCheckSumInitializeEx(key, key.Length, 17, out Context);
            if (status2 != 0)
                throw new Win32Exception(status2);

            // the output buffer for the checksum data
            byte[] checksumSrv = new byte[pCheckSum.Size];

            // actually checksum all the supplied data
            pCheckSumSum(Context, data.Length, data);

            // finish everything up
            pCheckSumFinalize(Context, checksumSrv);
            pCheckSumFinish(ref Context);

            return checksumSrv;
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosDecrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;
            
            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Decrypt pCSystemDecrypt = (Interop.KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(Interop.KERB_ECRYPT_Decrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemDecrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output;
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosEncrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Encrypt pCSystemEncrypt = (Interop.KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(Interop.KERB_ECRYPT_Encrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);

            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);

            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            // actually perform the decryption
            status = pCSystemEncrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);

            return output;
        }
    }
}
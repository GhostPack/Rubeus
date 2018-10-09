using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class S4u : ICommand
    {
        public static string CommandName => "s4u";

        public void Execute(Dictionary<string, string> arguments)
        {
            string targetUser = "";
            string targetSPN = "";
            string altSname = "";
            string user = "";
            string domain = "";
            string hash = "";
            bool ptt = false;
            string dc = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial; // throwaway placeholder, changed to something valid

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
            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
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
            if (arguments.ContainsKey("/impersonateuser"))
            {
                targetUser = arguments["/impersonateuser"];
            }

            if (arguments.ContainsKey("/msdsspn"))
            {
                targetSPN = arguments["/msdsspn"];
            }

            if (arguments.ContainsKey("/altservice"))
            {
                altSname = arguments["/altservice"];
            }

            if (String.IsNullOrEmpty(domain))
            {
                domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            if (String.IsNullOrEmpty(targetUser))
            {
                Console.WriteLine("\r\n[X] You must supply a /impersonateuser to impersonate!\r\n");
                return;
            }
            if (String.IsNullOrEmpty(targetSPN))
            {
                Console.WriteLine("\r\n[X] You must supply a /msdsspn !\r\n");
                return;
            }

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    S4U.Execute(kirbi, targetUser, targetSPN, ptt, dc, altSname);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    S4U.Execute(kirbi, targetUser, targetSPN, ptt, dc, altSname);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
                return;
            }
            else if (arguments.ContainsKey("/user"))
            {
                // if the user is supplying a user and rc4/aes256 hash to first execute a TGT request

                user = arguments["/user"];

                if (String.IsNullOrEmpty(hash))
                {
                    Console.WriteLine("\r\n[X] You must supply a /rc4 or /aes256 hash!\r\n");
                    return;
                }

                S4U.Execute(user, domain, hash, encType, targetUser, targetSPN, ptt, dc, altSname);
                return;
            }
            else
            {
                Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied for S4U!\r\n");
                Console.WriteLine("[X] Alternatively, supply a /user and </rc4:X | /aes256:X> hash to first retrieve a TGT.\r\n");
                return;
            }
        }
    }
}
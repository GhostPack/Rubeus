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
            string hash = "";
            string dc = "";
            bool ptt = false;
            uint luid = 0;
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;

            if (arguments.ContainsKey("/user"))
            {
                user = arguments["/user"];
            }
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
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
            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    luid = UInt32.Parse(arguments["/luid"]);
                }
                catch
                {
                    try
                    {
                        luid = Convert.ToUInt32(arguments["/luid"], 16);
                    }
                    catch
                    {
                        Console.WriteLine("[X] Invalid LUID format ({0})\r\n", arguments["/LUID"]);
                        return;
                    }
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
                Console.WriteLine("\r\n[X] You must supply a /rc4 or /aes256 hash!\r\n");
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
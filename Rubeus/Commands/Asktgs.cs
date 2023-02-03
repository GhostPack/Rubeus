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
            Interop.KERB_ETYPE requestEnctype = Interop.KERB_ETYPE.subkey_keymaterial;
            KRB_CRED tgs = null;
            string targetDomain = "";
            string servicekey = "";
            string asrepkey = "";
            bool u2u = false;
            string targetUser = "";
            bool printargs = false;
            bool keyList = false;
            string proxyUrl = null;

            if (arguments.ContainsKey("/keyList"))
            {
                keyList = true;
            }
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

            // for U2U requests
            if (arguments.ContainsKey("/u2u"))
            {
                u2u = true;
            }
            
            if (arguments.ContainsKey("/service"))
            {
                service = arguments["/service"];
            }
            else if (!u2u)
            {
                Console.WriteLine("[X] One or more '/service:sname/server.domain.com' specifications are needed");
                return;
            }

            if (arguments.ContainsKey("/servicekey")) {
                servicekey = arguments["/servicekey"];
            }

            if (u2u || !String.IsNullOrEmpty(servicekey))
            {
                // print command arguments for forging tickets
                if (arguments.ContainsKey("/printargs"))
                {
                    printargs = true;
                }
            }


            if (arguments.ContainsKey("/asrepkey")) {
                asrepkey = arguments["/asrepkey"];
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

            }

            // for manually specifying domain in requests
            if (arguments.ContainsKey("/targetdomain"))
            {
                targetDomain = arguments["/targetdomain"];
            }

            // for adding a PA-for-User PA data section
            if (arguments.ContainsKey("/targetuser"))
            {
                targetUser = arguments["/targetuser"];
            }

            // for using a KDC proxy
            if (arguments.ContainsKey("/proxyurl"))
            {
                proxyUrl = arguments["/proxyurl"];
            }

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    Ask.TGS(kirbi, service, requestEnctype, outfile, ptt, dc, true, enterprise, false, opsec, tgs, targetDomain, servicekey, asrepkey, u2u, targetUser, printargs, proxyUrl, keyList);
                    return;
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    Ask.TGS(kirbi, service, requestEnctype, outfile, ptt, dc, true, enterprise, false, opsec, tgs, targetDomain, servicekey, asrepkey, u2u, targetUser, printargs, proxyUrl, keyList);
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
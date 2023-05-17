using System;
using System.Collections.Generic;
using System.IO;
using Asn1;
using Rubeus.lib.Interop;


namespace Rubeus.Commands
{
    public class ASREP2Kirbi : ICommand
    {
        public static string CommandName => "asrep2kirbi";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: AS-REP to Kirbi");

            AsnElt asrep = null;
            byte[] key = null;
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1; //default if non /enctype is specified
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

            if (arguments.ContainsKey("/asrep"))
            {
                string buffer = arguments["/asrep"];

                if (Helpers.IsBase64String(buffer))
                {
                    byte[] bufferBytes = Convert.FromBase64String(buffer);

                    asrep = AsnElt.Decode(bufferBytes);
                }
                else if (File.Exists(buffer))
                {
                    byte[] bufferBytes = File.ReadAllBytes(buffer);
                    asrep = AsnElt.Decode(bufferBytes);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /asrep:X must either be a file or a base64 encoded AS-REP message\r\n");
                    return;
                }
            }
            else
            {
                Console.WriteLine("\r\n[X] A /asrep:X needs to be supplied!\r\n");
                return;
            }

            if (arguments.ContainsKey("/key"))
            {
                if (Helpers.IsBase64String(arguments["/key"]))
                {
                    key = Convert.FromBase64String(arguments["/key"]);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /key:X must be a base64 encoded client key\r\n");
                    //return;
                }
            }
            else if (arguments.ContainsKey("/keyhex"))
            {
                key = Helpers.StringToByteArray(arguments["/keyhex"]);
            }
            else
            {
                Console.WriteLine("\r\n[X]A /key:X or /keyhex:X must be supplied!");
                return;
            }

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

            Ask.HandleASREP(asrep, encType, Helpers.ByteArrayToString(key), outfile, ptt, luid, false, true);
        }
    }
}
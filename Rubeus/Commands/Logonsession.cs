using System;
using System.Collections.Generic;
using Rubeus.lib.Interop;

namespace Rubeus.Commands
{
    public class Logonsession : ICommand
    {
        public static string CommandName => "logonsession";

        public void Execute(Dictionary<string, string> arguments)
        {
            bool currentOnly = false;
            string targetLuidString = "";

            if (arguments.ContainsKey("/luid"))
            {
                targetLuidString = arguments["/luid"];
            }
            else if (arguments.ContainsKey("/current") || !Helpers.IsHighIntegrity())
            {
                currentOnly = true;
                Console.WriteLine("\r\n[*] Action: Display current logon session information\r\n");
            }
            else
            {
                Console.WriteLine("\r\n[*] Action: Display all logon session information\r\n");
            }

            List<LSA.LogonSessionData> logonSessions = new List<LSA.LogonSessionData>();

            if(!String.IsNullOrEmpty(targetLuidString))
            {
                try
                {
                    LUID targetLuid = new LUID(targetLuidString);
                    LSA.LogonSessionData logonData = LSA.GetLogonSessionData(targetLuid);
                    logonSessions.Add(logonData);
                }
                catch
                {
                    Console.WriteLine($"[!] Error parsing luid: {targetLuidString}");
                    return;
                }
            }
            else if (currentOnly)
            {
                // not elevated, so only enumerate current logon session information
                LUID currentLuid = Helpers.GetCurrentLUID();
                LSA.LogonSessionData logonData = LSA.GetLogonSessionData(currentLuid);
                logonSessions.Add(logonData);
            }
            else
            {
                // elevated, so enumerate all logon session information
                List<LUID> sessionLUIDs = LSA.EnumerateLogonSessions();

                foreach(LUID luid in sessionLUIDs)
                {
                    LSA.LogonSessionData logonData = LSA.GetLogonSessionData(luid);
                    logonSessions.Add(logonData);
                }
            }

            foreach(LSA.LogonSessionData logonData in logonSessions)
            {
                Console.WriteLine($"    LUID          : {logonData.LogonID} ({(UInt64)logonData.LogonID})");
                Console.WriteLine($"    UserName      : {logonData.Username}");
                Console.WriteLine($"    LogonDomain   : {logonData.LogonDomain}");
                Console.WriteLine($"    SID           : {logonData.Sid}");
                Console.WriteLine($"    AuthPackage   : {logonData.AuthenticationPackage}");
                Console.WriteLine($"    LogonType     : {logonData.LogonType} ({(int)logonData.LogonType})");
                Console.WriteLine($"    Session       : {logonData.Session}");
                Console.WriteLine($"    LogonTime     : {logonData.LogonTime}");
                Console.WriteLine($"    LogonServer   : {logonData.LogonServer}");
                Console.WriteLine($"    DnsDomainName : {logonData.DnsDomainName}");
                Console.WriteLine($"    Upn           : {logonData.Upn}\r\n");
            }
        }
    }
}

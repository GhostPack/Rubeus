using System;
using System.Collections.Generic;
using Rubeus.lib.Interop;

namespace Rubeus.Commands
{
    public class Currentlogonsession : ICommand
    {
        public static string CommandName => "currentlogonsession";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Display current logon session information\r\n");

            LUID currentLuid = Helpers.GetCurrentLUID();
            LSA.LogonSessionData logonData = LSA.GetLogonSessionData(currentLuid);

            Console.WriteLine($"    LUID          : {currentLuid} ({(UInt64)currentLuid})");
            Console.WriteLine($"    UserName      : {logonData.Username}");
            Console.WriteLine($"    LogonDomain   : {logonData.LogonDomain}");
            Console.WriteLine($"    AuthPackage   : {logonData.AuthenticationPackage}");
            Console.WriteLine($"    LogonType     : {logonData.LogonType} ({(int)logonData.LogonType})");
            Console.WriteLine($"    Session       : {logonData.Session}");
            Console.WriteLine($"    SID           : {logonData.Sid}");
            Console.WriteLine($"    LogonTime     : {logonData.LogonTime}");
            Console.WriteLine($"    LogonServer   : {logonData.LogonServer}");
            Console.WriteLine($"    DnsDomainName : {logonData.DnsDomainName}");
            Console.WriteLine($"    Upn           : {logonData.Upn}\r\n");
        }
    }
}

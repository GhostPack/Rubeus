using System;
using System.Collections.Generic;
using Rubeus.lib.Interop;


namespace Rubeus.Commands
{
    public class Currentluid : ICommand
    {
        public static string CommandName => "currentluid";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Display current LUID\r\n");

            LUID currentLuid = Helpers.GetCurrentLUID();
            Console.WriteLine("[*] Current LogonID (LUID) : {0} ({1})\r\n", currentLuid, (UInt64)currentLuid);
        }
    }
}

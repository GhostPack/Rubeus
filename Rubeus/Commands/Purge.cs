using System;
using System.Collections.Generic;
using Rubeus.lib.Interop;


namespace Rubeus.Commands
{
    public class Purge : ICommand
    {
        public static string CommandName => "purge";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Purge Tickets");

            LUID luid = new LUID();

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

            Console.WriteLine("Luid: {0}", luid);

            LSA.Purge(luid);
        }
    }
}
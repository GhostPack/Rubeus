using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Triage : ICommand
    {
        public static string CommandName => "triage";

        public void Execute(Dictionary<string, string> arguments)
        {
            Interop.LUID luid = new Interop.LUID();
            string user = "";
            string service = "";

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    luid = new Interop.LUID(arguments["/luid"]);
                }
                catch
                {
                    Console.WriteLine("[X] Invalid LUID format ({0})\r\n", arguments["/luid"]);
                    return;
                }
            }
            if (arguments.ContainsKey("/user"))
            {
                user = arguments["/user"];
            }
            if (arguments.ContainsKey("/service"))
            {
                service = arguments["/service"];
            }

            LSA.TriageKerberosTickets(luid, user, service);
        }
    }
}
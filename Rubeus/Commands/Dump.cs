using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Dump : ICommand
    {
        public static string CommandName => "dump";

        public void Execute(Dictionary<string, string> arguments)
        {
            if (arguments.ContainsKey("/luid"))
            {
                string service = "";
                if (arguments.ContainsKey("/service"))
                {
                    service = arguments["/service"];
                }

                Interop.LUID luid = new Interop.LUID();

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

                LSA.ListKerberosTicketData(luid, service);
            }
            else if (arguments.ContainsKey("/service"))
            {
                LSA.ListKerberosTicketData(new Interop.LUID(), arguments["/service"]);
            }
            else
            {
                LSA.ListKerberosTicketData(new Interop.LUID());
            }
        }
    }
}
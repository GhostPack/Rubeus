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
    }
}
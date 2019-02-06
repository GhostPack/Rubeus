using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Klist : ICommand
    {
        public static string CommandName => "klist";

        public void Execute(Dictionary<string, string> arguments)
        {
            if (arguments.ContainsKey("/luid"))
            {
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
                LSA.ListKerberosTickets(luid);
            }
            else
            {
                LSA.ListKerberosTickets();
            }
        }
    }
}
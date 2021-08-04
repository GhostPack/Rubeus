using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Createnetonly : ICommand
    {
        public static string CommandName => "createnetonly";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Create Process (/netonly)\r\n");

            if (arguments.ContainsKey("/program"))
            {
                if (arguments.ContainsKey("/show"))
                {
                    if (arguments.ContainsKey("/username"))
                    {
                        Helpers.CreateProcessNetOnly(arguments["/program"], true, arguments["/username"], arguments["/domain"], arguments["/password"]);
                    }
                    else
                    {
                        Helpers.CreateProcessNetOnly(arguments["/program"], true);
                    }
                }
                else
                {
                    if (arguments.ContainsKey("/username"))
                    {
                        Helpers.CreateProcessNetOnly(arguments["/program"], true, arguments["/username"], arguments["/domain"], arguments["/password"]);
                    }
                    else
                    {
                        Helpers.CreateProcessNetOnly(arguments["/program"]);
                    }
                }
            }

            else
            {
                Console.WriteLine("\r\n[X] A /program needs to be supplied!\r\n");
            }
        }
    }
}

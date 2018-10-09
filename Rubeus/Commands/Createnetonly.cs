using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Createnetonly : ICommand
    {
        public static string CommandName => "createnetonly";

        public void Execute(Dictionary<string, string> arguments)
        {
            if (arguments.ContainsKey("/program"))
            {
                if (arguments.ContainsKey("/show"))
                {
                    LSA.CreateProcessNetOnly(arguments["/program"], true);
                }
                else
                {
                    LSA.CreateProcessNetOnly(arguments["/program"]);
                }
            }

            else
            {
                Console.WriteLine("\r\n[X] A /program needs to be supplied!\r\n");
            }
        }
    }
}

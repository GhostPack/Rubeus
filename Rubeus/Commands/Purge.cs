using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Purge : ICommand
    {
        public static string CommandName => "purge";

        public void Execute(Dictionary<string, string> arguments)
        {

            uint luid = 0;
            if (arguments.ContainsKey("/luid"))
            {
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
            }

            LSA.Purge(luid);

        }
    }
}
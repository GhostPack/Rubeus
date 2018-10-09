using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Monitor : ICommand
    {
        public static string CommandName => "monitor";

        public void Execute(Dictionary<string, string> arguments)
        {
            string targetUser = "";
            int interval = 60;
            if (arguments.ContainsKey("/filteruser"))
            {
                targetUser = arguments["/filteruser"];
            }
            if (arguments.ContainsKey("/interval"))
            {
                interval = Int32.Parse(arguments["/interval"]);
            }
            Harvest.Monitor4624(interval, targetUser);
        }
    }
}
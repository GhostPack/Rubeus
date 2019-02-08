using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Monitor : ICommand
    {
        public static string CommandName => "monitor";

        public void Execute(Dictionary<string, string> arguments)
        {
            string targetUser = null;
            int interval = 60;
            string registryBasePath = null;
            if (arguments.ContainsKey("/filteruser"))
            {
                targetUser = arguments["/filteruser"];
            }
            if (arguments.ContainsKey("/interval"))
            {
                interval = Int32.Parse(arguments["/interval"]);
            }
            if (arguments.ContainsKey("/registry"))
            {
                registryBasePath = arguments["/registry"];
            }

            Harvest.Monitor4624(interval, targetUser, registryBasePath);
        }
    }
}
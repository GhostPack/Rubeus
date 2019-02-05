using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class HarvestCommand : ICommand
    {
        public static string CommandName => "harvest";

        public void Execute(Dictionary<string, string> arguments)
        {
            int intervalMinutes = 60;
            string registryBasePath = null;
            if (arguments.ContainsKey("/interval"))
            {
                intervalMinutes = Int32.Parse(arguments["/interval"]);
            }
            if (arguments.ContainsKey("/registry"))
            {
                registryBasePath = arguments["/registry"];
            }

            Harvest.HarvestTGTs(intervalMinutes, registryBasePath);
        }
    }
}

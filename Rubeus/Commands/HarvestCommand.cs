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
            if (arguments.ContainsKey("/interval"))
            {
                intervalMinutes = Int32.Parse(arguments["/interval"]);
            }

            Harvest.HarvestTGTs(intervalMinutes);
        }
    }
}

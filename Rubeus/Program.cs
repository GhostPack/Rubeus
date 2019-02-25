using Rubeus.Domain;
using System;

namespace Rubeus
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                Info.ShowLogo();

                // try to parse the command line arguments, show usage on failure and then bail
                var parsed = ArgumentParser.Parse(args);
                if (parsed.ParsedOk == false)
                    Info.ShowUsage();
                else
                {
                    // Try to execute the command using the arguments passed in

                    var commandName = args.Length != 0 ? args[0] : "";

                    var commandFound = new CommandCollection().ExecuteCommand(commandName, parsed.Arguments);

                    // show the usage if no commands were found for the command name
                    if (commandFound == false)
                        Info.ShowUsage();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled Rubeus exception:\r\n");
                Console.WriteLine(e);
            }
        }
    }
}

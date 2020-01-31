using Rubeus.Domain;
using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus
{
    public class Program
    {
        // global that specifies if ticket output should be wrapped or not
        public static bool wrapTickets = true;

        private static void FileExecute(string commandName, Dictionary<string, string> parsedArgs)
        {
            // execute w/ stdout/err redirected to a file

            string file = parsedArgs["/consoleoutfile"];

            TextWriter realStdOut = Console.Out;
            TextWriter realStdErr = Console.Error;

            using (StreamWriter writer = new StreamWriter(file, true))
            {
                writer.AutoFlush = true;
                Console.SetOut(writer);
                Console.SetError(writer);

                MainExecute(commandName, parsedArgs);

                Console.Out.Flush();
                Console.Error.Flush();
            }
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);
        }

        private static void MainExecute(string commandName, Dictionary<string,string> parsedArgs)
        {
            // main execution logic

            Info.ShowLogo();

            try
            {
                var commandFound = new CommandCollection().ExecuteCommand(commandName, parsedArgs);

                // show the usage if no commands were found for the command name
                if (commandFound == false)
                    Info.ShowUsage();
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled Rubeus exception:\r\n");
                Console.WriteLine(e);
            }
        }

        public static string MainString(string command)
        {
            // helper that executes an input string command and returns results as a string
            //  useful for PSRemoting execution

            string[] args = command.Split();

            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false)
            {
                Info.ShowLogo();
                Info.ShowUsage();
                return "Error parsing arguments: ${command}";
            }

            var commandName = args.Length != 0 ? args[0] : "";

            TextWriter realStdOut = Console.Out;
            TextWriter realStdErr = Console.Error;
            TextWriter stdOutWriter = new StringWriter();
            TextWriter stdErrWriter = new StringWriter();
            Console.SetOut(stdOutWriter);
            Console.SetError(stdErrWriter);

            MainExecute(commandName, parsed.Arguments);

            Console.Out.Flush();
            Console.Error.Flush();
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);

            string output = "";
            output += stdOutWriter.ToString();
            output += stdErrWriter.ToString();

            return output;
        }

        public static void Main(string[] args)
        {
            // try to parse the command line arguments, show usage on failure and then bail
            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false) {
                Info.ShowLogo();
                Info.ShowUsage();
                return;
            }

            var commandName = args.Length != 0 ? args[0] : "";

            if (parsed.Arguments.ContainsKey("/nowrap"))
            {
                wrapTickets = false;
            }

            if (parsed.Arguments.ContainsKey("/consoleoutfile")) {
                // redirect output to a file specified
                FileExecute(commandName, parsed.Arguments);
            }
            else
            {
                MainExecute(commandName, parsed.Arguments);
            }
        }
    }
}

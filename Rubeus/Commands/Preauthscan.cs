using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus.Commands
{
    public class Preauthscan : ICommand
    {
        public static string CommandName => "preauthscan";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Scan for accounts not requiring Kerberos Pre-Authentication\r\n");

            List<string> users = new List<string>();
            string domain = null;
            string dc = null;
            string proxyUrl = null;

            if (arguments.ContainsKey("/users"))
            {
                if (System.IO.File.Exists(arguments["/users"]))
                {
                    string fileContent = Encoding.UTF8.GetString(System.IO.File.ReadAllBytes(arguments["/users"]));
                    foreach (string u in fileContent.Split('\n'))
                    {
                        if (!String.IsNullOrWhiteSpace(u))
                        {
                            users.Add(u.Trim());
                        }
                    }
                }
                else
                {
                    foreach (string u in arguments["/users"].Split(','))
                    {
                        users.Add(u);
                    }
                }
            }

            if (users.Count < 1)
            {
                Console.WriteLine("[X] No usernames to try, exiting.");
                return;
            }

            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }

            if (String.IsNullOrEmpty(domain))
            {
                domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
            }

            if (arguments.ContainsKey("/proxyurl"))
            {
                proxyUrl = arguments["/proxyurl"];
            }

            Ask.PreAuthScan(users, domain, dc, proxyUrl);
        }
    }
}

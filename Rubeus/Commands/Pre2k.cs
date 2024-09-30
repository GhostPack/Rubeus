using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Rubeus.Commands
{
    public class Pre2k : ICommand
    {
        public static string CommandName => "pre2k";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Identify Pre2K machine accounts\r\n");

            List<string> computers = new List<string>();
            string outFile = "";
            string domain = "";
            string dc = "";
            string OU = "";
            string service = "HOST";
            string ldapFilter = "";
            KRB_CRED TGT = null;
            int resultLimit = 0;
            int delay = 0;
            int jitter = 0;
            bool ldaps = false;
            bool enterprise = false;
            bool randomspn = false;
            bool verbose = false;
            System.Net.NetworkCredential cred = null;

            if (arguments.ContainsKey("/computer"))
            {
                computers.Add(arguments["/computer"]);
            }
            if (arguments.ContainsKey("/computers"))
            {
                
                if (System.IO.File.Exists(arguments["/computers"]))
                {
                    string fileContent = Encoding.UTF8.GetString(System.IO.File.ReadAllBytes(arguments["/computers"]));
                    foreach (string s in fileContent.Split('\n'))
                    {
                        if (!String.IsNullOrEmpty(s))
                        {
                            computers.Add(s.Trim());
                        }
                    }
                }
                else
                {
                    foreach (string s in arguments["/computers"].Split(','))
                    {
                        computers.Add(s);
                    }
                }
            }
            if (arguments.ContainsKey("/domain"))
            {
                // roast users from a specific domain
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                // use a specific domain controller for kerberoasting
                dc = arguments["/dc"];
            }
            if (arguments.ContainsKey("/ou"))
            {
                // roast users from a specific OU
                OU = arguments["/ou"];
            }
            if (arguments.ContainsKey("/service"))
            {
                service = arguments["/service"];
            }
            if (arguments.ContainsKey("/outfile"))
            {
                // save output to a file
                outFile = arguments["/outfile"];
            }
            if (arguments.ContainsKey("/ticket"))
            {
                // use an existing TGT ticket when requesting/roasting
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    TGT = new KRB_CRED(kirbiBytes);
                }
                else if (System.IO.File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = System.IO.File.ReadAllBytes(kirbi64);
                    TGT = new KRB_CRED(kirbiBytes);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
            }
            if (arguments.ContainsKey("/ldapfilter"))
            {
                // additional LDAP targeting filter
                ldapFilter = arguments["/ldapfilter"].Trim('"').Trim('\'');
            }
            if (arguments.ContainsKey("/resultlimit"))
            {
                // limit the number of roastable users
                resultLimit = Convert.ToInt32(arguments["/resultlimit"]);
            }
            if (arguments.ContainsKey("/delay"))
            {
                delay = Int32.Parse(arguments["/delay"]);
                if (delay < 100)
                {
                    Console.WriteLine("[!] WARNING: delay is in milliseconds! Please enter a value > 100.");
                    return;
                }
            }
            if (arguments.ContainsKey("/jitter"))
            {
                try
                {
                    jitter = Int32.Parse(arguments["/jitter"]);
                }
                catch
                {
                    Console.WriteLine("[X] Jitter must be an integer between 1-100.");
                    return;
                }
                if (jitter <= 0 || jitter > 100)
                {
                    Console.WriteLine("[X] Jitter must be between 1-100");
                    return;
                }
            }
            if (arguments.ContainsKey("/ldaps"))
            {
                ldaps = true;
            }
            if (arguments.ContainsKey("/enterprise"))
            {
                enterprise = true;
            }
            if (arguments.ContainsKey("/randomspn"))
            {
                randomspn = true;
            }
            if (arguments.ContainsKey("/verbose"))
            {
                verbose = true;
            }
            if (String.IsNullOrEmpty(domain))
            {
                // try to get the current domain
                domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
            }
            if (arguments.ContainsKey("/creduser"))
            {
                // provide an alternate user to use for connection creds
                if (!Regex.IsMatch(arguments["/creduser"], ".+\\.+", RegexOptions.IgnoreCase))
                {
                    Console.WriteLine("\r\n[X] /creduser specification must be in fqdn format (domain.com\\user)\r\n");
                    return;
                }

                string[] parts = arguments["/creduser"].Split('\\');
                string domainName = parts[0];
                string userName = parts[1];

                // provide an alternate password to use for connection creds
                if (!arguments.ContainsKey("/credpassword"))
                {
                    Console.WriteLine("\r\n[X] /credpassword is required when specifying /creduser\r\n");
                    return;
                }

                string password = arguments["/credpassword"];

                cred = new System.Net.NetworkCredential(userName, password, domainName);
            }

            Roast.Pre2kRoast(computers, service, domain, dc, OU, cred, outFile, TGT, ldapFilter, resultLimit, delay, jitter, ldaps, enterprise, randomspn, verbose);
        }
    }
}

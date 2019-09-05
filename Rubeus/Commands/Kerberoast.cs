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
            string outFile = "";
            string domain = "";
            string dc = "";
            string supportedEType = "rc4";
            bool useTGTdeleg = false;
            KRB_CRED TGT = null;
            string pwdSetAfter = "";
            string pwdSetBefore = "";
            int resultLimit = 0;

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
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }
            if (arguments.ContainsKey("/outfile"))
            {
                outFile = arguments["/outfile"];
            }
            if (arguments.ContainsKey("/aes"))
            {
                supportedEType = "aes";
            }
            if (arguments.ContainsKey("/rc4opsec"))
            {
                supportedEType = "rc4opsec";
            }
            if (arguments.ContainsKey("/ticket"))
            {
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
                useTGTdeleg = true;
            }

            if (arguments.ContainsKey("/pwdsetafter"))
            {
                pwdSetAfter = arguments["/pwdsetafter"];
            }

            if (arguments.ContainsKey("/pwdsetbefore"))
            {
                pwdSetBefore = arguments["/pwdsetbefore"];
            }

            if (arguments.ContainsKey("/resultlimit"))
            {
                resultLimit = Convert.ToInt32(arguments["/resultlimit"]);
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

                Roast.Kerberoast(spn, user, OU, domain, dc, cred, outFile, TGT, useTGTdeleg, supportedEType, pwdSetAfter, pwdSetBefore, resultLimit);
            }
            else
            {
                Roast.Kerberoast(spn, user, OU, domain, dc, null, outFile, TGT, useTGTdeleg, supportedEType, pwdSetAfter, pwdSetBefore, resultLimit);
            }
        }
    }
}
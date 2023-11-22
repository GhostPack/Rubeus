using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class Createnetonly : ICommand
    {
        public static string CommandName => "createnetonly";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Create Process (/netonly)\r\n");

            string program = null;
            string username = null;
            string password = null;
            string domain = null;
            byte[] kirbiBytes = null;
            bool show = arguments.ContainsKey("/show");

            if (arguments.ContainsKey("/program") && !String.IsNullOrWhiteSpace(arguments["/program"]))
            {
                program = arguments["/program"];
            }
            else
            {
                Console.WriteLine("\r\n[X] A /program needs to be supplied!\r\n");
                return;
            }

            if (arguments.ContainsKey("/username"))
            {
                username = arguments["/username"];
            }
            if (arguments.ContainsKey("/password"))
            {
                password = arguments["/password"];
            }
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    kirbiBytes = Convert.FromBase64String(kirbi64);
                }
                else if (File.Exists(kirbi64))
                {
                    kirbiBytes = File.ReadAllBytes(kirbi64);
                }
                else
                {
                    Console.WriteLine("\r\n[X]/ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                    return;
                }
            }

            if (username == null && password == null && domain == null)
            {
                Console.WriteLine("\r\n[*] Using random username and password.\r\n");
                Helpers.CreateProcessNetOnly(program, show, username, domain, password, kirbiBytes);
                return;
            }

            if (!String.IsNullOrWhiteSpace(username) && !String.IsNullOrWhiteSpace(password) && !String.IsNullOrWhiteSpace(domain))
            {
                Console.WriteLine("\r\n[*] Using " + domain + "\\" + username + ":" + password + "\r\n");
                Helpers.CreateProcessNetOnly(program, show, username, domain, password, kirbiBytes);
                return;
            }

            Console.WriteLine("\r\n[X] Explicit creds require /username, /password, and /domain to be supplied!\r\n");
        }
    }
}

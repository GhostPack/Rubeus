using System;
using System.ComponentModel;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace Rubeus
{
    public class Networking
    {
        public static string GetDCName(string domainName = "")
        {
            // retrieves the current domain controller name

            // adapted from https://www.pinvoke.net/default.aspx/netapi32.dsgetdcname
            Interop.DOMAIN_CONTROLLER_INFO domainInfo;
            const int ERROR_SUCCESS = 0;
            IntPtr pDCI = IntPtr.Zero;

            int val = Interop.DsGetDcName("", domainName, 0, "",
                Interop.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED |
                Interop.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                Interop.DSGETDCNAME_FLAGS.DS_IP_REQUIRED, out pDCI);

            if (ERROR_SUCCESS == val) {
                domainInfo = (Interop.DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(pDCI, typeof(Interop.DOMAIN_CONTROLLER_INFO));
                string dcName = domainInfo.DomainControllerName;
                Interop.NetApiBufferFree(pDCI);
                return dcName.Trim('\\');
            }
            else {
                try {
                    string pdc = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().PdcRoleOwner.Name;
                    return pdc;
                }
                catch {
                    string errorMessage = new Win32Exception((int)val).Message;
                    Console.WriteLine("\r\n [X] Error {0} retrieving domain controller : {1}", val, errorMessage);
                    Interop.NetApiBufferFree(pDCI);
                    return "";
                }
            }
        }

        public static string GetDCIP(string DCName, bool display = true, string domainName = "")
        {
            if (String.IsNullOrEmpty(DCName))
            {
                DCName = GetDCName(domainName);
            }
            Match match = Regex.Match(DCName, @"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(\d{1,3}\.){3}\d{1,3}");
            if (match.Success)
            {
                if (display)
                {
                    Console.WriteLine("[*] Using domain controller: {0}", DCName);
                }
                return DCName;
            }
            else
            {
                try
                {
                    // If we call GetHostAddresses with an empty string, it will return IP addresses for localhost instead of DC
                    if (String.IsNullOrEmpty(DCName)) 
                    {
                        Console.WriteLine("[X] Error: No domain controller could be located");
                        return null;
                    }
                    System.Net.IPAddress[] dcIPs = System.Net.Dns.GetHostAddresses(DCName);

                    foreach (System.Net.IPAddress dcIP in dcIPs)
                    {
                        if (dcIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork || dcIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            if (display)
                            {
                                Console.WriteLine("[*] Using domain controller: {0} ({1})", DCName, dcIP);
                            }
                            return String.Format("{0}", dcIP);
                        }
                    }
                    Console.WriteLine("[X] Error resolving hostname '{0}' to an IP address: no IPv4 or IPv6 address found", DCName);
                    return null;
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] Error resolving hostname '{0}' to an IP address: {1}", DCName, e.Message);
                    return null;
                }
            }
        }

        public static byte[] SendBytes(string server, int port, byte[] data, bool noHeader = false)
        {
            // send the byte array to the specified server/port

            System.Net.IPAddress address;
            try
            {
                address = System.Net.IPAddress.Parse(server);
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error parsing IP address {0} : {1}", server, e.Message);
                return null;
            }

            System.Net.Sockets.AddressFamily addressFamily = System.Net.Sockets.AddressFamily.InterNetwork;

            if (address.AddressFamily.ToString() == System.Net.Sockets.ProtocolFamily.InterNetworkV6.ToString()) 
            {
                addressFamily = System.Net.Sockets.AddressFamily.InterNetworkV6;
            }

            // Console.WriteLine("[*] Connecting to {0}:{1}", server, port);
            System.Net.IPEndPoint endPoint = new System.Net.IPEndPoint(address, port);

            System.Net.Sockets.Socket socket = new System.Net.Sockets.Socket(addressFamily, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
            socket.Ttl = 128;
            byte[] totalRequestBytes;

            if (noHeader)
            {
                // used for MS Kpasswd
                totalRequestBytes = data;
            }
            else
            {
                byte[] lenBytes = BitConverter.GetBytes(data.Length);
                Array.Reverse(lenBytes);

                // build byte[req len + req bytes]
                totalRequestBytes = new byte[lenBytes.Length + data.Length];
                Array.Copy(lenBytes, totalRequestBytes, lenBytes.Length);
                Array.Copy(data, 0, totalRequestBytes, lenBytes.Length, data.Length);
            }

            try
            {
                // connect to the server over The specified port
                socket.Connect(endPoint);
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error connecting to {0}:{1} : {2}", server, port, e.Message);
                return null;
            }

            // actually send the bytes
            int bytesSent = socket.Send(totalRequestBytes);

            System.Collections.Generic.List<byte> responseList = new System.Collections.Generic.List<byte>();
            byte[] responseBuffer = new byte[256];
            int totalBytesReceived = 0;
            int bytesReceived = 0;

            // warp the receive to catch SocketExceptions for the edge case where the server is done sending data but the break statement wasn't hit
            // return null for other exceptions.
            try
            {
                while ((bytesReceived = socket.Receive(responseBuffer)) > 0)
                {
                    totalBytesReceived += bytesReceived;
                    //Console.WriteLine("[*] Bytes Received: {0}\n[*] Total Bytes Received: {1}", bytesReceived, totalBytesReceived);
                    responseList.AddRange(responseBuffer);

                    // break loop if the socket returns less than the buffer, we can assume the domain controller is done sending data.
                    // potential edge case if domain controller sends exactly 256 bytes as its last packet, handled by the try catch statement.
                    if (bytesReceived < 256)
                    {
                        break;
                    }
                }
            }
            catch (System.Net.Sockets.SocketException e)
            {
                Console.WriteLine("[*] No more data available. Assuming Domain Controller {0}:{1} is finished sending data: {2}", server, port, e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error Receiving from Domain Controller {0}:{1} \n {2}", server, port, e.Message);
                return null;
            }


            byte[] response;
            if (noHeader)
            {
                response = responseList.ToArray();
            }
            else
            {
                response = new byte[totalBytesReceived - 4];
                Array.Copy(responseList.ToArray(), 4, response, 0, totalBytesReceived - 4);
            }

            socket.Close();

            return response;
        }

        public static DirectoryEntry GetLdapSearchRoot(System.Net.NetworkCredential cred, string OUName, string domainController, string domain)
        {
            DirectoryEntry directoryObject = null;
            string ldapPrefix = "";
            string ldapOu = "";

            //If we have a DC then use that instead of the domain name so that this works if user doesn't have
            //name resolution working but specified the IP of a DC
            if (!String.IsNullOrEmpty(domainController))
            {
                ldapPrefix = domainController;
            }
            else if (!String.IsNullOrEmpty(domain)) //If we don't have a DC then use the domain name (if we have one)
            {
                ldapPrefix = domain;
            }
            else if (cred != null) //If we don't have a DC or a domain name but have credentials, get domain name from them
            {
                ldapPrefix = cred.Domain;
            }

            if (!String.IsNullOrEmpty(OUName))
            {
                ldapOu = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                ldapOu = String.Format("DC={0}", domain.Replace(".", ",DC="));
            }

            //If no DC, domain, credentials, or OU were specified
            if (String.IsNullOrEmpty(ldapPrefix) && String.IsNullOrEmpty(ldapOu))
            {
                directoryObject = new DirectoryEntry();
            }
            else //If we have a prefix (DC or domain), an OU path, or both
            {
                string bindPath = "";
                if (!String.IsNullOrEmpty(ldapPrefix))
                {
                    bindPath = String.Format("LDAP://{0}", ldapPrefix);
                }
                if (!String.IsNullOrEmpty(ldapOu))
                {
                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        bindPath = String.Format("{0}/{1}", bindPath, ldapOu);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{1]", ldapOu);
                    }
                }

                directoryObject = new DirectoryEntry(bindPath);
            }
            
            if (cred != null)
            {
                // if we're using alternate credentials for the connection
                string userDomain = String.Format("{0}\\{1}", cred.Domain, cred.UserName);
                directoryObject.Username = userDomain;
                directoryObject.Password = cred.Password;
             
                // Removed credential validation check because it just caused problems and doesn't gain us anything (if invalid
                // credentials are specified, the LDAP search will fail with "Logon failure: bad username or password" anyway)

                //string contextTarget = "";
                //if (!string.IsNullOrEmpty(domainController))
                //{
                //    contextTarget = domainController;
                //}
                //else
                //{
                //    contextTarget = cred.Domain;
                //}

                //using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, contextTarget))
                //{
                //    if (!pc.ValidateCredentials(cred.UserName, cred.Password))
                //    {
                //        throw new Exception(String.Format("\r\n[X] Credentials supplied for '{0}' are invalid!", userDomain));
                //    }
                //    else
                //    {
                //        Console.WriteLine("[*] Using alternate creds  : {0}", userDomain);
                //    }
                //}
            }
            return directoryObject;
        }



    }
}


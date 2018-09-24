using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class EncKDCRepPart
    {
        //EncKDCRepPart::= SEQUENCE {
        //        key[0] EncryptionKey,
        //        last-req[1] LastReq,
        //        nonce[2] UInt32,
        //        key-expiration[3] KerberosTime OPTIONAL,
        //        flags[4] TicketFlags,
        //        authtime[5] KerberosTime,
        //        starttime[6] KerberosTime OPTIONAL,
        //        endtime[7] KerberosTime,
        //        renew-till[8] KerberosTime OPTIONAL,
        //        srealm[9] Realm,
        //        sname[10] PrincipalName,
        //        caddr[11] HostAddresses OPTIONAL,
        //  encrypted-pa-data[12] SEQUENCE OF PA-DATA OPTIONAL
        //}

        public EncKDCRepPart(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        key = new EncryptionKey(s);
                        break;
                    case 1:
                        lastReq = new LastReq(s.Sub[0]);
                        break;
                    case 2:
                        nonce = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 3:
                        key_expiration = s.Sub[0].GetTime();
                        break;
                    case 4:
                        UInt32 temp = Convert.ToUInt32(s.Sub[0].GetInteger());
                        byte[] tempBytes = BitConverter.GetBytes(temp);
                        flags = (Interop.TicketFlags)BitConverter.ToInt32(tempBytes, 0);
                        break;
                    case 5:
                        authtime = s.Sub[0].GetTime();
                        break;
                    case 6:
                        starttime = s.Sub[0].GetTime();
                        break;
                    case 7:
                        endtime = s.Sub[0].GetTime();
                        break;
                    case 8:
                        renew_till = s.Sub[0].GetTime();
                        break;
                    case 9:
                        realm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 10:
                        // sname (optional)
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    case 11:
                        // HostAddresses, skipped for now
                        break;
                    case 12:
                        // encrypted-pa-data, skipped for now
                        break;
                    default:
                        break;
                }
            }
        }

        // won't really every need to *create* a KDC reply, so no Encode()

        public EncryptionKey key { get; set; }

        public LastReq lastReq { get; set; }

        public UInt32 nonce { get; set; }

        public DateTime key_expiration { get; set; }

        public Interop.TicketFlags flags { get; set; }

        public DateTime authtime { get; set; }

        public DateTime starttime { get; set; }

        public DateTime endtime { get; set; }

        public DateTime renew_till { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        // caddr (optional) - skip for now
        
        // encrypted-pa-data (optional) - skip for now
    }
}
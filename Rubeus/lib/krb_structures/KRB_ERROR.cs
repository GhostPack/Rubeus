using System;
using Asn1;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    public class KRB_ERROR
    {
        //KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
        //        pvno            [0] INTEGER (5),
        //        msg-type        [1] INTEGER (30),
        //        ctime           [2] KerberosTime OPTIONAL,
        //        cusec           [3] Microseconds OPTIONAL,
        //        stime           [4] KerberosTime,
        //        susec           [5] Microseconds,
        //        error-code      [6] Int32,
        //        crealm          [7] Realm OPTIONAL,
        //        cname           [8] PrincipalName OPTIONAL,
        //        realm           [9] Realm -- service realm --,
        //        sname           [10] PrincipalName -- service name --,
        //        e-text          [11] KerberosString OPTIONAL,
        //        e-data          [12] OCTET STRING OPTIONAL
        //}

        public KRB_ERROR(byte[] errorBytes)
        {
            
        }

        public KRB_ERROR(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        pvno = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        msg_type = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        ctime = s.Sub[0].GetTime();
                        break;
                    case 3:
                        cusec = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 4:
                        stime = s.Sub[0].GetTime();
                        break;
                    case 5:
                        susec = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 6:
                        error_code = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 7:
                        crealm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 8:
                        cname = new PrincipalName(s.Sub[0]);
                        break;
                    case 9:
                        realm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 10:
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    default:
                        break;
                }
            }
        }

        // don't ever really need to create a KRB_ERROR structure manually, so no Encode()

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public DateTime ctime { get; set; }

        public long cusec { get; set; }

        public DateTime stime { get; set; }

        public long susec { get; set; }

        public long error_code { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        // skipping these two for now
        // e_text
        // e_data


        //public Ticket[] tickets { get; set; }
        public List<Ticket> tickets { get; set; }

        public EncKrbCredPart enc_part { get; set; }
    }
}
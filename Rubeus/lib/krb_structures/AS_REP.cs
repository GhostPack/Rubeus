using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    public class AS_REP
    {
        //AS-REP          ::= [APPLICATION 11] KDC-REP

        //KDC-REP         ::= SEQUENCE {
        //        pvno            [0] INTEGER (5),
        //        msg-type        [1] INTEGER (11 -- AS),
        //        padata          [2] SEQUENCE OF PA-DATA OPTIONAL
        //                                -- NOTE: not empty --,
        //        crealm          [3] Realm,
        //        cname           [4] PrincipalName,
        //        ticket          [5] Ticket,
        //        enc-part        [6] EncryptedData
        //                                -- EncASRepPart
        //}

        public AS_REP(byte[] data)
        {
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt asn_AS_REP = AsnElt.Decode(data, false);

            this.Decode(asn_AS_REP);
        }

        public AS_REP(AsnElt asn_AS_REP)
        {
            this.Decode(asn_AS_REP);
        }

        private void Decode(AsnElt asn_AS_REP)
        {
            // AS-REP::= [APPLICATION 11] KDC-REQ
            if (asn_AS_REP.TagValue != (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                throw new System.Exception("AS-REP tag value should be 11");
            }

            if ((asn_AS_REP.Sub.Length != 1) || (asn_AS_REP.Sub[0].TagValue != 16))
            {
                throw new System.Exception("First AS-REP sub should be a sequence");
            }

            // extract the KDC-REP out
            AsnElt[] kdc_rep = asn_AS_REP.Sub[0].Sub;
            padata = new List<PA_DATA>();

            foreach (AsnElt s in kdc_rep)
            {
                switch (s.TagValue)
                {
                    case 0:
                        pvno = s.Sub[0].GetInteger();
                        break;
                    case 1:
                        msg_type = s.Sub[0].GetInteger();
                        break;
                    case 2:
                        // sequence of pa-data
                        foreach(AsnElt pad in s.Sub) {
                            padata.Add(new PA_DATA(pad.Sub[0]));
                        }                                                   
                        break;
                    case 3:
                        crealm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 4:
                        cname = new PrincipalName(s.Sub[0]);
                        break;
                    case 5:
                        ticket = new Ticket(s.Sub[0].Sub[0]);
                        break;
                    case 6:
                        enc_part = new EncryptedData(s.Sub[0]);
                        break;
                    default:
                        break;
                }
            }
        }

        // won't really every need to *create* a AS reply, so no encode

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public List<PA_DATA> padata { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public Ticket ticket { get; set; }

        public EncryptedData enc_part { get; set; }
    }
}

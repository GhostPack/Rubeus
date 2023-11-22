using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Asn1;

namespace Rubeus
{
    public class ETYPE_INFO2_ENTRY
    {
        /*
        ETYPE-INFO2-ENTRY::= SEQUENCE {
        etype [0] Int32 -- EncryptionType --,
        salt [1] KerberosString OPTIONAL,
        s2kparams [2] INTEGER OPTIONAL
        }
        */

        public ETYPE_INFO2_ENTRY(AsnElt body)
        {
            foreach (AsnElt s in body.Sub[0].Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        etype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        salt = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    default:
                        break;
                }
            }
        }

        public Int32 etype { get; set; }

        public string salt { get; set; }

        // skip sk2params for now
    }
}

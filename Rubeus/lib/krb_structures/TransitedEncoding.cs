using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class TransitedEncoding
    {
        //TransitedEncoding       ::= SEQUENCE {
        //  tr-type[0] Int32 -- must be registered --,
        //  contents[1] OCTET STRING
        //}
        public TransitedEncoding()
        {
            tr_type = Interop.TransitedEncodingType.NULL;
            contents = new byte[0];
        }

        public TransitedEncoding(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        tr_type = (Interop.TransitedEncodingType)s.Sub[0].GetInteger();
                        break;
                    case 1:
                        // just decode for now
                        contents = s.Sub[0].GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // tr-type            [0] Int32
            AsnElt trTypeElt = AsnElt.MakeInteger((long)tr_type);
            AsnElt trTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { trTypeElt });
            trTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, trTypeSeq);

            AsnElt seq;

            // contents            [1] OCTET STRING
            if (contents != null)
            {
                AsnElt contentsElt = AsnElt.MakeBlob(contents);
                AsnElt contentsSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { contentsElt });
                contentsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, contentsSeq);
                seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { trTypeSeq, contentsSeq });
            }
            else
            {
                seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { trTypeSeq });
            }

            seq = AsnElt.Make(AsnElt.SEQUENCE, seq);

            return seq;
        }

        public Interop.TransitedEncodingType tr_type { get; set; }

        public byte[] contents { get; set; }
    }
}

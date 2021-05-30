using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    //AuthorizationData       ::= SEQUENCE OF SEQUENCE {
    //          ad-type[0] Int32,
    //          ad-data[1] OCTET STRING
    //}

    public abstract class AuthorizationData
    {
        public AuthorizationData() { }

        public AuthorizationData(Interop.AuthorizationDataType adtype) : this(adtype, null) 
        {
        }

        public AuthorizationData(Interop.AuthorizationDataType adtype, byte[] data)
        {

            ad_type = adtype;
            ad_data = data;
        }

        public AsnElt ADEncode()
        {
            // ad-type            [0] Int32
            AsnElt adTypeElt = AsnElt.MakeInteger((long)ad_type);
            AsnElt adTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adTypeElt });
            adTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, adTypeSeq);

            // ad-data            [1] OCTET STRING
            AsnElt adDataElt = AsnElt.MakeBlob(ad_data);
            AsnElt adDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adDataElt });
            adDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, adDataSeq);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { adTypeSeq, adDataSeq });

            return seq;
        }

        public abstract AsnElt Encode();

        protected abstract void Decode(AsnElt data);

        protected abstract void Decode(AsnElt data, byte[] asrepKey = null);

        public Interop.AuthorizationDataType ad_type { get; set; }

        public byte[] ad_data { get; set; }
    }
}

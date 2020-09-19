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

    public class AuthorizationData
    {
        public AuthorizationData()
        {

            ad_type = Interop.AuthorizationDataType.AD_IF_RELEVANT;

            ad_data = null;
        }

        public AuthorizationData(AuthorizationData data)
        {

            ad_type = Interop.AuthorizationDataType.AD_IF_RELEVANT;

            List<AuthorizationData> tmp = new List<AuthorizationData>();
            tmp.Add(data);
            ad_data = tmp;
        }

        public AuthorizationData(List<AuthorizationData> auths)
        {

            ad_type = Interop.AuthorizationDataType.AD_IF_RELEVANT;

            ad_data = auths;
        }

        public AuthorizationData(Interop.AuthorizationDataType adtype)
        {

            ad_type = adtype;

            if (adtype == Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS)
                ad_data = new KERB_AD_RESTRICTION_ENTRY();
            else if (adtype == Interop.AuthorizationDataType.KERB_LOCAL)
            {
                // random KERB-LOCAL for now
                var rand = new Random();
                byte[] randomBytes = new byte[16];
                rand.NextBytes(randomBytes);
                ad_data = randomBytes;
            }
        }

        public AsnElt Encode()
        {
            // ad-type            [0] Int32
            AsnElt adTypeElt = AsnElt.MakeInteger((long)ad_type);
            AsnElt adTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adTypeElt });
            adTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, adTypeSeq);

            // ad-data            [1] OCTET STRING
            if (ad_type == Interop.AuthorizationDataType.AD_IF_RELEVANT)
            {
                if (ad_data != null)
                {
                    List<AsnElt> adList = new List<AsnElt>();
                    foreach (AuthorizationData ad in (List<AuthorizationData>)ad_data)
                    {
                        AsnElt addrElt = ad.Encode();
                        adList.Add(addrElt);
                    }
                    AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, adList.ToArray());
                    AsnElt finalData = AsnElt.MakeBlob(seq.Encode());
                    AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { finalData });
                    seq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, seq2);

                    seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { adTypeSeq, seq2 });
                    seq2 = AsnElt.Make(AsnElt.SEQUENCE, seq2);

                    return seq2;
                }
                else
                {
                    return null;
                }
            }
            else if (ad_type == Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS)
            {
                AsnElt adDataElt = AsnElt.MakeBlob(((KERB_AD_RESTRICTION_ENTRY)ad_data).Encode().Encode());
                AsnElt adDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adDataElt });
                adDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, adDataSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { adTypeSeq, adDataSeq });
                return seq;
            }
            else if (ad_type == Interop.AuthorizationDataType.KERB_LOCAL)
            {
                AsnElt adDataElt = AsnElt.MakeBlob((byte[])ad_data);
                AsnElt adDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adDataElt });
                adDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, adDataSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { adTypeSeq, adDataSeq });
                return seq;
            }
            else
            {
                return null;
            }
        }


        public Interop.AuthorizationDataType ad_type { get; set; }

        public Object ad_data { get; set; }
    }
}

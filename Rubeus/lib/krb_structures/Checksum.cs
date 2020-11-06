using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class Checksum
    {
        //Checksum        ::= SEQUENCE {
        //        cksumtype       [0] Int32,
        //        checksum        [1] OCTET STRING
        //}

        public Checksum(byte[] data)
        {
            // KERB_CHECKSUM_HMAC_MD5 = -138
            cksumtype = -138;

            checksum = data;
        }

        public Checksum(Interop.KERB_CHECKSUM_ALGORITHM cktype, byte[] data)
        {
            cksumtype = (int)cktype;

            checksum = data;
        }

        public Checksum(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        cksumtype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        checksum = s.Sub[0].GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // cksumtype       [0] Int32
            AsnElt cksumtypeAsn = AsnElt.MakeInteger(cksumtype);
            AsnElt cksumtypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { cksumtypeAsn });
            cksumtypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, cksumtypeSeq);


            // checksum        [1] OCTET STRING
            AsnElt checksumAsn = AsnElt.MakeBlob(checksum);
            AsnElt checksumSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { checksumAsn });
            checksumSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, checksumSeq);


            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { cksumtypeSeq, checksumSeq });
            AsnElt totalSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { totalSeq });
            return totalSeq2;
        }

        public Int32 cksumtype { get; set; }

        public byte[] checksum { get; set; }
    }
}
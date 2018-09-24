using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class EncryptedData
    {
        //EncryptedData::= SEQUENCE {
        //    etype[0] Int32 -- EncryptionType --,
        //    kvno[1] UInt32 OPTIONAL,
        //    cipher[2] OCTET STRING -- ciphertext
        //}

        public EncryptedData()
        {

        }

        public EncryptedData(Int32 encType, byte[] data)
        {
            etype = encType;
            cipher = data;
        }

        public EncryptedData(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        etype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        kvno = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        cipher = s.Sub[0].GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // etype   [0] Int32 -- EncryptionType --,
            AsnElt etypeAsn = AsnElt.MakeInteger(etype);
            AsnElt etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { etypeAsn });
            etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, etypeSeq);


            // cipher  [2] OCTET STRING -- ciphertext
            AsnElt cipherAsn = AsnElt.MakeBlob(cipher);
            AsnElt cipherSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { cipherAsn });
            cipherSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, cipherSeq);


            if (kvno != 0)
            {
                // kvno    [1] UInt32 OPTIONAL
                AsnElt kvnoAsn = AsnElt.MakeInteger(kvno);
                AsnElt kvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { kvnoAsn });
                kvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, kvnoSeq);

                AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { etypeSeq, kvnoSeq, cipherSeq });
                return totalSeq;
            }
            else
            {
                AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { etypeSeq, cipherSeq });
                return totalSeq;
            }
        }

        public Int32 etype { get; set; }

        public UInt32 kvno { get; set; }

        public byte[] cipher { get; set; }
    }
}
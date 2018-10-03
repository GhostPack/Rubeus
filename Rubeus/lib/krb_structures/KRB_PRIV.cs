using System;
using Asn1;
using System.Collections.Generic;

namespace Rubeus
{
    public class KRB_PRIV
    {
        //KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
        //        pvno            [0] INTEGER (5),
        //        msg-type        [1] INTEGER (21),
        //                        -- NOTE: there is no [2] tag
        //        enc-part        [3] EncryptedData -- EncKrbPrivPart
        //}

        public KRB_PRIV(Interop.KERB_ETYPE encType, byte[] encKey)
        {
            // defaults for creation
            pvno = 5;
            msg_type = 21;

            etype = encType;

            ekey = encKey;

            enc_part = new EncKrbPrivPart();
        }

        public AsnElt Encode()
        {
            // pvno            [0] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, pvnoSeq);


            // msg-type        [1] INTEGER (21)
            AsnElt msg_typeAsn = AsnElt.MakeInteger(msg_type);
            AsnElt msg_typeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { msg_typeAsn });
            msg_typeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, msg_typeSeq);

            // enc-part        [3] EncryptedData -- EncKrbPrivPart
            AsnElt enc_partAsn = enc_part.Encode();

            // etype
            AsnElt etypeAsn = AsnElt.MakeInteger((int)etype);
            AsnElt etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { etypeAsn });
            etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, etypeSeq);

            // now encrypt the enc_part (EncKrbPrivPart)
            //  KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART = 13;
            byte[] encBytes = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART, ekey, enc_partAsn.Encode());
            AsnElt blob = AsnElt.MakeBlob(encBytes);
            AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });
            blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

            AsnElt encPrivSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { etypeSeq, blobSeq });
            AsnElt encPrivSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { encPrivSeq });
            encPrivSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, encPrivSeq2);


            // all the components
            AsnElt total = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { pvnoSeq, msg_typeSeq, encPrivSeq2 });

            // tag the final total ([APPLICATION 21])
            AsnElt final = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { total });
            final = AsnElt.MakeImplicit(AsnElt.APPLICATION, 21, final);

            return final;
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public EncKrbPrivPart enc_part { get; set; }

        public Interop.KERB_ETYPE etype { get; set; }

        public byte[] ekey { get; set; }
    }
}
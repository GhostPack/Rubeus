using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    // PA-S4U-X509-USER::= SEQUENCE {
    //    user-id[0] S4UUserID,
    //    checksum[1] Checksum
    //}

    
    public class PA_S4U_X509_USER
    {
        public PA_S4U_X509_USER(byte[] key, string name, string realm, uint nonce)
        {
            user_id = new S4UUserID(name, realm, nonce);

            AsnElt userIDAsn = user_id.Encode();
            AsnElt userIDSeq = AsnElt.Make(AsnElt.SEQUENCE, userIDAsn);
            //userIDSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, userIDSeq);
            byte[] userIDBytes = userIDSeq.CopyValue();


            byte[] cksumBytes = Crypto.KerberosChecksum(key, userIDBytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256_X509);
            cksum = new Checksum(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256, cksumBytes);
        }

        public AsnElt Encode()
        {
            AsnElt userIDAsn = user_id.Encode();
            AsnElt userIDSeq = AsnElt.Make(AsnElt.SEQUENCE, userIDAsn);
            userIDSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, userIDSeq);

            AsnElt checksumAsn = cksum.Encode();
            checksumAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, checksumAsn);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { userIDSeq, checksumAsn });

            return seq;
        }

        public S4UUserID user_id { get; set; }
        public Checksum cksum { get; set; }
    }
}

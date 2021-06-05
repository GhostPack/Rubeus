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
        public PA_S4U_X509_USER(byte[] key, string name, string realm, uint nonce, Interop.KERB_ETYPE eType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
        {
            user_id = new S4UUserID(name, realm, nonce);

            AsnElt userIDAsn = user_id.Encode();
            AsnElt userIDSeq = AsnElt.Make(AsnElt.SEQUENCE, userIDAsn);
            byte[] userIDBytes = userIDSeq.CopyValue();
            byte[] cksumBytes = null;

            if (eType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
                cksumBytes = Crypto.KerberosChecksum(key, userIDBytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256, Interop.KRB_KEY_USAGE_PA_S4U_X509_USER);
            if (eType == Interop.KERB_ETYPE.aes128_cts_hmac_sha1)
                cksumBytes = Crypto.KerberosChecksum(key, userIDBytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128, Interop.KRB_KEY_USAGE_PA_S4U_X509_USER);
            if (eType == Interop.KERB_ETYPE.rc4_hmac)
                cksumBytes = Crypto.KerberosChecksum(key, userIDBytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_RSA_MD4, Interop.KRB_KEY_USAGE_PA_S4U_X509_USER);

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

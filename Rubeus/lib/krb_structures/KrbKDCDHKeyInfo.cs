using Asn1;
using System;

namespace Rubeus {

    public class KrbKDCDHKeyInfo {

        public byte[] SubjectPublicKey { get; private set; }
        public long Nonce { get; private set; }
        public DateTime DHKeyExpiration { get; private set; }
        public KrbKDCDHKeyInfo(AsnElt asnElt) {

            if(asnElt.TagValue != AsnElt.SEQUENCE) {
                throw new ArgumentException("Unexpected tag type for KDCDHKeyInfo");
            }

            foreach(AsnElt sub in asnElt.Sub) {
                switch (sub.TagValue){
                    case 0:     //subjectPublicKey
                        SubjectPublicKey = AsnElt.Decode(sub.Sub[0].GetBitString()).GetOctetString();              
                        break;
                    case 1:     //nonce
                        Nonce = sub.Sub[0].GetInteger(0, uint.MaxValue);
                        break;
                    case 2:     //dhKeyExpiration
                        DHKeyExpiration = sub.Sub[0].GetTime();
                        break;
                }
            }
        }
    }
}

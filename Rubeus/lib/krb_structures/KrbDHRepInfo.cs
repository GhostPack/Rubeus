using Asn1;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Rubeus {
    public class KrbDHRepInfo{
        public byte[] ServerDHNonce { get; private set; }
        public byte[] DHSignedData { get; private set; }
        public KrbKDCDHKeyInfo KDCDHKeyInfo { get; private set; }

        public KrbDHRepInfo(AsnElt asnElt) {

            if(asnElt.TagValue != AsnElt.SEQUENCE) {
                throw new ArgumentException("Expected SEQUENCE for type DHRepInfo");
            }

            foreach(AsnElt seq in asnElt.Sub) {
                switch (seq.TagValue) {
                    case 0: //dhSignedData
                        DHSignedData = seq.GetOctetString();
                        SignedCms cms = new SignedCms();
                        cms.Decode(DHSignedData);

                        try {
                            cms.CheckSignature(true);
                        } catch (CryptographicException) {
                            Console.WriteLine("[!] DHRepInfo Signature Not Valid! - Do you even care?");
                        }

                        KDCDHKeyInfo = new KrbKDCDHKeyInfo(AsnElt.Decode(cms.ContentInfo.Content));
                        break;

                    case 1: //serverDHNonce
                        ServerDHNonce = seq.GetOctetString();
                        break;
                }
            }
        }
    }
}

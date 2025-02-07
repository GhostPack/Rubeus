using Asn1;
using System;
using System.Security.Cryptography;

namespace Rubeus {
    public class KrbPkAuthenticator {

        public KrbPkAuthenticator(uint cuSec, DateTime cTime, int nonce, KDCReqBody reqBody) {
            CuSec = cuSec;
            CTime = cTime;
            Nonce = nonce;
            RequestBody = reqBody;
        }

        public KDCReqBody RequestBody { get; private set; }
        public uint CuSec { get; set; }
        public DateTime CTime { get; set; }
        public int Nonce { get; set; }

        public AsnElt Encode() {

            byte[] paChecksum;

            using (SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider()) {
                paChecksum = sha1.ComputeHash(RequestBody.Encode().Encode());
            }
        
            AsnElt asnCTime = AsnElt.MakeString(AsnElt.GeneralizedTime, CTime.ToString("yyyyMMddHHmmssZ"));

            return AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.Make(AsnElt.CONTEXT,0, new AsnElt[] { AsnElt.MakeInteger(CuSec) }),
                    AsnElt.Make(AsnElt.CONTEXT,1, new AsnElt[]{ asnCTime } ),
                    AsnElt.Make(AsnElt.CONTEXT,2, new AsnElt[]{ AsnElt.MakeInteger(Nonce) } ),
                    AsnElt.Make(AsnElt.CONTEXT,3, new AsnElt[]{ AsnElt.MakeBlob(paChecksum) })
                });        
        }
    }
}

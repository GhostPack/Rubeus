using Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Rubeus {
    public class PA_PK_AS_REQ {

        public static readonly Oid IdPkInitAuthData = new Oid("1.3.6.1.5.2.3.1");
        public KrbAuthPack AuthPack { get; private set; }
        public X509Certificate2 PKCert { get; private set; }
        public KDCKeyAgreement Agreement { get; private set; }

        public PA_PK_AS_REQ(KrbAuthPack krbAuthPack, X509Certificate2 pkCert, KDCKeyAgreement agreement) {
            AuthPack = krbAuthPack;
            PKCert = pkCert;
            Agreement = agreement;
        }

        public AsnElt Encode() {

            SignedCms signed = new SignedCms(
                new ContentInfo(
                    IdPkInitAuthData,
                    AuthPack.Encode().Encode()
                )
            );
            
            var signer = new CmsSigner(PKCert);
            signed.ComputeSignature(signer, silent: false);

            return AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                AsnElt.Make(AsnElt.CONTEXT, 0, new AsnElt[]{
                    AsnElt.MakeBlob(signed.Encode())
                })
            });                  
        }
    }
}

using Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Rubeus {
    public class KrbAuthPack {

        public KrbPkAuthenticator Authenticator { get; private set; }
        public KrbSubjectPublicKeyInfo ClientPublicValue { get; set; }
        public KrbAlgorithmIdentifier[] SupportedCMSTypes { get; set; }
        public byte[] ClientDHNonce { get; set; }
        public X509Certificate2 Certificate { get; set; }

        public KrbAuthPack(KrbPkAuthenticator authenticator, X509Certificate2 certificate) {
            Authenticator = authenticator;
            Certificate = certificate;
            ClientDHNonce = new byte[0];
        }

        public AsnElt Encode() {
          
            return AsnElt.Make(AsnElt.SEQUENCE, 
                new AsnElt[] {
                    AsnElt.Make(AsnElt.CONTEXT,0, Authenticator.Encode()),
                    AsnElt.Make(AsnElt.CONTEXT,1, ClientPublicValue.Encode() ),
                    //AsnElt.Make(AsnElt.CONTEXT,2, new AsnElt[]{ CMSTypes } ),
                    AsnElt.Make(AsnElt.CONTEXT,3, AsnElt.MakeBlob(ClientDHNonce)) 
                });
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus.Kerberos.PAC {

    public class SignatureData : PacInfoBuffer {

        public Interop.KERB_CHECKSUM_ALGORITHM SignatureType { get; set; }
        public byte[] Signature { get; set; }
        
        public SignatureData(byte[] data, PacInfoBufferType type) : base(data, type) {

            SignatureType = (Interop.KERB_CHECKSUM_ALGORITHM)br.ReadInt32();

            switch (SignatureType) {
                case Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5:
                    Signature = br.ReadBytes(16);
                    break;
                case Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128:
                case Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256:
                    Signature = br.ReadBytes(12);
                    break;
            }
        }

        public override byte[] Encode() {
            throw new NotImplementedException();
        }

        protected override void Decode(byte[] data) {
            
        }
    }
}

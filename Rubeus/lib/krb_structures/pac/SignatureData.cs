using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GoldenRetriever.Kerberos.PAC {

    public enum PacSignatureType : uint {
        KERB_CHECKSUM_HMAC_MD5 = 0xFFFFFF76,
        HMAC_SHA1_96_AES128 = 0x0000000F,
        HMAC_SHA1_96_AES256 = 0x00000010
    }

    public class SignatureData : PacInfoBuffer {

        public PacSignatureType SignatureType { get; set; }
        public byte[] Signature { get; set; }
        
        public SignatureData(byte[] data, PacInfoBufferType type) : base(data, type) {

            SignatureType = (PacSignatureType)br.ReadInt32();

            switch (SignatureType) {
                case PacSignatureType.KERB_CHECKSUM_HMAC_MD5:
                    Signature = br.ReadBytes(16);
                    break;
                case PacSignatureType.HMAC_SHA1_96_AES128:
                case PacSignatureType.HMAC_SHA1_96_AES256:
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

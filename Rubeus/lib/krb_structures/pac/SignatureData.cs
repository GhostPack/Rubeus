using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Rubeus.Kerberos.PAC {

    public enum PacSignatureType : uint {
        KERB_CHECKSUM_HMAC_MD5 = 0xFFFFFF76,
        HMAC_SHA1_96_AES128 = 0x0000000F,
        HMAC_SHA1_96_AES256 = 0x00000010
    }

    public class SignatureData : PacInfoBuffer {

        public PacSignatureType SignatureType { get; set; }
        public byte[] Signature { get; set; }
        
        public SignatureData(byte[] data, PacInfoBufferType type) : base(data, type) {
            Decode(data);
        }

        public override byte[] Encode() {
            BinaryWriter bw = new BinaryWriter(new MemoryStream());            
            bw.Write((int)SignatureType);
            bw.Write(Signature);
            return ((MemoryStream)bw.BaseStream).ToArray();
        }

        protected override void Decode(byte[] data) {

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
    }
}

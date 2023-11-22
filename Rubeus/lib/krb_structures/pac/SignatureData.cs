using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Rubeus.Kerberos.PAC {

    public class SignatureData : PacInfoBuffer {

        public Interop.KERB_CHECKSUM_ALGORITHM SignatureType { get; set; }
        public byte[] Signature { get; set; }

        public SignatureData(PacInfoBufferType type)
        {
            this.Type = type;
        }
        
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

            SignatureType = (Interop.KERB_CHECKSUM_ALGORITHM)br.ReadInt32();

            switch (SignatureType) {
                case Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5:
                    Signature = br.ReadBytes(16);
                    break;
                case Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128:
                case Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256:
                case Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_NONE:
                    Signature = br.ReadBytes(12);
                    break;
            }
        }
    }
}

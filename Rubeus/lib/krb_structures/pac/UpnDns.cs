using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GoldenRetriever.Kerberos.PAC {
    public class UpnDns : PacInfoBuffer {
        public UpnDns(int flags, string dnsDomainName, string upn) {
            Flags = flags;
            DnsDomainName = dnsDomainName;
            Upn = upn;
        }

        public UpnDns(byte[] data) : base(data, PacInfoBufferType.UpnDns) { }


        public short UpnLength { get; set; }
        public short UpnOffset { get; set; }

        public short DnsDomainNameLen { get; set; }

        public short DnsDomainNameOffset { get; set; }

        public int Flags { get; set; }

        public string DnsDomainName { get; set; }

        public string Upn { get; set; }


        public override byte[] Encode() {
            throw new NotImplementedException();
        }

        protected override void Decode(byte[] data) {

            UpnLength = br.ReadInt16();
            UpnOffset = br.ReadInt16();
            DnsDomainNameLen = br.ReadInt16();
            DnsDomainNameOffset = br.ReadInt16();
            Flags = br.ReadInt32();

            br.BaseStream.Position = UpnOffset;
            Upn = Encoding.Unicode.GetString(br.ReadBytes(UpnLength));

            br.BaseStream.Position = DnsDomainNameOffset;
            DnsDomainName = Encoding.Unicode.GetString(br.ReadBytes(DnsDomainNameLen));                    
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Rubeus.Kerberos.PAC {
    public class UpnDns : PacInfoBuffer {

        public short UpnLength { get; private set; }
        public short UpnOffset { get; private set; }
        public short DnsDomainNameLen { get; private set; }
        public short DnsDomainNameOffset { get; private set; }
        public int Flags { get; set; }
        public string DnsDomainName { get; set; }
        public string Upn { get; set; }

        public UpnDns(int flags, string dnsDomainName, string upn) {
            Flags = flags;
            DnsDomainName = dnsDomainName;
            Upn = upn;
            Type = PacInfoBufferType.UpnDns;
        }

        public UpnDns(byte[] data) : base(data, PacInfoBufferType.UpnDns) {
            Decode(data);
        }

        public override byte[] Encode() {

            UpnOffset = 16;
            UpnLength = (short)(Upn.Length * 2);

            DnsDomainNameLen = (short)(DnsDomainName.Length * 2);
            DnsDomainNameOffset = (short)(UpnOffset + UpnLength);

            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(UpnLength);
            bw.Write(UpnOffset);
            bw.Write(DnsDomainNameLen);
            bw.Write(DnsDomainNameOffset);
            bw.Write(Flags);
            bw.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 });
            bw.Write(Encoding.Unicode.GetBytes(Upn));
            bw.Write(Encoding.Unicode.GetBytes(DnsDomainName));
            bw.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 });
            return ((MemoryStream)bw.BaseStream).ToArray();
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

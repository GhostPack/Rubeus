using System;
using System.IO;
using System.Security.Principal;
using System.Text;

namespace Rubeus.Kerberos.PAC
{
    public class UpnDns : PacInfoBuffer
    {

        public short? UpnLength { get; private set; }
        public short? UpnOffset { get; private set; }
        public short? DnsDomainNameLen { get; private set; }
        public short? DnsDomainNameOffset { get; private set; }
        public Interop.UpnDnsFlags Flags { get; set; }
        public string DnsDomainName { get; set; }
        public string Upn { get; set; }
        public short? SamNameLength { get; set; }
        public short? SamNameOffset { get; set; }
        public short? SidLength { get; set; }
        public short? SidOffset { get; set; }
        public string SamName { get; set; }
        public SecurityIdentifier Sid { get; set; }
        public byte[] Junk { get; set; }

        public UpnDns(int flags, string dnsDomainName, string upn, string samName = null, SecurityIdentifier sid = null)
        {
            Flags = (Interop.UpnDnsFlags)flags;
            DnsDomainName = dnsDomainName;
            Upn = upn;
            Type = PacInfoBufferType.UpnDns;
            SamName = samName;
            Sid = sid;
        }

        public UpnDns(byte[] data) : base(data, PacInfoBufferType.UpnDns)
        {
            Decode(data);
        }

        public override byte[] Encode()
        {

            if (UpnOffset == null)
            {
                UpnOffset = 16;
                if (Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED))
                {
                    UpnOffset += 8;
                }
            }
            if (UpnLength == null)
            {
                UpnLength = (short)(Upn.Length * 2);
            }
            if (DnsDomainNameLen == null)
            {
                DnsDomainNameLen = (short)(DnsDomainName.Length * 2);
            }
            if (DnsDomainNameOffset == null)
            {
                DnsDomainNameOffset = (short)(UpnOffset + UpnLength);
            }
            if (SamNameLength == null && Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED) && SamName != null)
            {
                SamNameLength = (short)(SamName.Length * 2);
            }
            if (SamNameOffset == null && Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED) && SamName != null)
            {
                SamNameOffset = (short)(DnsDomainNameOffset + DnsDomainNameLen);
            }
            if (SidLength == null && Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED) && Sid != null)
            {
                SidLength = (short)Sid.BinaryLength;
            }
            if (SidOffset == null && Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED) && Sid != null)
            {
                SidOffset = (short)(SamNameOffset + SamNameLength);
            }

            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write((short)UpnLength);
            bw.Write((short)UpnOffset);
            bw.Write((short)DnsDomainNameLen);
            bw.Write((short)DnsDomainNameOffset);
            bw.Write((int)Flags);
            if (Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED))
            {
                bw.Write((short)SamNameLength);
                bw.Write((short)SamNameOffset);
                bw.Write((short)SidLength);
                bw.Write((short)SidOffset);
            }
            bw.BaseStream.Position = (long)UpnOffset;
            bw.Write(Encoding.Unicode.GetBytes(Upn));
            bw.BaseStream.Position = (long)DnsDomainNameOffset;
            bw.Write(Encoding.Unicode.GetBytes(DnsDomainName));
            if (Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED))
            {
                bw.BaseStream.Position = (long)SamNameOffset;
                bw.Write(Encoding.Unicode.GetBytes(SamName));
                bw.BaseStream.Position = (long)SidOffset;
                byte[] sidBytes = new byte[Sid.BinaryLength];
                Sid.GetBinaryForm(sidBytes, 0);
                bw.Write(sidBytes);
            }

            if (Junk != null)
            {
                bw.Write(Junk);
            }

            byte[] data = ((MemoryStream)bw.BaseStream).ToArray();
            return data;
        }

        protected override void Decode(byte[] data)
        {
            UpnLength = br.ReadInt16();
            UpnOffset = br.ReadInt16();
            DnsDomainNameLen = br.ReadInt16();
            DnsDomainNameOffset = br.ReadInt16();
            Flags = (Interop.UpnDnsFlags)br.ReadInt32();
            if (Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED))
            {
                SamNameLength = br.ReadInt16();
                SamNameOffset = br.ReadInt16();
                SidLength = br.ReadInt16();
                SidOffset = br.ReadInt16();
            }

            br.BaseStream.Position = (long)UpnOffset;
            Upn = Encoding.Unicode.GetString(br.ReadBytes((int)UpnLength));

            br.BaseStream.Position = (long)DnsDomainNameOffset;
            DnsDomainName = Encoding.Unicode.GetString(br.ReadBytes((int)DnsDomainNameLen));

            if (Flags.HasFlag(Interop.UpnDnsFlags.EXTENDED))
            {
                br.BaseStream.Position = (long)SamNameOffset;
                SamName = Encoding.Unicode.GetString(br.ReadBytes((int)SamNameLength));

                br.BaseStream.Position = (long)SidOffset;
                Sid = new SecurityIdentifier(br.ReadBytes((int)SidLength), 0);
            }

            long left = data.Length - br.BaseStream.Position;
            Junk = br.ReadBytes((int)left);
        }
    }
}

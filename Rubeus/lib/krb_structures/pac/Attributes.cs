using System;
using System.IO;

namespace Rubeus.Kerberos.PAC
{
    public class Attributes : PacInfoBuffer
    {
        
        public uint Length { get; set; }

        public Interop.PacAttribute Flags { get; set; }

        public Attributes(PacInfoBufferType type)
        {
            this.Type = type;
        }

        public Attributes()
        {
            Type = PacInfoBufferType.Attributes;
            Length = 2; // always going to be 2?
            Flags = Interop.PacAttribute.PAC_WAS_REQUESTED;
        }

        public Attributes(byte[] data) : base(data, PacInfoBufferType.Attributes)
        {
            Decode(data);
        }

        public override byte[] Encode()
        {
            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(Length);
            bw.Write((int)Flags);
            return ((MemoryStream)bw.BaseStream).ToArray();
        }

        protected override void Decode(byte[] data)
        {
            Length = br.ReadUInt32();
            Flags = (Interop.PacAttribute)br.ReadInt32();
        }
    }
}

using System;

namespace Rubeus.Kerberos.PAC
{
    public class Attributes : PacInfoBuffer
    {
        
        public byte[] attrib { get; set; }

        public Attributes(PacInfoBufferType type)
        {
            this.Type = type;
        }

        public Attributes()
        {
            Type = PacInfoBufferType.Attributes;
            byte[] data = { 0x2, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0 };
            Decode(data);
        }

        public Attributes(byte[] data) : base(data, PacInfoBufferType.Attributes)
        {
            Decode(data);
        }

        public override byte[] Encode()
        {
            return attrib;
        }

        protected override void Decode(byte[] data)
        {
            attrib = data;
        }
    }
}

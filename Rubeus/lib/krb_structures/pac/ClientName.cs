using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Rubeus.Kerberos.PAC {
    public class ClientName : PacInfoBuffer {
        public ClientName(DateTime clientId, string name) {            
            ClientId =  new DateTime(
                            clientId.Ticks - (clientId.Ticks % TimeSpan.TicksPerSecond),
                            clientId.Kind
                            );
            NameLength = (short)(name.Length * 2);
            Name = name;
            Type = PacInfoBufferType.ClientName;
        }

        public ClientName(byte[] data) : base(data, PacInfoBufferType.ClientName) {
            Decode(data);
        }

        public DateTime ClientId { get; set; }
        public short NameLength { get; private set; }
        public string Name { get; set; }

        protected override void Decode(byte[] data) {           
            ClientId = DateTime.FromFileTimeUtc(br.ReadInt64());
            NameLength = br.ReadInt16();
            Name = Encoding.Unicode.GetString(br.ReadBytes(NameLength));
        }

        public override byte[] Encode() {
            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(ClientId.ToFileTimeUtc());
            bw.Write(NameLength);
            bw.Write(Encoding.Unicode.GetBytes(Name));
            return ((MemoryStream)bw.BaseStream).ToArray();            
        }   
    }
}

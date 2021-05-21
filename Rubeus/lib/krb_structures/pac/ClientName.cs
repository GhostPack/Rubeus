using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace GoldenRetriever.Kerberos.PAC {
    public class ClientName : PacInfoBuffer {
        public ClientName(DateTime clientId, short nameLength, string name) {
            ClientId = clientId;
            NameLength = nameLength;
            Name = name;
        }

        public ClientName(byte[] data) : base(data, PacInfoBufferType.ClientName){}

        public DateTime ClientId { get; set; }
        public short NameLength { get; set; }
        public string Name { get; set; }

        protected override void Decode(byte[] data) {           
            ClientId = DateTime.FromFileTime(br.ReadInt64());
            NameLength = br.ReadInt16();
            Name = Encoding.Unicode.GetString(br.ReadBytes(NameLength));
        }

        public override byte[] Encode() {
            throw new NotImplementedException();
        }   
    }
}

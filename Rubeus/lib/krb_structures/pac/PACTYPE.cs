using Rubeus.Kerberos.PAC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Rubeus.Kerberos {

    public class PACTYPE {        
        public int cBuffers;
        public int Version;
        public List<PacInfoBuffer> PacInfoBuffers;

        public PACTYPE(int version, List<PacInfoBuffer> piBuffers) {
            Version = version;
            cBuffers = piBuffers.Count;
            PacInfoBuffers = piBuffers;
        }

        public PACTYPE(byte[] data, byte[] key) {

            BinaryReader br = new BinaryReader(new MemoryStream(data));
            cBuffers = br.ReadInt32();
            Version = br.ReadInt32();
            PacInfoBuffers = new List<PacInfoBuffer>();

            for(int idx=0; idx<cBuffers; ++idx) {

                var type = (PacInfoBufferType)br.ReadInt32();
                var bufferSize = br.ReadInt32();
                var offset = br.ReadInt64();

                long oldPostion = br.BaseStream.Position;
                br.BaseStream.Position = offset;
                var pacData = br.ReadBytes(bufferSize);
                br.BaseStream.Position = oldPostion;

                switch (type) {
                    case PacInfoBufferType.ClientName:
                        PacInfoBuffers.Add(new ClientName(pacData));
                        break;
                    case PacInfoBufferType.UpnDns:
                        PacInfoBuffers.Add(new UpnDns(pacData));
                        break;
                    case PacInfoBufferType.KDCChecksum:
                    case PacInfoBufferType.ServerChecksum:
                    case PacInfoBufferType.TicketChecksum:
                        PacInfoBuffers.Add(new SignatureData(pacData, type));
                        break;
                    case PacInfoBufferType.LogonInfo:
                        PacInfoBuffers.Add(new LogonInfo(pacData));
                        break;
                    case PacInfoBufferType.CredInfo:
                        PacInfoBuffers.Add(new PacCredentialInfo(pacData, PacInfoBufferType.CredInfo, key));
                        break;
                    case PacInfoBufferType.S4U2Proxy:
                        PacInfoBuffers.Add(new S4UDelegationInfo(pacData));
                        break;
                    case PacInfoBufferType.Attributes:
                        PacInfoBuffers.Add(new Attributes(pacData));
                        break;
                    case PacInfoBufferType.Requestor:
                        PacInfoBuffers.Add(new Requestor(pacData));
                        break;
                }                             
            }
        }
        
        public byte[] Encode() {

            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(cBuffers);
            bw.Write(Version);
            long offset = 8 + (PacInfoBuffers.Count * 16);

            foreach (var pacInfoBuffer in PacInfoBuffers) {

                byte[] pacBuffer = pacInfoBuffer.Encode();
                bw.Write((int)pacInfoBuffer.Type);
                bw.Write((int)pacBuffer.Length);
                bw.Write(offset);

                long oldPosition = bw.BaseStream.Position;
                bw.BaseStream.Position = offset;
                bw.Write(pacBuffer);
                bw.BaseStream.Position = oldPosition;
                offset = (offset + pacBuffer.Length + 7) / 8 * 8;
            }

            bw.BaseStream.SetLength(offset);

            return ((MemoryStream)bw.BaseStream).ToArray();
        }
    }
}

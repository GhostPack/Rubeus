using GoldenRetriever.Kerberos.PAC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GoldenRetriever.Kerberos {

    public class PACTYPE {        
        public int cBuffers;
        public int Version;
        public List<PacInfoBuffer> PacInfoBuffers;

        public PACTYPE(byte[] data) {

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
                        PacInfoBuffers.Add(new SignatureData(pacData, type));
                        break;
                    case PacInfoBufferType.LogonInfo:
                        PacInfoBuffers.Add(new LogonInfo(pacData));
                        break;
                }                             
            }
        } 
    }
}

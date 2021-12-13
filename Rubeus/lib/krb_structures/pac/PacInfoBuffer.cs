using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Rubeus.Kerberos.PAC {

    public enum PacInfoBufferType {
        LogonInfo = 1,
        CredInfo = 2,
        ServerChecksum = 6,
        KDCChecksum = 7,
        ClientName = 0xA,
        S4U2Proxy = 0xb,
        UpnDns = 0xc,
        ClientClaims = 0xd,
        DeviceInfo = 0xe,
        DeviceClaims = 0xf,
        TicketChecksum = 0x10,
        Attributes = 0x11,
        Requestor = 0x12
    }

    public abstract class PacInfoBuffer {

        protected BinaryReader br;
        protected byte[] key;

        public PacInfoBufferType Type { get; set; }

        public PacInfoBuffer() {}

        public PacInfoBuffer(byte[] data, PacInfoBufferType type) {
            Type = type;
            br = new BinaryReader(new MemoryStream(data));
        }

        public abstract byte[] Encode();
        protected abstract void Decode(byte[] data);
    }
}

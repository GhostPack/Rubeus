using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Rubeus.Ndr;
using Rubeus.Ndr.Marshal;

namespace Rubeus.Kerberos.PAC {
    public class S4UDelegationInfo : PacInfoBuffer {
        public S4UDelegationInfo() {
            Type = PacInfoBufferType.S4U2Proxy;
        }

        public S4UDelegationInfo(_S4U_DELEGATION_INFO s4uInfo) : this()
        {
            s4u = s4uInfo;
        }

        public S4UDelegationInfo(byte[] data) : base(data, PacInfoBufferType.S4U2Proxy) {
            Decode(data);
        }

        public _S4U_DELEGATION_INFO s4u { get; set; }

        protected override void Decode(byte[] data) {
            NdrPickledType npt = new NdrPickledType(data);
            _Unmarshal_Helper uh = new _Unmarshal_Helper(npt.Data);
            s4u = (_S4U_DELEGATION_INFO)uh.ReadReferentValue(uh.ReadStruct<_S4U_DELEGATION_INFO>, false);
        }

        public override byte[] Encode() {
            _Marshal_Helper mh = new _Marshal_Helper();
            mh.WriteReferent(s4u, new Action<_S4U_DELEGATION_INFO>(mh.WriteStruct));
            return mh.ToPickledType().ToArray();           
        }   
    }
}

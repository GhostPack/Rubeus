using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Rubeus.Ndr;
using Rubeus.Ndr.Marshal;

namespace Rubeus.Kerberos.PAC {
    public class S4UDelegationInfo : PacInfoBuffer {

        public _S4U_DELEGATION_INFO s4u { get; set; }

        public S4UDelegationInfo() {
            Type = PacInfoBufferType.S4U2Proxy;
            s4u = _S4U_DELEGATION_INFO.CreateDefault();
        }

        public S4UDelegationInfo(string s4uProxyTarget, string[] s4uTransitedServices)
        {
            Type = PacInfoBufferType.S4U2Proxy;
            _RPC_UNICODE_STRING[] tmp = new _RPC_UNICODE_STRING[s4uTransitedServices.Length];
            int c = 0;
            foreach (string s4uTransitedService in s4uTransitedServices)
            {
                tmp[c] = new _RPC_UNICODE_STRING(s4uTransitedService);
                c += 1;
            }
            s4u = new _S4U_DELEGATION_INFO(new _RPC_UNICODE_STRING(s4uProxyTarget), s4uTransitedServices.Length, tmp);
        }

        public S4UDelegationInfo(_S4U_DELEGATION_INFO s4uInfo) : this()
        {
            s4u = s4uInfo;
        }

        public S4UDelegationInfo(byte[] data) : base(data, PacInfoBufferType.S4U2Proxy) {
            Decode(data);
        }

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

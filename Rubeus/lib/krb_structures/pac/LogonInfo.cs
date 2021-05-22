using NtApiDotNet.Ndr.Marshal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Rubeus.Ndr;

namespace Rubeus.Kerberos.PAC {
    public class LogonInfo : PacInfoBuffer {

        public _KERB_VALIDATION_INFO KerbValidationInfo { get; set; }

        public LogonInfo(byte[] data) : base(data, PacInfoBufferType.LogonInfo) {
            
            NdrPickledType npt = new NdrPickledType(data);
            _Unmarshal_Helper uh = new _Unmarshal_Helper(npt.Data);
            KerbValidationInfo = (_KERB_VALIDATION_INFO)uh.ReadReferentValue(uh.ReadStruct<_KERB_VALIDATION_INFO>, false);
        }

        public override byte[] Encode() {
            throw new NotImplementedException();
        }

        protected override void Decode(byte[] data) {
            
        }
    }
}

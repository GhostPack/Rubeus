using Rubeus.Ndr.Marshal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Rubeus.Ndr;

namespace Rubeus.Kerberos.PAC {
    public class LogonInfo : PacInfoBuffer {

        public _KERB_VALIDATION_INFO KerbValidationInfo { get; set; }

        public LogonInfo()
        {
            Type = PacInfoBufferType.LogonInfo;
        }

        public LogonInfo(_KERB_VALIDATION_INFO kerbValidationInfo) : this() {
            KerbValidationInfo = kerbValidationInfo;
        }

        public LogonInfo(byte[] data) : base(data, PacInfoBufferType.LogonInfo) {
            Decode(data);
        }
        
        public override byte[] Encode() {
            _Marshal_Helper mh = new _Marshal_Helper();
            mh.WriteReferent(KerbValidationInfo, new Action<_KERB_VALIDATION_INFO>(mh.WriteStruct));
            return mh.ToPickledType().ToArray();            
        }

        protected override void Decode(byte[] data) {
            NdrPickledType npt = new NdrPickledType(data);
            _Unmarshal_Helper uh = new _Unmarshal_Helper(npt.Data);
            KerbValidationInfo = (_KERB_VALIDATION_INFO)uh.ReadReferentValue(uh.ReadStruct<_KERB_VALIDATION_INFO>, false);
        }
    }
}

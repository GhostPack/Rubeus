using NtApiDotNet.Ndr.Marshal;
using Rubeus.Ndr;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus.Kerberos.PAC {
    class PacCredentialInfo : PacInfoBuffer {

        public int Version { get; set; }

        public Interop.KERB_ETYPE EncryptionType { get; set; }

        public _PAC_CREDENTIAL_DATA? CredentialInfo { get; set; }


        public PacCredentialInfo(byte[] data, PacInfoBufferType type, byte[] key) :  base(data, type, key) {
           
        }

        public override byte[] Encode() {
            throw new NotImplementedException();
        }

        protected override void Decode(byte[] data) {
            Version = br.ReadInt32();
            EncryptionType = (Interop.KERB_ETYPE)br.ReadInt32();

            if(key == null) {
                return;
            }

            var encCredData = br.ReadBytes((int)(br.BaseStream.Length - br.BaseStream.Position));
            var plainCredData = Crypto.KerberosDecrypt(EncryptionType, Interop.KRB_KEY_USAGE_KRB_NON_KERB_SALT, key, encCredData);

            NdrPickledType npt = new NdrPickledType(plainCredData);
            _Unmarshal_Helper uh = new _Unmarshal_Helper(npt.Data);
            CredentialInfo = uh.ReadReferentValue(uh.ReadStruct<_PAC_CREDENTIAL_DATA>,false);           
        }
    }
}

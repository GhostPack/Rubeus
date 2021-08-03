using System;
using Asn1;
using Rubeus.Kerberos;

namespace Rubeus
{
    public class ADWin2KPac : AuthorizationData
    {
        public PACTYPE Pac { get; set; }

        public ADWin2KPac()
        {
            ad_type = Interop.AuthorizationDataType.AD_WIN2K_PAC;

            ad_data = null;
        }
        public ADWin2KPac(byte[] data)
        {
            ad_type = Interop.AuthorizationDataType.AD_WIN2K_PAC;
            Pac = new PACTYPE(data, null);
        }

        public ADWin2KPac(byte[] data, byte[] asrepKey)
        {
            ad_type = Interop.AuthorizationDataType.AD_WIN2K_PAC;
            Pac = new PACTYPE(data, asrepKey);
        }

        public ADWin2KPac(PACTYPE pac)
        {
            ad_type = Interop.AuthorizationDataType.AD_WIN2K_PAC;
            Pac = pac;
        }

        public ADWin2KPac(AsnElt data, byte[] asrepKey = null)
        {
            Decode(data, asrepKey);
        }

        protected override void Decode(AsnElt data)
        {
            Decode(data, null);
        }

        protected override void Decode(AsnElt data, byte[] asrepKey = null)
        {
            foreach (AsnElt s in data.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        ad_type = (Interop.AuthorizationDataType)s.Sub[0].GetInteger();
                        break;
                    case 1:
                        ad_data = s.Sub[0].CopyValue();
                        Pac = new PACTYPE(ad_data, asrepKey);
                        break;
                    default:
                        break;
                }
            }
        }

        public override AsnElt Encode()
        {
            if (Pac != null)
            {
                ad_data = Pac.Encode();
            }

            return ADEncode();
        }
    }
}

using System;
using Asn1;

namespace Rubeus
{
    public class ADKerbLocal : AuthorizationData
    {
        public byte[] LocalData { get; set; }

        public ADKerbLocal()
        {
            ad_type = Interop.AuthorizationDataType.KERB_LOCAL;

            // random KERB-LOCAL
            var rand = new Random();
            byte[] randomBytes = new byte[16];
            rand.NextBytes(randomBytes);
            ad_data = randomBytes;
        }
        public ADKerbLocal(byte[] data)
        {
            ad_type = Interop.AuthorizationDataType.KERB_LOCAL;
            ad_data = data;
        }

        public ADKerbLocal(AsnElt data)
        {
            Decode(data);
        }

        protected override void Decode(AsnElt data, byte[] junk = null)
        {
            Decode(data);
        }

        protected override void Decode(AsnElt data)
        {
            foreach (AsnElt s in data.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        ad_type = (Interop.AuthorizationDataType)s.Sub[0].GetInteger();
                        break;
                    case 1:
                        ad_data = s.Sub[0].GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public override AsnElt Encode()
        {
            return ADEncode();
        }
    }
}


﻿using System;
using System.Collections.Generic;
using Asn1;

namespace Rubeus
{
    public class ADIfRelevant : AuthorizationData
    {
        public List<AuthorizationData> ADData { get; set; }

        public ADIfRelevant()
        {
            ad_type = Interop.AuthorizationDataType.AD_IF_RELEVANT;
            ADData = new List<AuthorizationData>();
        }
        public ADIfRelevant(byte[] data)
        {
            ad_type = Interop.AuthorizationDataType.AD_IF_RELEVANT;
            ad_data = data;
        }

        public ADIfRelevant(AuthorizationData data)
        {
            ad_type = Interop.AuthorizationDataType.AD_IF_RELEVANT;
            ADData = new List<AuthorizationData>();
            ADData.Add(data);
        }

        public ADIfRelevant(List<AuthorizationData> data)
        {
            ad_type = Interop.AuthorizationDataType.AD_IF_RELEVANT;
            ADData = data;
        }

        public ADIfRelevant(AsnElt data, byte[] asrepKey = null)
        {
            Decode(data, asrepKey);
        }

        protected override void Decode(AsnElt data)
        {
            Decode(data, null);
        }

        protected override void Decode(AsnElt data, byte[] asrepKey = null)
        {
            foreach (AsnElt s in data.Sub[0].Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        ad_type = (Interop.AuthorizationDataType)s.Sub[0].GetInteger();
                        break;
                    case 1:
                        ADData = new List<AuthorizationData>();
                        foreach (AsnElt i in AsnElt.Decode(s.Sub[0].GetOctetString()).Sub[0].Sub)
                        {
                            switch (i.TagValue)
                            {
                                case 0:
                                    switch ((Interop.AuthorizationDataType)i.Sub[0].GetInteger())
                                    {
                                        case Interop.AuthorizationDataType.AD_IF_RELEVANT:
                                            ADData.Add(new ADIfRelevant(AsnElt.Decode(s.Sub[0].GetOctetString())));
                                            break;
                                        case Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS:
                                            ADData.Add(new ADRestrictionEntry(AsnElt.Decode(s.Sub[0].GetOctetString())));
                                            break;
                                        case Interop.AuthorizationDataType.KERB_LOCAL:
                                            ADData.Add(new ADKerbLocal(AsnElt.Decode(s.Sub[0].GetOctetString())));
                                            break;
                                        case Interop.AuthorizationDataType.AD_WIN2K_PAC:
                                            ADData.Add(new ADWin2KPac(AsnElt.Decode(s.Sub[0].GetOctetString()), asrepKey));
                                            break;
                                        default:
                                            break;
                                    }
                                    break;
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        public override AsnElt Encode()
        {

            // ad-data            [1] OCTET STRING
            if (ADData.Count > 0)
            {
                List<AsnElt> adList = new List<AsnElt>();

                foreach (AuthorizationData ad in ADData)
                {
                    AsnElt addrElt = ad.Encode();
                    adList.Add(addrElt);
                }
                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, adList.ToArray());
                ad_data = seq.Encode();
            }
            else
            {
                ad_data = new byte[0];
            }

            return ADEncode();
        }
    }
}
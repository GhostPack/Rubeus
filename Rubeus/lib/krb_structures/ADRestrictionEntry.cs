using Asn1;
using System;

namespace Rubeus
{
    //  KERB-AD-RESTRICTION-ENTRY ::= SEQUENCE {
    // restriction-type[0] Int32,
    // restriction[1] OCTET STRING
    // }
    public class ADRestrictionEntry : AuthorizationData
    {
        public ADRestrictionEntry()
        {
            ad_type = Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS;

            restriction_type = 0;

            Interop.LSAP_TOKEN_INFO_INTEGRITY_FLAGS flags = Interop.LSAP_TOKEN_INFO_INTEGRITY_FLAGS.UAC_RESTRICTED;
            Interop.LSAP_TOKEN_INFO_INTEGRITY_TOKENIL tokenIL = Interop.LSAP_TOKEN_INFO_INTEGRITY_TOKENIL.MEDIUM;

            restriction = buildTokenStruct(flags, tokenIL);


        }

        public ADRestrictionEntry(byte[] data)
        {
            ad_type = Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS;

            restriction_type = 0;

            restriction = data;
        }

        public ADRestrictionEntry(Interop.LSAP_TOKEN_INFO_INTEGRITY_FLAGS flags, Interop.LSAP_TOKEN_INFO_INTEGRITY_TOKENIL tokenIL)
        {
            ad_type = Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS;

            restriction_type = 0;

            restriction = buildTokenStruct(flags, tokenIL);
        }

        public ADRestrictionEntry(AsnElt data)
        {
            Decode(data);
        }

        private byte[] buildTokenStruct(Interop.LSAP_TOKEN_INFO_INTEGRITY_FLAGS flags, Interop.LSAP_TOKEN_INFO_INTEGRITY_TOKENIL tokenIL)
        {
            // LSAP_TOKEN_INFO_INTEGRITY struct
            Interop.LSAP_TOKEN_INFO_INTEGRITY tokenInfo;
            tokenInfo.Flags = flags;
            tokenInfo.TokenIL = tokenIL;

            // random machine ID
            var rand = new Random();
            tokenInfo.machineID = new byte[32];
            rand.NextBytes(tokenInfo.machineID);

            // get struct bytes
            byte[] data = new byte[40];
            data[0] = (byte)((int)tokenInfo.Flags >> 24);
            data[1] = (byte)((int)tokenInfo.Flags >> 16);
            data[2] = (byte)((int)tokenInfo.Flags >> 8);
            data[3] = (byte)((int)tokenInfo.Flags);
            data[4] = (byte)((int)tokenInfo.TokenIL >> 24);
            data[5] = (byte)((int)tokenInfo.TokenIL >> 16);
            data[6] = (byte)((int)tokenInfo.TokenIL >> 8);
            data[7] = (byte)((int)tokenInfo.TokenIL);
            for (int j = 0; j < 32; ++j)
            {
                data[j + 8] = tokenInfo.machineID[j];
            }

            return data;
        }

        protected override void Decode(AsnElt data, byte[] junk = null)
        {
            Decode(data);
        }

        protected override void Decode(AsnElt data)
        {
            ad_type = Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS;
            foreach (AsnElt s in data.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        restriction_type = s.Sub[0].GetInteger();
                        break;
                    case 1:
                        restriction = s.Sub[0].CopyValue();
                        break;
                    default:
                        break;
                }
            }
        }

        public override AsnElt Encode()
        {
            // KERB-AD-RESTRICTION-ENTRY encoding
            // restriction-type       [0] Int32
            AsnElt adRestrictionEntryElt = AsnElt.MakeInteger(restriction_type);
            AsnElt adRestrictionEntrySeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adRestrictionEntryElt });
            adRestrictionEntrySeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, adRestrictionEntrySeq);

            // restriction            [1] OCTET STRING
            AsnElt adRestrictionEntryDataElt = AsnElt.MakeBlob(restriction);
            AsnElt adRestrictionEntryDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adRestrictionEntryDataElt });
            adRestrictionEntryDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, adRestrictionEntryDataSeq);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { adRestrictionEntrySeq, adRestrictionEntryDataSeq });
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, seq);

            ad_data = seq2.Encode();

            return ADEncode();
        }

        public long restriction_type { get; set; }

        public byte[] restriction { get; set; }
    }
}

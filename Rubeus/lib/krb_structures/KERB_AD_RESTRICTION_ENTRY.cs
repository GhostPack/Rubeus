using Asn1;
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace Rubeus
{
    //  KERB-AD-RESTRICTION-ENTRY ::= SEQUENCE {
    // restriction-type[0] Int32,
    // restriction[1] OCTET STRING
    // }
    public class KERB_AD_RESTRICTION_ENTRY
    {
        public KERB_AD_RESTRICTION_ENTRY()
        {

            restriction_type = 0;

            Interop.LSAP_TOKEN_INFO_INTEGRITY_FLAGS flags = Interop.LSAP_TOKEN_INFO_INTEGRITY_FLAGS.UAC_RESTRICTED;
            Interop.LSAP_TOKEN_INFO_INTEGRITY_TOKENIL tokenIL = Interop.LSAP_TOKEN_INFO_INTEGRITY_TOKENIL.MEDIUM;

            restriction = buildTokenStruct(flags, tokenIL);


        }

        public KERB_AD_RESTRICTION_ENTRY(byte[] data)
        {

            restriction_type = 0;

            restriction = data;
        }

        public KERB_AD_RESTRICTION_ENTRY(Interop.LSAP_TOKEN_INFO_INTEGRITY_FLAGS flags, Interop.LSAP_TOKEN_INFO_INTEGRITY_TOKENIL tokenIL)
        {

            restriction_type = 0;

            restriction = buildTokenStruct(flags, tokenIL);
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

        public AsnElt Encode()
        {
            // restriction-type       [0] Int32
            AsnElt adTypeElt = AsnElt.MakeInteger(restriction_type);
            AsnElt adTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adTypeElt });
            adTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, adTypeSeq);

            // restriction            [1] OCTET STRING
            AsnElt adDataElt = AsnElt.MakeBlob(restriction);
            AsnElt adDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adDataElt });
            adDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, adDataSeq);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { adTypeSeq, adDataSeq });
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { seq });

            return seq2;
        }

        public long restriction_type { get; set; }

        public byte[] restriction { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Asn1;

namespace Rubeus
{
    /* PA-PAC-OPTIONS ::= SEQUENCE {
        KerberosFlags
        -- Claims(0)
        -- Branch Aware(1)
        -- Forward to Full DC(2)
        -- Resource-based Constrained Delegation (3)
       }
    */

    public class PA_PAC_OPTIONS
    {
        public byte[] kerberosFlags { get; set; }
        public PA_PAC_OPTIONS(bool claims, bool branch, bool fullDC, bool rbcd)
        {
            kerberosFlags = new byte[4] { 0, 0, 0, 0 };
            if (claims) kerberosFlags[0] = (byte)(kerberosFlags[0] | 8);
            if (branch) kerberosFlags[0] = (byte)(kerberosFlags[0] | 4);
            if (fullDC) kerberosFlags[0] = (byte)(kerberosFlags[0] | 2);
            if (rbcd) kerberosFlags[0] = (byte)(kerberosFlags[0] | 1);
            kerberosFlags[0] = (byte)(kerberosFlags[0] * 0x10);
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();
            AsnElt kerberosFlagsAsn = AsnElt.MakeBitString(kerberosFlags);
            kerberosFlagsAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.BIT_STRING, kerberosFlagsAsn);
            AsnElt parent = AsnElt.MakeExplicit(0, kerberosFlagsAsn);
            allNodes.Add(parent);
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());
            return seq;
        }
    }
}

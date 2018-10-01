using System;
using Asn1;
using System.Collections.Generic;

namespace Rubeus
{
    //EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
    //        ticket-info     [0] SEQUENCE OF KrbCredInfo,
    //        nonce           [1] UInt32 OPTIONAL,
    //        timestamp       [2] KerberosTime OPTIONAL,
    //        usec            [3] Microseconds OPTIONAL,
    //        s-address       [4] HostAddress OPTIONAL,
    //        r-address       [5] HostAddress OPTIONAL
    //}

    public class EncKrbCredPart
    {
        public EncKrbCredPart()
        {
            // TODO: defaults for creation
            ticket_info = new List<KrbCredInfo>();
        }

        public EncKrbCredPart(AsnElt body)
        {
            ticket_info = new List<KrbCredInfo>();

            byte[] octetString = body.Sub[1].Sub[0].GetOctetString();
            AsnElt body2 = AsnElt.Decode(octetString, false);

            // assume only one KrbCredInfo for now
            KrbCredInfo info = new KrbCredInfo(body2.Sub[0].Sub[0].Sub[0].Sub[0]);
            ticket_info.Add(info);
        }

        public AsnElt Encode()
        {
            // ticket-info     [0] SEQUENCE OF KrbCredInfo
            //  assume just one ticket-info for now
            //  TODO: handle multiple ticket-infos
            AsnElt infoAsn = ticket_info[0].Encode();
            AsnElt seq1 = AsnElt.Make(AsnElt.SEQUENCE, new[] { infoAsn });
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq1 });
            seq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, seq2);

            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq2 });
            AsnElt totalSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { totalSeq });
            totalSeq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 29, totalSeq2);

            return totalSeq2;
        }

        public List<KrbCredInfo> ticket_info { get; set; }

        // other fields are optional/not used in our use cases
    }
}
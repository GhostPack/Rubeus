using System;
using Asn1;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    //EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
    //        user-data       [0] OCTET STRING,
    //        timestamp       [1] KerberosTime OPTIONAL,
    //        usec            [2] Microseconds OPTIONAL,
    //        seq-number      [3] UInt32 OPTIONAL,
    //        s-address       [4] HostAddress -- sender's addr --,
    //        r-address       [5] HostAddress OPTIONAL -- recip's addr
    //}

    // NOTE: we only use:
    //  user-data       [0] OCTET STRING
    //  seq-number      [3] UInt32 OPTIONAL
    //  s-address       [4] HostAddress

    // only used by the changepw command

    public class EncKrbPrivPart
    {
        public EncKrbPrivPart()
        {
            new_password = "";

            var rand = new Random();
            seq_number = (UInt32)rand.Next(1, Int32.MaxValue);

            host_name = "";
        }

        public EncKrbPrivPart(string newPassword, string hostName)
        {
            new_password = newPassword;

            var rand = new Random();
            seq_number = (UInt32)rand.Next(1, Int32.MaxValue);

            host_name = hostName;
        }

        public AsnElt Encode()
        {
            // user-data       [0] OCTET STRING
            byte[] pwBytes = Encoding.ASCII.GetBytes(new_password);
            AsnElt new_passwordAsn = AsnElt.MakeBlob(pwBytes);
            AsnElt new_passwordSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { new_passwordAsn });
            new_passwordSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, new_passwordSeq);


            // seq-number      [3] UInt32 OPTIONAL
            AsnElt seq_numberAsn = AsnElt.MakeInteger(seq_number);
            AsnElt seq_numberSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { seq_numberAsn });
            seq_numberSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, seq_numberSeq);


            //  s-address       [4] HostAddress
            AsnElt hostAddressTypeAsn = AsnElt.MakeInteger(20);
            AsnElt hostAddressTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { hostAddressTypeAsn });
            hostAddressTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, hostAddressTypeSeq);

            byte[] hostAddressAddressBytes = Encoding.ASCII.GetBytes(host_name);
            AsnElt hostAddressAddressAsn = AsnElt.MakeBlob(hostAddressAddressBytes);
            AsnElt hostAddressAddressSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { hostAddressAddressAsn });
            hostAddressAddressSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, hostAddressAddressSeq);

            AsnElt hostAddressSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { hostAddressTypeSeq, hostAddressAddressSeq });
            AsnElt hostAddressSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { hostAddressSeq });
            hostAddressSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, hostAddressSeq2);


            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { new_passwordSeq, seq_numberSeq, hostAddressSeq2 });
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });

            seq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 28, seq2);

            return seq2;
        }

        public string new_password { get; set; }

        public UInt32 seq_number { get; set; }

        public string host_name { get; set; }
    }
}
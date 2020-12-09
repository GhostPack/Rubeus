using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    //Hostname::= SEQUENCE {
    //        name-type[0] Int32,
    //        name-string[1] SEQUENCE OF KerberosString
    //}

    public class HostAddress
    {
        public HostAddress()
        {
            // nETBIOS = 20
            //      netbios name of the requesting machine

            addr_type = Interop.HostAddressType.ADDRTYPE_NETBIOS;

            addr_string = string.Empty;
        }

        public HostAddress(string hostName)
        {
            // create with hostname
            addr_type = Interop.HostAddressType.ADDRTYPE_NETBIOS;

            // setup padding
            Int32 numSpaces = 8 - (hostName.Length % 8);
            hostName = hostName.PadRight(hostName.Length + numSpaces);

            addr_string = hostName.ToUpper();
        }

        public HostAddress(Interop.HostAddressType atype, string address)
        {
            // create with different type
            addr_type = atype;

            // setup padding
            Int32 numSpaces = 8 - (address.Length % 8);
            address = address.PadRight(address.Length + numSpaces);

            addr_string = address.ToUpper();
        }

        public HostAddress(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        addr_type = (Interop.HostAddressType)s.Sub[0].GetInteger();
                        break;
                    case 1:
                        addr_string = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // addr-type[0] Int32
            // addr-string[1] OCTET STRING
            AsnElt addrTypeElt = AsnElt.MakeInteger((long)addr_type);
            AsnElt addrTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { addrTypeElt });
            addrTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, addrTypeSeq);

            AsnElt addrStringElt = AsnElt.MakeString(AsnElt.TeletexString, addr_string);
            addrStringElt = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.OCTET_STRING, addrStringElt);
            AsnElt addrStringSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { addrStringElt });
            addrStringSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, addrStringSeq);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { addrTypeSeq, addrStringSeq });

            return seq;
        }

        public Interop.HostAddressType addr_type { get; set; }

        public string addr_string { get; set; }
    }
}

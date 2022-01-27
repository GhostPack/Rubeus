using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using Asn1;

namespace Rubeus
{
    public class KDC_PROXY_MESSAGE
    {
        /*
        KDC-PROXY-MESSAGE::= SEQUENCE {
        kerb-message [0] OCTET STRING,
        target-domain [1] KerberosString OPTIONAL,
        dclocator-hint [2] INTEGER OPTIONAL
        }
        */

        public KDC_PROXY_MESSAGE()
        {
            kerb_message = null;
            target_domain = null;
            dclocator_hint = null;
        }

        public KDC_PROXY_MESSAGE(byte[] message)
        {
            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(IPAddress.HostToNetworkOrder(message.Length));
            bw.Write(message);
            kerb_message = ((MemoryStream)bw.BaseStream).ToArray();
            target_domain = null;
            dclocator_hint = null;
        }

        public KDC_PROXY_MESSAGE(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        kerb_message = s.Sub[0].GetOctetString();
                        break;
                    case 1:
                        target_domain = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 2:
                        dclocator_hint = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            // kerb-message [0] OCTET STRING
            AsnElt messageAsn = AsnElt.MakeBlob(kerb_message);
            AsnElt messageSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { messageAsn });
            messageSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, messageSeq);
            allNodes.Add(messageSeq);

            // target-domain [1] KerberosString OPTIONAL,
            if (target_domain != null)
            {
                AsnElt domainAsn = AsnElt.MakeString(AsnElt.IA5String, target_domain);
                domainAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, domainAsn);
                AsnElt domainSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { domainAsn });
                domainSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, domainSeq);
                allNodes.Add(domainSeq);
            }

            // dclocator-hint [2] INTEGER OPTIONAL
            if (dclocator_hint != null)
            {
                AsnElt dchintAsn = AsnElt.MakeInteger((uint)dclocator_hint);
                AsnElt dchintSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { dchintAsn });
                dchintSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, dchintSeq);
                allNodes.Add(dchintSeq);
            }

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());

            return seq;
        }

        public byte[] kerb_message { get; set; }

        public string target_domain { get; set; }

        public uint? dclocator_hint { get; set; }
    }
}


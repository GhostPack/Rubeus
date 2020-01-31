using System;
using Asn1;
using System.Collections.Generic;

namespace Rubeus
{
    public class KRB_CRED
    {
        //KRB-CRED::= [APPLICATION 22] SEQUENCE {
        //    pvno[0] INTEGER(5),
        //    msg-type[1] INTEGER(22),
        //    tickets[2] SEQUENCE OF Ticket,
        //    enc-part[3] EncryptedData -- EncKrbCredPart
        //}

        public KRB_CRED()
        {
            // defaults for creation
            pvno = 5;
            msg_type = 22;

            tickets = new List<Ticket>();

            enc_part = new EncKrbCredPart();
        }

        public KRB_CRED(byte[] bytes)
        {
            RawBytes = bytes;
            AsnElt asn_KRB_CRED = AsnElt.Decode(bytes, false);
            this.Decode(asn_KRB_CRED.Sub[0]);
        }

        public KRB_CRED(AsnElt body)
        {
            this.Decode(body);
        }

        public void Decode(AsnElt body)
        {
            tickets = new List<Ticket>();

            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        pvno = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        msg_type = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        foreach (AsnElt ae in s.Sub[0].Sub[0].Sub)
                        {
                            Ticket ticket = new Ticket(ae);
                            tickets.Add(ticket);
                        }
                        break;
                    case 3:
                        enc_part = new EncKrbCredPart(s.Sub[0]);
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // pvno            [0] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, pvnoSeq);


            // msg-type        [1] INTEGER (22)
            AsnElt msg_typeAsn = AsnElt.MakeInteger(msg_type);
            AsnElt msg_typeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { msg_typeAsn });
            msg_typeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, msg_typeSeq);


            // tickets         [2] SEQUENCE OF Ticket
            //  TODO: encode/handle multiple tickets!
            AsnElt ticketAsn = tickets[0].Encode();
            AsnElt ticketSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { ticketAsn });
            AsnElt ticketSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { ticketSeq });
            ticketSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, ticketSeq2);


            // enc-part        [3] EncryptedData -- EncKrbCredPart
            AsnElt enc_partAsn = enc_part.Encode();
            AsnElt blob = AsnElt.MakeBlob(enc_partAsn.Encode());

            AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });
            blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

            // etype == 0 -> no encryption
            AsnElt etypeAsn = AsnElt.MakeInteger(0);
            AsnElt etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { etypeAsn });
            etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, etypeSeq);
            
            AsnElt infoSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { etypeSeq, blobSeq });
            AsnElt infoSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { infoSeq });
            infoSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, infoSeq2);


            // all the components
            AsnElt total = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { pvnoSeq, msg_typeSeq, ticketSeq2, infoSeq2 });

            // tag the final total ([APPLICATION 22])
            AsnElt final = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { total });
            final = AsnElt.MakeImplicit(AsnElt.APPLICATION, 22, final);

            return final;
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        //public Ticket[] tickets { get; set; }
        public List<Ticket> tickets { get; set; }

        public EncKrbCredPart enc_part { get; set; }

        public byte[] RawBytes { get; set; }
    }
}
using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class EncTicketPart
    {
        //EncTicketPart::= [APPLICATION 3] SEQUENCE {
        //   flags[0] TicketFlags,
        //   key[1] EncryptionKey,
        //   crealm[2] Realm,
        //   cname[3] PrincipalName,
        //   transited[4] TransitedEncoding,
        //   authtime[5] KerberosTime,
        //   starttime[6] KerberosTime OPTIONAL,
        //   endtime[7] KerberosTime,
        //   renew-till[8] KerberosTime OPTIONAL,
        //   caddr[9] HostAddresses OPTIONAL,
        //  authorization-data[10] AuthorizationData OPTIONAL
        //}

        public EncTicketPart(byte[] sessionKey, Interop.KERB_ETYPE etype, string domain, string user, Interop.TicketFlags ticketFlags)
        {
            // flags
            flags = ticketFlags;

            // default times
            authtime = DateTime.Now;
            starttime = DateTime.Now;
            endtime = starttime.AddHours(10);
            renew_till = starttime.AddDays(7);

            // set session key
            key = new EncryptionKey();
            key.keytype = (int)etype;
            key.keyvalue = sessionKey;

            // cname information
            crealm = domain;
            cname = new PrincipalName(user);

            // default empty TransitedEncoding
            transited = new TransitedEncoding();

            // null caddr and authdata
            caddr = null;
            authorization_data = null;

        }
        public EncTicketPart(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        UInt32 temp = Convert.ToUInt32(s.Sub[0].GetInteger());
                        byte[] tempBytes = BitConverter.GetBytes(temp);
                        flags = (Interop.TicketFlags)BitConverter.ToInt32(tempBytes, 0);
                        break;
                    case 1:
                        key = new EncryptionKey(s);
                        break;
                    case 2:
                        crealm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 3:
                        cname = new PrincipalName(s.Sub[0]);
                        break;
                    case 4:
                        transited = new TransitedEncoding(s.Sub[0]);
                        break;
                    case 5:
                        authtime = s.Sub[0].GetTime();
                        break;
                    case 6:
                        starttime = s.Sub[0].GetTime();
                        break;
                    case 7:
                        endtime = s.Sub[0].GetTime();
                        break;
                    case 8:
                        renew_till = s.Sub[0].GetTime();
                        break;
                    case 9:
                        // caddr (optional)
                        caddr = new List<HostAddress>();
                        caddr.Add(new HostAddress(s.Sub[0]));
                        break;
                    case 10:
                        // authorization-data (optional)
                        authorization_data = new AuthorizationData(s.Sub[0]);
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            // flags           [0] TicketFlags
            byte[] flagBytes = BitConverter.GetBytes((UInt32)flags);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(flagBytes);
            }
            AsnElt flagBytesAsn = AsnElt.MakeBitString(flagBytes);
            AsnElt flagBytesSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { flagBytesAsn });
            flagBytesSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, flagBytesSeq);
            allNodes.Add(flagBytesSeq);

            // key             [1] EncryptionKey
            AsnElt keyAsn = key.Encode();
            keyAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, keyAsn);
            allNodes.Add(keyAsn);

            // crealm                   [2] Realm
            //                          -- clients realm
            AsnElt realmAsn = AsnElt.MakeString(AsnElt.IA5String, crealm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { realmAsn });
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, realmSeq);
            allNodes.Add(realmSeq);

            // cname                   [3] PrincipalName
            if (cname != null)
            {
                AsnElt cnameElt = cname.Encode();
                cnameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, cnameElt);
                allNodes.Add(cnameElt);
            }

            // transited                    [4] TransitedEncoding
            AsnElt transitedElt = transited.Encode();
            transitedElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, transitedElt);
            allNodes.Add(transitedElt);

            // authtime                    [5] KerberosTime
            AsnElt authTimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, authtime.ToString("yyyyMMddHHmmssZ"));
            AsnElt authTimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { authTimeAsn });
            authTimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, authTimeSeq);
            allNodes.Add(authTimeSeq);

            // starttime                    [6] KerberosTime OPTIONAL
            if (starttime != null)
            {
                AsnElt startTimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, starttime.ToString("yyyyMMddHHmmssZ"));
                AsnElt startTimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { startTimeAsn });
                startTimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, startTimeSeq);
                allNodes.Add(startTimeSeq);
            }

            // endtime                    [7] KerberosTime
            AsnElt endTimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, endtime.ToString("yyyyMMddHHmmssZ"));
            AsnElt endTimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { endTimeAsn });
            endTimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, endTimeSeq);
            allNodes.Add(endTimeSeq);

            // renew-till                    [8] KerberosTime OPTIONAL
            if (renew_till != null)
            {
                AsnElt renewTimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, renew_till.ToString("yyyyMMddHHmmssZ"));
                AsnElt renewTimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { renewTimeAsn });
                renewTimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, renewTimeSeq);
                allNodes.Add(renewTimeSeq);
            }

            // caddr                    [9] HostAddresses OPTIONAL
            if (caddr != null)
            {
                List<AsnElt> addrList = new List<AsnElt>();
                foreach (HostAddress addr in caddr)
                {
                    AsnElt addrElt = addr.Encode();
                    addrList.Add(addrElt);
                }
                AsnElt addrSeqTotal1 = AsnElt.Make(AsnElt.SEQUENCE, addrList.ToArray());
                AsnElt addrSeqTotal2 = AsnElt.Make(AsnElt.SEQUENCE, addrSeqTotal1);
                addrSeqTotal2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, addrSeqTotal2);
                allNodes.Add(addrSeqTotal2);
            }

            // authorization-data            [10] AuthorizationData OPTIONAL
            // do this manually here and just copy the PAC across for now
            if (authorization_data != null)
            {
                AsnElt adTypeElt = AsnElt.MakeInteger((long)authorization_data.ad_type);
                AsnElt adTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { adTypeElt });
                adTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, adTypeSeq);

                AsnElt finalData = AsnElt.MakeBlob((byte[])authorization_data.ad_data);
                AsnElt adDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { finalData });
                adDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, adDataSeq);
                AsnElt authDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { adTypeSeq, adDataSeq });
                authDataSeq = AsnElt.Make(AsnElt.SEQUENCE, authDataSeq);
                authDataSeq = AsnElt.Make(AsnElt.SEQUENCE, authDataSeq);

                authDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 10, authDataSeq);
                allNodes.Add(authDataSeq);

            }

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            seq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 3, seq2);

            return seq2;
        }

        public Interop.TicketFlags flags { get; set; }

        public EncryptionKey key { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public TransitedEncoding transited { get; set; }

        public DateTime authtime { get; set; }

        public DateTime starttime { get; set; }

        public DateTime endtime { get; set; }

        public DateTime renew_till { get; set; }

        public List<HostAddress> caddr { get; set; }

        public AuthorizationData authorization_data { get; set; }
    }
}

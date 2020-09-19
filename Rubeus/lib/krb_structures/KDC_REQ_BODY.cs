using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class KDCReqBody
    {
        //KDC-REQ-BODY::= SEQUENCE {
        //    kdc-options[0] KDCOptions,
        //    cname[1] PrincipalName OPTIONAL
        //                                -- Used only in AS-REQ --,
        //    realm[2] Realm
        //                                -- Server's realm
        //                                -- Also client's in AS-REQ --,
        //    sname[3] PrincipalName OPTIONAL,
        //    from[4] KerberosTime OPTIONAL,
        //    till[5] KerberosTime,
        //    rtime[6] KerberosTime OPTIONAL,
        //    nonce[7] UInt32,
        //            etype[8] SEQUENCE OF Int32 -- EncryptionType
        //                                        -- in preference order --,
        //            addresses[9] HostAddresses OPTIONAL,
        //    enc-authorization-data[10] EncryptedData OPTIONAL
        //                                        -- AuthorizationData --,
        //            additional-tickets[11] SEQUENCE OF Ticket OPTIONAL
        //                                            -- NOTE: not empty
        //}

        public KDCReqBody(bool c = true, bool r = false)
        {
            // defaults for creation
            kdcOptions = Interop.KdcOptions.FORWARDABLE | Interop.KdcOptions.RENEWABLE | Interop.KdcOptions.RENEWABLEOK;

            // added ability to remove cname from request
            // seems to be useful for cross domain stuff
            // didn't see a cname in "real" S4U request traffic
            if (c)
            {
                cname = new PrincipalName();
            }

            sname = new PrincipalName();

            // date time from kekeo ;) HAI 2037!
            till = DateTime.ParseExact("20370913024805Z", "yyyyMMddHHmmssZ", System.Globalization.CultureInfo.InvariantCulture);

            // add rtime for AS-REQs
            if (r)
            {
                rtime = DateTime.ParseExact("20370913024805Z", "yyyyMMddHHmmssZ", System.Globalization.CultureInfo.InvariantCulture);
            }

            var rand = new Random();
            nonce = (UInt32)rand.Next(1, Int32.MaxValue);

            additional_tickets = new List<Ticket>();

            etypes = new List<Interop.KERB_ETYPE>();
        }

        public KDCReqBody(AsnElt body)
        {
            foreach (AsnElt s in body.Sub)
            {
                switch (s.TagValue)
                {
                    case 0:
                        UInt32 temp = Convert.ToUInt32(s.Sub[0].GetInteger());
                        byte[] tempBytes = BitConverter.GetBytes(temp);
                        kdcOptions = (Interop.KdcOptions)BitConverter.ToInt32(tempBytes, 0);
                        break;
                    case 1:
                        // optional
                        cname = new PrincipalName(s.Sub[0]);
                        break;
                    case 2:
                        realm = Encoding.ASCII.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 3:
                        // optional
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    case 4:
                        // optional
                        from = s.Sub[0].GetTime();
                        break;
                    case 5:
                        till = s.Sub[0].GetTime();
                        break;
                    case 6:
                        // optional
                        rtime = s.Sub[0].GetTime();
                        break;
                    case 7:
                        nonce = Convert.ToUInt32(s.Sub[0].GetInteger());
                        break;
                    case 8:
                        //etypes = new Enums.KERB_ETYPE[s.Sub[0].Sub.Length];
                        etypes = new List<Interop.KERB_ETYPE>();
                        for (int i = 0; i < s.Sub[0].Sub.Length; i++)
                        {
                            //etypes[i] = (Enums.KERB_ETYPE)Convert.ToUInt32(s.Sub[0].Sub[i].GetInteger());
                            etypes.Add((Interop.KERB_ETYPE)Convert.ToUInt32(s.Sub[0].Sub[i].GetInteger()));
                        }
                        break;
                    case 9:
                        // addresses (optional)
                        addresses = new List<HostAddress>();
                        addresses.Add(new HostAddress(s.Sub[0]));
                        break;
                    case 10:
                        // enc authorization-data (optional)
                        break;
                    case 11:
                        // additional-tickets (optional)
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // TODO: error-checking!

            List<AsnElt> allNodes = new List<AsnElt>();

            // kdc-options             [0] KDCOptions
            byte[] kdcOptionsBytes = BitConverter.GetBytes((UInt32)kdcOptions);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(kdcOptionsBytes);
            }
            AsnElt kdcOptionsAsn = AsnElt.MakeBitString(kdcOptionsBytes);
            AsnElt kdcOptionsSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { kdcOptionsAsn });
            kdcOptionsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, kdcOptionsSeq);
            allNodes.Add(kdcOptionsSeq);


            // cname                   [1] PrincipalName
            if (cname != null)
            {
                AsnElt cnameElt = cname.Encode();
                cnameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, cnameElt);
                allNodes.Add(cnameElt);
            }


            // realm                   [2] Realm
            //                          --Server's realm
            //                          -- Also client's in AS-REQ --
            AsnElt realmAsn = AsnElt.MakeString(AsnElt.IA5String, realm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { realmAsn });
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, realmSeq);
            allNodes.Add(realmSeq);


            // sname                   [3] PrincipalName OPTIONAL
            AsnElt snameElt = sname.Encode();
            snameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, snameElt);
            allNodes.Add(snameElt);


            // from                    [4] KerberosTime OPTIONAL


            // till                    [5] KerberosTime
            AsnElt tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, till.ToString("yyyyMMddHHmmssZ"));
            AsnElt tillSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { tillAsn });
            tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, tillSeq);
            allNodes.Add(tillSeq);


            // rtime                   [6] KerberosTime
            if (rtime.Year > 0001)
            {
                AsnElt rtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, rtime.ToString("yyyyMMddHHmmssZ"));
                AsnElt rtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { rtimeAsn });
                rtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, rtimeSeq);
                allNodes.Add(rtimeSeq);
            }

            // nonce                   [7] UInt32
            AsnElt nonceAsn = AsnElt.MakeInteger(nonce);
            AsnElt nonceSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { nonceAsn });
            nonceSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, nonceSeq);
            allNodes.Add(nonceSeq);


            // etype                   [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --
            List <AsnElt> etypeList = new List<AsnElt>();
            foreach (Interop.KERB_ETYPE etype in etypes)
            {
                AsnElt etypeAsn = AsnElt.MakeInteger((Int32)etype);
                //AsnElt etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { etypeAsn });
                etypeList.Add(etypeAsn);
            }
            AsnElt etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, etypeList.ToArray());
            AsnElt etypeSeqTotal1 = AsnElt.Make(AsnElt.SEQUENCE, etypeList.ToArray());
            AsnElt etypeSeqTotal2 = AsnElt.Make(AsnElt.SEQUENCE, etypeSeqTotal1);
            etypeSeqTotal2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, etypeSeqTotal2);
            allNodes.Add(etypeSeqTotal2);


            // addresses               [9] HostAddresses OPTIONAL
            if (addresses != null)
            {
                List<AsnElt> addrList = new List<AsnElt>();
                foreach (HostAddress addr in addresses)
                {
                    AsnElt addrElt = addr.Encode();
                    addrList.Add(addrElt);
                }
                AsnElt addrSeqTotal1 = AsnElt.Make(AsnElt.SEQUENCE, addrList.ToArray());
                AsnElt addrSeqTotal2 = AsnElt.Make(AsnElt.SEQUENCE, addrSeqTotal1);
                addrSeqTotal2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, addrSeqTotal2);
                allNodes.Add(addrSeqTotal2);
            }

            // enc-authorization-data  [10] EncryptedData OPTIONAL
            if (enc_authorization_data != null)
            {
                AsnElt authorizationEncryptedDataASN = enc_authorization_data.Encode();
                AsnElt authorizationEncryptedDataSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { authorizationEncryptedDataASN });
                authorizationEncryptedDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 10, authorizationEncryptedDataSeq);
                allNodes.Add(authorizationEncryptedDataSeq);
            }

            // additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
            if (additional_tickets.Count > 0) {
                AsnElt ticketAsn = additional_tickets[0].Encode();
                AsnElt ticketSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { ticketAsn });
                AsnElt ticketSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { ticketSeq });
                ticketSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 11, ticketSeq2);
                allNodes.Add(ticketSeq2);
            }

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());

            return seq;
        }


        public Interop.KdcOptions kdcOptions { get; set; }

        public PrincipalName cname { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public DateTime from { get; set; }

        public DateTime till { get; set; }

        public DateTime rtime { get; set; }

        public UInt32 nonce { get; set; }

        public List<Interop.KERB_ETYPE> etypes { get; set; }

        public List<HostAddress> addresses { get; set; }

        public EncryptedData enc_authorization_data { get; set; }

        public List<Ticket> additional_tickets { get; set; }
    }
}

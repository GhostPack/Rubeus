using System;
using Asn1;
using System.Text;
using System.Collections.Generic;
using System.IO;
using Rubeus.Kerberos;
using Rubeus.Kerberos.PAC;

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

        public EncTicketPart(byte[] sessionKey, Interop.KERB_ETYPE etype, string domain, string user, Interop.TicketFlags ticketFlags, DateTime startTime)
        {
            // flags
            flags = ticketFlags;

            // default times
            authtime = startTime;
            starttime = startTime;
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
        public EncTicketPart(AsnElt body, byte[] asrepKey = null, bool noAdData = false)
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
                        authorization_data = new List<AuthorizationData>();
                        if (noAdData)
                        {
                            authorization_data.Add(new ADIfRelevant(s.Sub[0].Sub[0].Sub[1].Sub[0].CopyValue()));
                        }
                        else
                        {
                            foreach (AsnElt tmp in s.Sub[0].Sub)
                            {
                                authorization_data.Add(new ADIfRelevant(tmp, asrepKey));
                            }
                        }
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
            if (authorization_data != null)
            {
                List<AsnElt> adList = new List<AsnElt>();

                foreach (AuthorizationData ad in authorization_data)
                {
                    AsnElt addrElt = ad.Encode();
                    adList.Add(addrElt);
                }
                AsnElt authDataSeq = AsnElt.Make(AsnElt.SEQUENCE, adList.ToArray());
                AsnElt addrSeqTotal1 = AsnElt.Make(AsnElt.SEQUENCE, authDataSeq);
                authDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 10, addrSeqTotal1);
                allNodes.Add(authDataSeq);

            }

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            seq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 3, seq2);

            return seq2;
        }

        public PACTYPE GetPac(byte[] asrepKey)
        {
            if (authorization_data != null)
            {
                foreach (var addata in authorization_data)
                {
                    foreach (var ifrelevant in ((ADIfRelevant)addata).ADData)
                    {
                        if (ifrelevant is ADWin2KPac win2k_pac)
                        {
                            return win2k_pac.Pac;
                        }
                    }
                }
            }
            return null;
        }

        public void SetPac(PACTYPE pac) {
            if (authorization_data == null)
            {
                authorization_data = new List<AuthorizationData>();
            }
            List<AuthorizationData> oldAuthData = new List<AuthorizationData>();
            foreach (var authdata in authorization_data)
            {
                ADIfRelevant tmpifrelevant = new ADIfRelevant();
                foreach (var adData in ((ADIfRelevant)authdata).ADData)
                {
                    if (!(adData is ADWin2KPac win2k_pac))
                    {
                        tmpifrelevant.ADData.Add(adData);
                    }
                }
                if (tmpifrelevant.ADData.Count > 0)
                {
                    oldAuthData.Add(tmpifrelevant);
                }
            }
            authorization_data = new List<AuthorizationData>();
            ADIfRelevant ifrelevant = new ADIfRelevant();
            ifrelevant.ADData.Add(new ADWin2KPac(pac));
            authorization_data.Add(ifrelevant);
            foreach (var authdata in oldAuthData)
            {
                authorization_data.Add(authdata);
            }
        }

        public Tuple<bool, bool, bool> ValidatePac(byte[] serviceKey, byte[] krbKey = null)
        {
            byte[] pacBytes = null;
            if (authorization_data != null)
            {
                foreach (var addata in authorization_data)
                {
                    foreach (var ifrelevant in ((ADIfRelevant)addata).ADData)
                    {
                        if (ifrelevant is ADWin2KPac win2k_pac)
                        {
                            pacBytes = win2k_pac.ad_data;
                        }
                    }
                }
            }
            if (pacBytes == null)
            {
                return null;
            }
            BinaryReader br = new BinaryReader(new MemoryStream(pacBytes));
            int cBuffers = br.ReadInt32();
            int Version = br.ReadInt32();
            long offset = 0, svrOffset = 0, kdcOffset = 0;
            Interop.KERB_CHECKSUM_ALGORITHM svrSigType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
            Interop.KERB_CHECKSUM_ALGORITHM kdcSigType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
            int svrLength = 12, kdcLength = 12;
            byte[] oldSvrSig = null, oldKdcSig = null;

            for (int idx = 0; idx < cBuffers; ++idx)
            {

                var type = (PacInfoBufferType)br.ReadInt32();
                var bufferSize = br.ReadInt32();
                offset = br.ReadInt64();

                long oldPostion = br.BaseStream.Position;
                br.BaseStream.Position = offset;
                var pacData = br.ReadBytes(bufferSize);
                br.BaseStream.Position = oldPostion;
                BinaryReader brPacData = new BinaryReader(new MemoryStream(pacData));

                switch (type)
                {
                    case PacInfoBufferType.KDCChecksum:
                        kdcOffset = offset + 4;
                        kdcSigType = (Interop.KERB_CHECKSUM_ALGORITHM)brPacData.ReadInt32();
                        if (kdcSigType == Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5)
                        {
                            kdcLength = 16;
                        }
                        oldKdcSig = brPacData.ReadBytes(kdcLength);
                        break;
                    case PacInfoBufferType.ServerChecksum:
                        svrOffset = offset + 4;
                        svrSigType = (Interop.KERB_CHECKSUM_ALGORITHM)brPacData.ReadInt32();
                        if (svrSigType == Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5)
                        {
                            svrLength = 16;
                        }
                        oldSvrSig = brPacData.ReadBytes(svrLength);
                        break;

                }
            }

            byte[] svrZeros = new byte[svrLength], kdcZeros = new byte[kdcLength];
            Array.Clear(svrZeros, 0, svrLength);
            Array.Clear(kdcZeros, 0, kdcLength);
            Array.Copy(svrZeros, 0, pacBytes, svrOffset, svrLength);
            Array.Copy(kdcZeros, 0, pacBytes, kdcOffset, kdcLength);

            byte[] svrSig = Crypto.KerberosChecksum(serviceKey, pacBytes, svrSigType);

            if (krbKey == null)
            {
                return Tuple.Create((Helpers.ByteArrayToString(oldSvrSig) == Helpers.ByteArrayToString(svrSig)), false, false);
            }

            byte[] kdcSig = Crypto.KerberosChecksum(krbKey, oldSvrSig, kdcSigType);
            return Tuple.Create((Helpers.ByteArrayToString(oldSvrSig) == Helpers.ByteArrayToString(svrSig)), (Helpers.ByteArrayToString(oldKdcSig) == Helpers.ByteArrayToString(kdcSig)), ValidateTicketChecksum(krbKey));
        }

        public byte[] CalculateTicketChecksum(byte[] krbKey, Interop.KERB_CHECKSUM_ALGORITHM krbChecksumType)
        {
            byte[] ticketChecksum = null;
            byte[] oldWin2kPacData = null;
            PACTYPE oldWin2kPac = null;
            EncTicketPart tmpEncTicketPart = this;

            // find the PAC and place a zero in it's ad-data
            List<AuthorizationData> newAuthData = new List<AuthorizationData>();
            foreach (var tmpadData in tmpEncTicketPart.authorization_data)
            {
                ADIfRelevant tmpifrelevant = new ADIfRelevant();
                foreach (var ifrelevant in ((ADIfRelevant)tmpadData).ADData)
                {
                    if (ifrelevant is ADWin2KPac win2k_pac)
                    {
                        oldWin2kPacData = win2k_pac.ad_data;
                        oldWin2kPac = win2k_pac.Pac;
                        ADWin2KPac tmpWin2k = new ADWin2KPac();
                        tmpWin2k.ad_data = new byte[] { 0x00 };
                        tmpWin2k.Pac = null;
                        tmpifrelevant.ADData.Add(tmpWin2k);
                    }
                    else
                    {
                        tmpifrelevant.ADData.Add(ifrelevant);
                    }
                }
                newAuthData.Add(tmpifrelevant);
            }
            tmpEncTicketPart.authorization_data = newAuthData;

            ticketChecksum = Crypto.KerberosChecksum(krbKey, tmpEncTicketPart.Encode().Encode(), krbChecksumType);

            foreach (var tmpadData in tmpEncTicketPart.authorization_data)
            {
                ADIfRelevant tmpifrelevant = new ADIfRelevant();
                foreach (var ifrelevant in ((ADIfRelevant)tmpadData).ADData)
                {
                    if (ifrelevant is ADWin2KPac win2k_pac)
                    {
                        win2k_pac.ad_data = oldWin2kPacData;
                        win2k_pac.Pac = oldWin2kPac;
                    }
                }
            }

            return ticketChecksum;
        }

        public bool ValidateTicketChecksum(byte[] krbKey)
        {
            SignatureData ticketSig = null;

            // find the PAC the old TicketChecksum
            foreach (var tmpadData in authorization_data)
            {
                foreach (var ifrelevant in ((ADIfRelevant)tmpadData).ADData)
                {
                    if (ifrelevant is ADWin2KPac win2k_pac)
                    {
                        foreach (var PacInfoBuffer in win2k_pac.Pac.PacInfoBuffers)
                        {
                            if (PacInfoBuffer.Type is PacInfoBufferType.TicketChecksum)
                            {
                                ticketSig = (SignatureData)PacInfoBuffer;
                            }
                        }
                    }
                }
            }

            if (ticketSig == null)
            {
                return false;
            }

            byte[] calculatedSig = CalculateTicketChecksum(krbKey, ticketSig.SignatureType);

            return (Helpers.ByteArrayToString(calculatedSig) == Helpers.ByteArrayToString(ticketSig.Signature));
        }

        public bool TicketChecksumExists()
        {
            bool ret = false;
            PACTYPE pt = null;

            // get the PAC
            if (authorization_data != null)
            {
                foreach (var addata in authorization_data)
                {
                    foreach (var ifrelevant in ((ADIfRelevant)addata).ADData)
                    {
                        if (ifrelevant is ADWin2KPac win2k_pac)
                        {
                            pt = win2k_pac.Pac;
                        }
                    }
                }
            }

            // If not PAC was retrieved return false
            if (pt == null)
            {
                return ret;
            }

            // look for the TicketChecksum
            foreach (var pacInfoBuffer in pt.PacInfoBuffers)
            {
                if (pacInfoBuffer.Type is PacInfoBufferType.TicketChecksum)
                {
                    ret = true;
                }
            }

            return ret;
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

        public List<AuthorizationData> authorization_data { get; set; }
    }
}

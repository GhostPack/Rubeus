using Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace Rubeus
{
    //TGS-REQ         ::= [APPLICATION 12] KDC-REQ

    //KDC-REQ         ::= SEQUENCE {
    //    -- NOTE: first tag is [1], not [0]
    //    pvno            [1] INTEGER (5) ,
    //    msg-type        [2] INTEGER (12 -- TGS),
    //    padata          [3] SEQUENCE OF PA-DATA OPTIONAL
    //                        -- NOTE: not empty --,
    //                          in this case, it's an AP-REQ
    //    req-body        [4] KDC-REQ-BODY
    //}

    public class TGS_REQ
    {
        public static byte[] NewTGSReq(string userName, string domain, string sname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial, bool renew = false, string s4uUser = "", bool enterprise = false, bool roast = false, bool opsec = false, bool unconstrained = false)
        {
            TGS_REQ req = new TGS_REQ(!opsec);
            if (!opsec)
            {
                // set the username
                req.req_body.cname.name_string.Add(userName);
            }

            // get domain from service for cross domain requests
            // if not requesting a cross domain TGT (krbtgt)
            string targetDomain = "";
            string[] parts = sname.Split('/');
            if (!(roast) && (parts.Length > 1) && (parts[0] != "krbtgt"))
            {
                targetDomain = parts[1].Substring(parts[1].IndexOf('.')+1);
            }
            else
            {
                targetDomain = domain;
            }

            // the realm (domain) the user exists in
            req.req_body.realm = targetDomain.ToUpper();

            // add in our encryption types
            if (requestEType == Interop.KERB_ETYPE.subkey_keymaterial)
            {
                // normal behavior
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                //req.req_body.etypes.Add(Interop.KERB_ETYPE.des_cbc_crc);
            }
            // real traffic have these etypes except when requesting a TGT, then only 
            else if ((opsec) && (parts.Length > 1) && (parts[0] != "krbtgt"))
            {
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);
            }
            else
            {
                // add in the supported etype specified
                req.req_body.etypes.Add(requestEType);
            }

            if (!String.IsNullOrEmpty(s4uUser))
            {
                // constrained delegation yo'
                req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;
                req.req_body.sname.name_string.Add(userName);

                if (!opsec)
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.ENCTKTINSKEY;

                if (opsec)
                    req.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);
            }

            else
            {
                if (enterprise)
                {
                    // KRB_NT-ENTERPRISE = 10
                    //      userPrincipalName
                    //      sAMAccountName
                    //      sAMAccountName@DomainNetBIOSName
                    //      sAMAccountName@DomainFQDN
                    //      DomainNetBIOSName\sAMAccountName
                    //      DomainFQDN\sAMAccountName
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
                    req.req_body.sname.name_string.Add(sname);
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
                }
                else if (parts.Length == 1)
                {
                    // KRB_NT_SRV_INST = 2
                    //      service and other unique instance (e.g. krbtgt)
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                    req.req_body.sname.name_string.Add(sname);
                    req.req_body.sname.name_string.Add(domain);
                }
                else if (parts.Length == 2)
                {
                    // KRB_NT_SRV_INST = 2
                    //      SPN (sname/server.domain.com)
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                    req.req_body.sname.name_string.Add(parts[0]);
                    req.req_body.sname.name_string.Add(parts[1]);
                }
                else if (parts.Length == 3)
                {
                    // KRB_NT_SRV_HST = 3
                    //      SPN (sname/server.domain.com/blah)
                    req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_HST;
                    req.req_body.sname.name_string.Add(parts[0]);
                    req.req_body.sname.name_string.Add(parts[1]);
                    req.req_body.sname.name_string.Add(parts[2]);
                }
                else
                {
                    Console.WriteLine("[X] Error: invalid TGS_REQ sname '{0}'", sname);
                }
            }

            if (renew)
            {
                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.RENEW;
            }

            // needed for authenticator checksum
            byte[] cksum_Bytes = null;

            // opsec complete the request body before the creation of the AP-REQ
            if (opsec)
            {
                // set correct flags based on type of request
                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
                if (!unconstrained)
                    req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK;
                if (unconstrained)
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.FORWARDED;

                // get hostname and hostname of SPN
                string hostName = Dns.GetHostName().ToUpper();
                string targetHostName;
                if (parts.Length > 1)
                {
                    targetHostName = parts[1].Substring(0, parts[1].IndexOf('.')).ToUpper();
                }
                else
                {
                    targetHostName = hostName;
                }

                // create enc-authorization-data if target host is not the local machine
                if ((hostName != targetHostName) && String.IsNullOrEmpty(s4uUser) && (!unconstrained))
                {
                    List<AuthorizationData> tmp = new List<AuthorizationData>();
                    AuthorizationData restrictions = new AuthorizationData(Interop.AuthorizationDataType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS);
                    AuthorizationData kerbLocal = new AuthorizationData(Interop.AuthorizationDataType.KERB_LOCAL);
                    tmp.Add(restrictions);
                    tmp.Add(kerbLocal);
                    AuthorizationData authorizationData = new AuthorizationData(tmp);
                    byte[] authorizationDataBytes = authorizationData.Encode().Encode();
                    byte[] enc_authorization_data = Crypto.KerberosEncrypt(requestEType, Interop.KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA, clientKey, authorizationDataBytes);
                    req.req_body.enc_authorization_data = new EncryptedData((Int32)requestEType, enc_authorization_data);
                }

                // S4U requests have a till time of 15 minutes in the future
                if (!String.IsNullOrEmpty(s4uUser))
                {
                    DateTime till = DateTime.Now;
                    till = till.AddMinutes(15);
                    req.req_body.till = till;
                }

                // encode req_body for authenticator cksum
                AsnElt req_Body_ASN = req.req_body.Encode();
                AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
                req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);
                byte[] req_Body_Bytes = req_Body_ASNSeq.CopyValue();
                cksum_Bytes = Crypto.KerberosChecksum(clientKey, req_Body_Bytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_RSA_MD5);
            }

            // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
            PA_DATA padata = new PA_DATA(domain, userName, providedTicket, clientKey, paEType, opsec, cksum_Bytes);
            req.padata.Add(padata);


            // moved so all PA-DATA sections are inserted after the request body has been completed, this is useful when
            // forming opsec requests as they require a checksum of the request body within the authenticator and the 
            // PADATA-TGS-REQ should go before the other PA-DATA sections
            if (opsec && (!String.IsNullOrEmpty(s4uUser)))
            {
                // real packets seem to lowercase the domain in these 2 PA_DATA's
                domain = domain.ToLower();

                // PA_S4U_X509_USER commented out until we get the checksum working
                //PA_DATA s4upadata = new PA_DATA(clientKey, s4uUser, domain, req.req_body.nonce);
                //req.padata.Add(s4upadata);
            }

            // add final S4U PA-DATA
            if (!String.IsNullOrEmpty(s4uUser))
            {
                // constrained delegation yo'
                PA_DATA s4upadata = new PA_DATA(clientKey, s4uUser, domain);
                req.padata.Add(s4upadata);
            }
            else if (opsec)
            {
                PA_DATA padataoptions = new PA_DATA(false, true, false, false);
                req.padata.Add(padataoptions);
            }

            return req.Encode().Encode();
        }

        // To request a TGS for a foreign KRBTGT, requires 2 different domains
        public static byte[] NewTGSReq(string userName, string domain, string targetDomain, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, Interop.KERB_ETYPE requestEType)
        {
            // foreign domain "TGT" request
            TGS_REQ req = new TGS_REQ(cname: false);

            // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
            PA_DATA padata = new PA_DATA(domain, userName, providedTicket, clientKey, paEType);
            req.padata.Add(padata);

            req.req_body.realm = domain;

            // add in our encryption types
            if (requestEType == Interop.KERB_ETYPE.subkey_keymaterial)
            {
                // normal behavior
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                //req.req_body.etypes.Add(Interop.KERB_ETYPE.des_cbc_crc);
            }
            else
            {
                // add in the supported etype specified
                req.req_body.etypes.Add(requestEType);
            }

            PA_DATA padataoptions = new PA_DATA(false, true, false, false);
            req.padata.Add(padataoptions);

            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            req.req_body.sname.name_string.Add("krbtgt");
            req.req_body.sname.name_string.Add(targetDomain);

            req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE | Interop.KdcOptions.FORWARDABLE;
            req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK & ~Interop.KdcOptions.RENEW;

            return req.Encode().Encode();
        }

        // maybe the function above can be combined with this one?
        public static byte[] NewTGSReq(string userName, string targetUser, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE paEType, Interop.KERB_ETYPE requestEType, bool cross = true, string requestDomain = "")
        {
            // cross domain "S4U2Self" requests
            TGS_REQ req = new TGS_REQ(cname: false);

            // get domains
            string domain = userName.Split('@')[1];
            string targetDomain = targetUser.Split('@')[1];

            // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
            PA_DATA padata = new PA_DATA(domain, userName.Split('@')[0], providedTicket, clientKey, paEType);
            req.padata.Add(padata);

            // which domain is the "local" domain for this TGS
            if (cross)
            {
                if (String.IsNullOrEmpty(requestDomain))
                    requestDomain = targetDomain;

                req.req_body.realm = requestDomain;
            }
            else
            {
                req.req_body.realm = domain;
            }

            // add in our encryption types
            if (requestEType == Interop.KERB_ETYPE.subkey_keymaterial)
            {
                // normal behavior
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                //req.req_body.etypes.Add(Interop.KERB_ETYPE.des_cbc_crc);
            }
            else
            {
                // add in the supported etype specified
                req.req_body.etypes.Add(requestEType);
            }

            PA_DATA s4upadata = new PA_DATA(clientKey, targetUser, targetDomain);
            req.padata.Add(s4upadata);

            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
            req.req_body.sname.name_string.Add(userName);

            req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE | Interop.KdcOptions.FORWARDABLE;
            req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK & ~Interop.KdcOptions.RENEW;

            return req.Encode().Encode();
        }

        public static byte[] NewTGSReq(byte[] kirbi)
        {
            // take a supplied .kirbi TGT cred and build a TGS_REQ

            return null;
        }

        
        public TGS_REQ(bool cname = true)
        {
            // default, for creation
            pvno = 5;

            // msg-type        [2] INTEGER (12 -- TGS)
            msg_type = (long)Interop.KERB_MESSAGE_TYPE.TGS_REQ;

            padata = new List<PA_DATA>();

            // added ability to remove cname from TGS request
            // seemed to be useful for cross domain stuff
            // didn't see a cname in "real" S4U request traffic
            req_body = new KDCReqBody(c: cname);
        }

        public AsnElt Encode()
        {
            // pvno            [1] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, pvnoSeq);


            // msg-type        [2] INTEGER (12 -- TGS -- )
            AsnElt msg_type_ASN = AsnElt.MakeInteger(msg_type);
            AsnElt msg_type_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { msg_type_ASN });
            msg_type_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, msg_type_ASNSeq);


            // padata          [3] SEQUENCE OF PA-DATA OPTIONAL
            List<AsnElt> padatas = new List<AsnElt>();
            foreach (PA_DATA pa in padata)
            {
                padatas.Add(pa.Encode());
            }
            AsnElt padata_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, padatas.ToArray());
            AsnElt padata_ASNSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { padata_ASNSeq });
            padata_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, padata_ASNSeq2);
            

            // req-body        [4] KDC-REQ-BODY
            AsnElt req_Body_ASN = req_body.Encode();
            AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
            req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);


            // encode it all into a sequence
            AsnElt[] total = new[] { pvnoSeq, msg_type_ASNSeq, padata_ASNSeq, req_Body_ASNSeq };
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, total);

            // TGS-REQ         ::= [APPLICATION 12] KDC-REQ
            //  put it all together and tag it with 10
            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            totalSeq = AsnElt.MakeImplicit(AsnElt.APPLICATION, 12, totalSeq);

            return totalSeq;
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public List<PA_DATA> padata { get; set; }

        public KDCReqBody req_body { get; set; }
    }
}

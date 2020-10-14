using Asn1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Rubeus
{
    //AS-REQ          ::= [APPLICATION 10] KDC-REQ

    //KDC-REQ         ::= SEQUENCE {
    //    -- NOTE: first tag is [1], not [0]
    //    pvno            [1] INTEGER (5) ,
    //    msg-type        [2] INTEGER (10 -- AS),
    //    padata          [3] SEQUENCE OF PA-DATA OPTIONAL
    //                        -- NOTE: not empty --,
    //    req-body        [4] KDC-REQ-BODY
    //}
    
    public class AS_REQ
    {
        public static AS_REQ NewASReq(string userName, string domain, Interop.KERB_ETYPE etype, bool opsec = false)
        {
            // build a new AS-REQ for the given userName, domain, and etype, but no PA-ENC-TIMESTAMP
            //  used for AS-REP-roasting

            AS_REQ req = new AS_REQ(opsec);

            // set the username to roast
            req.req_body.cname.name_string.Add(userName);

            // the realm (domain) the user exists in
            req.req_body.realm = domain;

            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)
            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            req.req_body.sname.name_string.Add("krbtgt");
            req.req_body.sname.name_string.Add(domain);

            // try to build a realistic request
            if (opsec)
            {
                string hostName = Dns.GetHostName();
                List<HostAddress> addresses = new List<HostAddress>();
                addresses.Add(new HostAddress(hostName));
                req.req_body.addresses = addresses;
                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.des_cbc_md5);

            }
            else
            {
                // add in our encryption type
                req.req_body.etypes.Add(etype);
            }

            return req;
        }

        public static AS_REQ NewASReq(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, bool opsec = false)
        {
            // build a new AS-REQ for the given userName, domain, and etype, w/ PA-ENC-TIMESTAMP
            //  used for "legit" AS-REQs w/ pre-auth

            // set pre-auth
            AS_REQ req = new AS_REQ(keyString, etype, opsec);
            
            // req.padata.Add()

            // set the username to request a TGT for
            req.req_body.cname.name_string.Add(userName);

            // the realm (domain) the user exists in
            req.req_body.realm = domain;

            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)
            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            req.req_body.sname.name_string.Add("krbtgt");
            req.req_body.sname.name_string.Add(domain);

            // try to build a realistic request
            if (opsec)
            {
                string hostName = Dns.GetHostName();
                List<HostAddress> addresses = new List<HostAddress>();
                addresses.Add(new HostAddress(hostName));
                req.req_body.addresses = addresses;
                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac_exp);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.old_exp);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.des_cbc_md5);
            }
            else
            {
                // add in our encryption type
                req.req_body.etypes.Add(etype);
            }

            return req; 
        }

        //TODO: Insert DHKeyPair parameter also.
        public static AS_REQ NewASReq(string userName, string domain, X509Certificate2 cert, KDCKeyAgreement agreement, Interop.KERB_ETYPE etype) {

            // build a new AS-REQ for the given userName, domain, and etype, w/ PA-ENC-TIMESTAMP
            //  used for "legit" AS-REQs w/ pre-auth

            // set pre-auth
            AS_REQ req = new AS_REQ(cert, agreement);

            // req.padata.Add()

            // set the username to request a TGT for
            req.req_body.cname.name_string.Add(userName);

            // the realm (domain) the user exists in
            req.req_body.realm = domain;

            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)
            req.req_body.sname.name_type = Interop.PRINCIPAL_TYPE.NT_SRV_INST;
            req.req_body.sname.name_string.Add("krbtgt");
            req.req_body.sname.name_string.Add(domain);

            // add in our encryption type
            req.req_body.etypes.Add(etype);

            return req;
        }

        public AS_REQ(bool opsec = false)
        {
            // default, for creation
            pvno = 5;
            msg_type = (long)Interop.KERB_MESSAGE_TYPE.AS_REQ;

            padata = new List<PA_DATA>();
            padata.Add(new PA_DATA());

            req_body = new KDCReqBody(true, opsec);
        }

        public AS_REQ(string keyString, Interop.KERB_ETYPE etype, bool opsec = false)
        {
            // default, for creation
            pvno = 5;
            msg_type = (long)Interop.KERB_MESSAGE_TYPE.AS_REQ;

            padata = new List<PA_DATA>();
            
            // add the encrypted timestamp
            padata.Add(new PA_DATA(keyString, etype));

            // add the include-pac == true
            padata.Add(new PA_DATA());
            
            req_body = new KDCReqBody(true, opsec);

            this.keyString = keyString;
        }

        public AS_REQ(X509Certificate2 pkCert, KDCKeyAgreement agreement) {

            // default, for creation
            pvno = 5;
            msg_type = 10;

            padata = new List<PA_DATA>();

            req_body = new KDCReqBody();

            // add the include-pac == true
            padata.Add(new PA_DATA());

            // add the encrypted timestamp
            padata.Add(new PA_DATA(pkCert, agreement,  req_body));           
        }

        public AS_REQ(byte[] data)
        {
            // decode the supplied bytes to an AsnElt object
            data = AsnIO.FindBER(data);
            AsnElt asn_AS_REQ = AsnElt.Decode(data);
            padata = new List<PA_DATA>();

            // AS-REQ::= [APPLICATION 10] KDC-REQ
            //  tag class == 1
            //  tag class == 10
            //  SEQUENCE
            if (asn_AS_REQ.TagValue != (int)Interop.KERB_MESSAGE_TYPE.AS_REQ)
            {
                throw new System.Exception("AS-REQ tag value should be 10");
            }

            if ((asn_AS_REQ.Sub.Length != 1) || (asn_AS_REQ.Sub[0].TagValue != 16))
            {
                throw new System.Exception("First AS-REQ sub should be a sequence");
            }

            // extract the KDC-REP out
            AsnElt[] kdc_req = asn_AS_REQ.Sub[0].Sub;

            foreach (AsnElt s in kdc_req)
            {
                switch (s.TagValue)
                {
                    case 1:
                        pvno = s.Sub[0].GetInteger();
                        break;
                    case 2:
                        msg_type = s.Sub[0].GetInteger();
                        break;
                    case 3:
                        // sequence of pa-data
                        foreach(AsnElt pa in s.Sub[0].Sub)
                        {
                            padata.Add(new PA_DATA(pa));
                        }
                        break;
                    case 4:
                        // KDC-REQ-BODY
                        req_body = new KDCReqBody(s.Sub[0]);
                        break;
                    default:
                        throw new System.Exception(String.Format("Invalid tag AS-REQ value : {0}", s.TagValue));
                }
            }
        }

        public AsnElt Encode()
        {
            // pvno            [1] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, pvnoSeq);


            // msg-type        [2] INTEGER (10 -- AS -- )
            AsnElt msg_type_ASN = AsnElt.MakeInteger(msg_type);
            AsnElt msg_type_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { msg_type_ASN });
            msg_type_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, msg_type_ASNSeq);

            // padata          [3] SEQUENCE OF PA-DATA OPTIONAL
            List<AsnElt> padatas = new List<AsnElt>();
            foreach (PA_DATA pa in padata)
            {
                padatas.Add(pa.Encode());
            }

            // req-body        [4] KDC-REQ-BODY
            AsnElt req_Body_ASN = req_body.Encode();
            AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
            req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);

            AsnElt padata_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, padatas.ToArray());
            AsnElt padata_ASNSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { padata_ASNSeq });
            padata_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, padata_ASNSeq2);

            // encode it all into a sequence
            AsnElt[] total = new[] { pvnoSeq, msg_type_ASNSeq, padata_ASNSeq, req_Body_ASNSeq };
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, total);

            // AS-REQ          ::= [APPLICATION 10] KDC-REQ
            //  put it all together and tag it with 10
            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });
            totalSeq = AsnElt.MakeImplicit(AsnElt.APPLICATION, 10, totalSeq);

            return totalSeq;
        }

        public long pvno { get; set;}

        public long msg_type { get; set; }

        //public PAData[] padata { get; set; }
        public List<PA_DATA> padata { get; set; }

        public KDCReqBody req_body { get; set; }

        //Ugly hack to make keyString available to 
        //the generic InnerTGT function
        public string keyString { get; set; }
    }
}

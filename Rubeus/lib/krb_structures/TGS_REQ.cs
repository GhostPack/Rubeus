using Asn1;
using System;
using System.Collections.Generic;
using System.IO;

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
        public static byte[] NewTGSReq(string userName, string domain, string sname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE etype, bool renew, string s4uUser = "")
        {
            TGS_REQ req = new TGS_REQ();

            // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
            PA_DATA padata = new PA_DATA(domain, userName, providedTicket, clientKey, etype);
            req.padata.Add(padata);

            // set the username
            req.req_body.cname.name_string.Add(userName);

            // the realm (domain) the user exists in
            req.req_body.realm = domain;

            if (!String.IsNullOrEmpty(s4uUser))
            {
                // constrained delegation yo'
                PA_DATA s4upadata = new PA_DATA(clientKey, String.Format("{0}@{1}", s4uUser, domain), domain);
                req.padata.Add(s4upadata);

                req.req_body.sname.name_type = 1;
                req.req_body.sname.name_string.Add(userName);

                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.ENCTKTINSKEY;

                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
            }

            else
            {
                // add in our encryption type
                req.req_body.etypes.Add(etype);

                // KRB_NT_SRV_INST = 2
                //      service and other unique instance (e.g. krbtgt)
                req.req_body.sname.name_type = 2;
                req.req_body.sname.name_string.Add(sname);
                req.req_body.sname.name_string.Add(domain);

                if (renew)
                {
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.RENEW;
                }
            }

            return req.Encode().Encode();
        }

        public static byte[] NewTGSReq(byte[] kirbi)
        {
            // take a supplied .kirbi TGT cred and build a TGS_REQ

            return null;
        }


        public TGS_REQ()
        {
            // default, for creation
            pvno = 5;

            // msg-type        [2] INTEGER (12 -- TGS)
            msg_type = 12;

            padata = new List<PA_DATA>();

            req_body = new KDCReqBody();
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
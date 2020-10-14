using System;
using Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;


namespace Rubeus {
    public class PA_DATA
    {
        public static readonly Oid DiffieHellman = new Oid("1.2.840.10046.2.1");

        //PA-DATA         ::= SEQUENCE {
        //        -- NOTE: first tag is [1], not [0]
        //        padata-type     [1] Int32,
        //        padata-value    [2] OCTET STRING -- might be encoded AP-REQ
        //}

        public PA_DATA()
        {
            // defaults for creation
            type = Interop.PADATA_TYPE.PA_PAC_REQUEST;

            value = new KERB_PA_PAC_REQUEST();
        }

        public PA_DATA(bool claims, bool branch, bool fullDC, bool rbcd)
        {
            // defaults for creation
            type = Interop.PADATA_TYPE.PA_PAC_OPTIONS;
            value = new PA_PAC_OPTIONS(claims, branch, fullDC, rbcd);
        }

        public PA_DATA(string keyString, Interop.KERB_ETYPE etype)
        {
            // include pac, supply enc timestamp

            type = Interop.PADATA_TYPE.ENC_TIMESTAMP;

            PA_ENC_TS_ENC temp = new PA_ENC_TS_ENC();

            byte[] rawBytes = temp.Encode().Encode();
            byte[] key = Helpers.StringToByteArray(keyString);

            // KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP == 1
            // From https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L55
            byte[] encBytes = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, key, rawBytes);

            value = new EncryptedData((int)etype, encBytes);
        }

        public PA_DATA(byte[] key, string name, string realm)
        {
            // used for constrained delegation
            type = Interop.PADATA_TYPE.S4U2SELF;

            value = new PA_FOR_USER(key, name, realm);
        }

        public PA_DATA(byte[] key, string name, string realm, uint nonce)
        {
            // used for constrained delegation
            type = Interop.PADATA_TYPE.PA_S4U_X509_USER;

            value = new PA_S4U_X509_USER(key, name, realm, nonce);
        }

        public PA_DATA(string crealm, string cname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE etype, bool opsec = false, byte[] req_body = null)
        {
            // include an AP-REQ, so PA-DATA for a TGS-REQ

            type = Interop.PADATA_TYPE.AP_REQ;

            // build the AP-REQ
            AP_REQ ap_req = new AP_REQ(crealm, cname, providedTicket, clientKey, etype);

            // make authenticator look more realistic
            if (opsec)
            {
                var rand = new Random();
                ap_req.authenticator.seq_number = (UInt32)rand.Next(1, Int32.MaxValue);
                // Could be useful to output the sequence number in case we implement KRB_PRIV or KRB_SAFE messages
                Console.WriteLine("[+] Sequence number is: {0}", ap_req.authenticator.seq_number);

                // randomize cusec to avoid fingerprinting
                ap_req.authenticator.cusec = rand.Next(0, 999999);

                if (req_body != null)
                    ap_req.authenticator.cksum = new Checksum(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_RSA_MD5, req_body);
            }

            value = ap_req;
        }

        public PA_DATA(X509Certificate2 pkInitCert, KDCKeyAgreement agreement, KDCReqBody kdcRequestBody) {

            DateTime now = DateTime.UtcNow;
            KrbPkAuthenticator authenticator = new KrbPkAuthenticator((uint)now.Millisecond, now, now.Millisecond, kdcRequestBody);
            KrbAuthPack authPack = new KrbAuthPack(authenticator, pkInitCert);

            byte[] pubKeyInfo = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                AsnElt.MakeInteger(agreement.P),
                AsnElt.MakeInteger(agreement.G),
            }).Encode();
     
            authPack.ClientPublicValue = new KrbSubjectPublicKeyInfo(new KrbAlgorithmIdentifier(DiffieHellman, pubKeyInfo),            
                AsnElt.MakeInteger(agreement.Y).Encode());
            
            type = Interop.PADATA_TYPE.PK_AS_REQ;
            value = new PA_PK_AS_REQ(authPack, pkInitCert, agreement);
        }

        public PA_DATA(AsnElt body)
        {
            //if (body.Sub.Length != 2)
            //{
            //    throw new System.Exception("PA-DATA should contain two elements");
            //}

            //Console.WriteLine("tag: {0}", body.Sub[0].Sub[1].TagString);
            type = (Interop.PADATA_TYPE)body.Sub[0].Sub[0].GetInteger();
            byte[] valueBytes = body.Sub[1].Sub[0].GetOctetString();

            switch (type) {
                case Interop.PADATA_TYPE.PA_PAC_REQUEST:
                    value = new KERB_PA_PAC_REQUEST(AsnElt.Decode(body.Sub[1].Sub[0].CopyValue()));
                    break;

                case Interop.PADATA_TYPE.PK_AS_REP:
                    value = new PA_PK_AS_REP(AsnElt.Decode(body.Sub[1].Sub[0].CopyValue()));
                    break;
            }
        }

        public AsnElt Encode()
        {
            // padata-type     [1] Int32
            AsnElt typeElt = AsnElt.MakeInteger((long)type);
            AsnElt nameTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { typeElt });
            nameTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, nameTypeSeq);

            AsnElt paDataElt;
            if (type == Interop.PADATA_TYPE.PA_PAC_REQUEST)
            {
                // used for AS-REQs

                // padata-value    [2] OCTET STRING -- might be encoded AP-REQ
                paDataElt = ((KERB_PA_PAC_REQUEST)value).Encode();
                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, paDataElt);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else if (type == Interop.PADATA_TYPE.ENC_TIMESTAMP)
            {
                // used for AS-REQs
                AsnElt blob = AsnElt.MakeBlob(((EncryptedData)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });
                blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, blobSeq });
                return seq;
            }
            else if (type == Interop.PADATA_TYPE.AP_REQ)
            {
                // used for TGS-REQs
                AsnElt blob = AsnElt.MakeBlob(((AP_REQ)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });

                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else if (type == Interop.PADATA_TYPE.S4U2SELF)
            {
                // used for constrained delegation
                AsnElt blob = AsnElt.MakeBlob(((PA_FOR_USER)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });

                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else if (type == Interop.PADATA_TYPE.PA_S4U_X509_USER)
            {
                // used for constrained delegation
                AsnElt blob = AsnElt.MakeBlob(((PA_S4U_X509_USER)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });

                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else if (type == Interop.PADATA_TYPE.PA_PAC_OPTIONS)
            {
                AsnElt blob = AsnElt.MakeBlob(((PA_PAC_OPTIONS)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });

                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else if(type == Interop.PADATA_TYPE.PK_AS_REQ) {

                AsnElt blob = AsnElt.MakeBlob(((PA_PK_AS_REQ)value).Encode().Encode());
                AsnElt blobSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { blob });

                paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

                AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeSeq, paDataElt });
                return seq;
            }
            else
            {
                return null;
            }
        }

        public Interop.PADATA_TYPE type { get; set; }

        public Object value { get; set; }
    }
}
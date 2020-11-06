using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    //S4UUserID::= SEQUENCE {
    //    nonce[0] UInt32, --the nonce in KDC - REQ - BODY
    //    cname[1] PrincipalName OPTIONAL,
    //    --Certificate mapping hints
    //    crealm[2] Realm,
    //    subject-certificate[3] OCTET STRING OPTIONAL, 
    //    options[4] BIT STRING OPTIONAL,
    //    ...
    //}

    public class S4UUserID
    {
        public S4UUserID(string name, string realm, uint n)
        {
            nonce = n;

            cname = new PrincipalName(name);
            cname.name_type = Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;

            crealm = realm;

            // default for creation
            options = Interop.PA_S4U_X509_USER_OPTIONS.SIGN_REPLY;
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            // nonce                   [0] UInt32
            AsnElt nonceAsn = AsnElt.MakeInteger(nonce);
            AsnElt nonceSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { nonceAsn });
            nonceSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, nonceSeq);
            allNodes.Add(nonceSeq);

            // cname                   [1] PrincipalName
            AsnElt cnameElt = cname.Encode();
            cnameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, cnameElt);
            allNodes.Add(cnameElt);

            // crealm                  [2] Realm
            AsnElt realmAsn = AsnElt.MakeString(AsnElt.IA5String, crealm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { realmAsn });
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, realmSeq);
            allNodes.Add(realmSeq);

            // options                 [4] PA_S4U_X509_USER_OPTIONS
            byte[] optionsBytes = BitConverter.GetBytes((uint)options);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(optionsBytes);
            }
            AsnElt optionsAsn = AsnElt.MakeBitString(optionsBytes);
            AsnElt optionsSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { optionsAsn });
            optionsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, optionsSeq);
            allNodes.Add(optionsSeq);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());
            //AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, seq);

            return seq;
        }

        public UInt32 nonce { get; set; }

        public PrincipalName cname { get; set; }

        public string crealm { get; set; }

        public Interop.PA_S4U_X509_USER_OPTIONS options { get; set; }
    }
}

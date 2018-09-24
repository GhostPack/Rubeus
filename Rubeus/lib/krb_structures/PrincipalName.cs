using Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Rubeus
{
    //PrincipalName::= SEQUENCE {
    //        name-type[0] Int32,
    //        name-string[1] SEQUENCE OF KerberosString
    //}

    public class PrincipalName
    {
        public PrincipalName()
        {
            // KRB_NT_PRINCIPAL = 1
            //      means just the name of the principal
            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)
            // KRB_NT_ENTERPRISE_PRINCIPAL = 10
            //      user@domain.com

            name_type = 1;
            
            name_string = new List<string>();
        }

        public PrincipalName(string principal)
        {
            // create with principal
            name_type = 1;

            name_string = new List<string>();
            name_string.Add(principal);
        }

        public PrincipalName(AsnElt body)
        {
            // KRB_NT_PRINCIPAL = 1
            //      means just the name of the principal
            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)

            name_type = body.Sub[0].Sub[0].GetInteger();

            int numberOfNames = body.Sub[1].Sub[0].Sub.Length;

            name_string = new List<string>();

            for (int i = 0; i < numberOfNames; i++)
            {
                name_string.Add(Encoding.ASCII.GetString(body.Sub[1].Sub[0].Sub[i].GetOctetString()));
            }
        }

        public AsnElt Encode()
        {
            // name-type[0] Int32
            AsnElt nameTypeElt = AsnElt.MakeInteger(name_type);
            AsnElt nameTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { nameTypeElt });
            nameTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, nameTypeSeq);


            // name-string[1] SEQUENCE OF KerberosString
            //  add in the name string sequence (one or more)
            AsnElt[] strings = new AsnElt[name_string.Count];

            for (int i = 0; i < name_string.Count; ++i)
            {
                string name = name_string[i];
                AsnElt nameStringElt = AsnElt.MakeString(AsnElt.IA5String, name);
                nameStringElt = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, nameStringElt);
                strings[i] = nameStringElt;
            }

            AsnElt stringSeq = AsnElt.Make(AsnElt.SEQUENCE, strings);
            AsnElt stringSeq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { stringSeq } );
            stringSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, stringSeq2);


            // build the final sequences
            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, new[] { nameTypeSeq, stringSeq2 });

            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, new[] { seq });

            return seq2;
        }

        public long name_type { get; set; }

        public List<string> name_string { get; set; }
    }
}
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
            /*
   Name Type       Value  Meaning

   NT-UNKNOWN        0    Name type not known
   NT-PRINCIPAL      1    Just the name of the principal as in DCE,
                            or for users
   NT-SRV-INST       2    Service and other unique instance (krbtgt)
   NT-SRV-HST        3    Service with host name as instance
                            (telnet, rcommands)
   NT-SRV-XHST       4    Service with host as remaining components
   NT-UID            5    Unique ID
   NT-X500-PRINCIPAL 6    Encoded X.509 Distinguished name [RFC2253]
   NT-SMTP-NAME      7    Name in form of SMTP email name
                            (e.g., user@example.com)
   NT-ENTERPRISE    10    Enterprise name - may be mapped to principal
                            name
             */

            name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;

            name_string = new List<string>();
        }

        public PrincipalName(string principal)
        {
            // create with principal
            name_type = Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;

            name_string = new List<string>();
            name_string.Add(principal);
        }

        public PrincipalName(AsnElt body)
        {
            // KRB_NT_PRINCIPAL = 1
            //      means just the name of the principal
            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)

            name_type = (Interop.PRINCIPAL_TYPE)body.Sub[0].Sub[0].GetInteger();

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
            AsnElt nameTypeElt = AsnElt.MakeInteger((long)name_type);
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

        public Interop.PRINCIPAL_TYPE name_type { get; set; }

        public List<string> name_string { get; set; }
    }
}
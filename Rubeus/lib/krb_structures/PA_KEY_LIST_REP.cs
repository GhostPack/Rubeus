using Asn1;
using System;
using System.Text;

namespace Rubeus
{
    public class PA_KEY_LIST_REP
    {
        // KERB-KEY-LIST-REP ::= SEQUENCE OF EncryptionKey
        public PA_KEY_LIST_REP()
        {
            encryptionKey = new EncryptionKey();
        }
        public PA_KEY_LIST_REP(AsnElt body)
        {
            encryptionKey = new EncryptionKey(body);
        }

        public AsnElt Encode()
        {
            AsnElt encryptionKeyAsn = encryptionKey.Encode();
            AsnElt encryptionKeySeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { encryptionKeyAsn });
            return encryptionKeySeq;
        }

        public EncryptionKey encryptionKey { get; set; }

    }
}
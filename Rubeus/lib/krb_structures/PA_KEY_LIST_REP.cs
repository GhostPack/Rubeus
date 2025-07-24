using Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus
{
    public class PA_KEY_LIST_REP
    {
        // KERB-KEY-LIST-REP ::= SEQUENCE OF EncryptionKey

        public PA_KEY_LIST_REP()
        {
            EncryptionKeys = new List<EncryptionKey>();
        }

        public PA_KEY_LIST_REP(AsnElt body)
        {
            if (body.TagValue != AsnElt.SEQUENCE)
                throw new ArgumentException("KERB-KEY-LIST-REP must be a SEQUENCE", nameof(body));

            EncryptionKeys = new List<EncryptionKey>(body.Sub.Length);
            foreach (var child in body.Sub)
            {
                EncryptionKeys.Add(new EncryptionKey(child));
            }
        }

        public AsnElt Encode()
        {
            var encodedKeys = EncryptionKeys
                .Select(key => key.Encode())
                .ToArray();

            return AsnElt.Make(AsnElt.SEQUENCE, encodedKeys);
        }

        public List<EncryptionKey> EncryptionKeys { get; set; }
    }
}
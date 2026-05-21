using System;
using System.Collections.Generic;
using System.Text;
using Asn1;

namespace Rubeus
{
    public class ETYPE_INFO_ENTRY
    {
        /*
        ETYPE-INFO-ENTRY::= SEQUENCE {
            etype       [0] Int32 -- EncryptionType --,
            salt        [1] OCTET STRING OPTIONAL,
            s2kparams   [2] OCTET STRING OPTIONAL
        }
        */

        public ETYPE_INFO_ENTRY(AsnElt body)
        {
            if (body == null)
            {
                return;
            }

            foreach (AsnElt child in GetChildren(body))
            {
                if (child == null)
                {
                    continue;
                }

                AsnElt content = GetContent(child);
                if (content == null)
                {
                    continue;
                }

                switch (child.TagValue)
                {
                    case 0:
                        try
                        {
                            etype = Convert.ToInt32(GetInteger(content));
                        }
                        catch { }
                        break;
                    case 1:
                        salt = GetStringValue(content);
                        break;
                    default:
                        break;
                }
            }
        }

        public Int32 etype { get; set; }

        public string salt { get; set; }

        private static IEnumerable<AsnElt> GetChildren(AsnElt body)
        {
            if (body.Sub == null)
            {
                yield break;
            }

            if (body.Sub.Length == 1 && body.Sub[0].TagClass == AsnElt.UNIVERSAL && body.Sub[0].TagValue == AsnElt.SEQUENCE)
            {
                foreach (var sub in body.Sub[0].Sub)
                {
                    yield return sub;
                }
            }
            else
            {
                foreach (var sub in body.Sub)
                {
                    yield return sub;
                }
            }
        }

        private static AsnElt GetContent(AsnElt element)
        {
            if (element.Sub != null && element.Sub.Length > 0 && element.TagClass == AsnElt.CONTEXT)
            {
                return element.Sub[0];
            }
            return element;
        }

        private static long GetInteger(AsnElt element)
        {
            if (element == null)
            {
                throw new InvalidOperationException();
            }
            if (!element.Constructed || element.TagClass == AsnElt.UNIVERSAL)
            {
                return element.GetInteger();
            }
            foreach (var sub in element.Sub)
            {
                try
                {
                    return sub.GetInteger();
                }
                catch { }
            }
            throw new InvalidOperationException();
        }

        private static string GetStringValue(AsnElt element)
        {
            if (element == null)
            {
                return null;
            }

            try
            {
                if (element.TagClass == AsnElt.UNIVERSAL)
                {
                    return element.GetString();
                }
            }
            catch { }

            if (element.Sub != null && element.Sub.Length > 0)
            {
                foreach (var sub in element.Sub)
                {
                    string result = GetStringValue(sub);
                    if (!string.IsNullOrEmpty(result))
                    {
                        return result;
                    }
                }
            }

            try
            {
                return Encoding.UTF8.GetString(element.GetOctetString());
            }
            catch { }

            return null;
        }
    }
}


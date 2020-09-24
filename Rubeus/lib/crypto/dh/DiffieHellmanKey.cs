// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Asn1;
using Rubeus.Asn1;

namespace Kerberos.NET.Crypto
{
    public enum AsymmetricKeyType {
        Public,
        Private
    }

    public class DiffieHellmanKey : IExchangeKey
    {
        public AsymmetricKeyType Type { get; set; }

        public KeyAgreementAlgorithm Algorithm { get; set; }

        public DateTimeOffset? CacheExpiry { get; set; }

        public int KeyLength { get; set; }

        public byte[] Modulus { get; set; }

        public byte[] Generator { get; set; }

        public byte[] Factor { get; set; }

        public byte[] PublicComponent { get; set; }

        public byte[] PrivateComponent { get; set; }

        public byte[] EncodePublicKey()            
        {
            return AsnElt.MakeInteger(this.PublicComponent).Encode();
        }

        public static DiffieHellmanKey ParsePublicKey(byte[] data, int keyLength)
        {
            AsnElt publicKeyAsn = AsnElt.Decode(data); 
            
            if(publicKeyAsn.TagValue != AsnElt.INTEGER) {
                throw new ArgumentException("data doesn't appear to be an ASN.1 encoded INTERGER");
            }

            return new DiffieHellmanKey { PublicComponent = publicKeyAsn.GetOctetString().DepadLeft().PadRight(keyLength) };
        }
    }
}
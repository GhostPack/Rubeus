
// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------
//
// CCob (@_EthicalChaos_) -     Updated slightly from original Kerberos.NET version to use BigInteger
//                              from Mono library and not .NET, since System.Numerics is only available
//                              since .NET 4.0+.  Also switched to raw byte arrays for .NET 2.0+ compatibility.   
//                              Mono's internal representation of data is in also in big endian format
//                              so this class had to be updated to reflect that as .NET's BigInteger is little endian.
//                              We are not particular bothered about security correctness of using ManagedDiffieHellman
//                              as long as we can use it to calculate a valid shared secret from the KDC.
//

using Mono.Math;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto {
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // DO NOT USE THIS
    //
    // THIS IS NOT PRODUCTION-WORTHY CODE
    // IT IS UNSAFE AND UNTESTED
    //
    // DO NOT USE THIS
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /// <summary>
    /// DO NOT USE THIS
    ///
    /// THIS IS NOT PRODUCTION-WORTHY CODE
    /// IT IS UNSAFE AND UNTESTED
    ///
    /// DO NOT USE THIS
    /// </summary>
    public abstract class ManagedDiffieHellman : IKeyAgreement
    {
        private readonly int keyLength;

        private readonly BigInteger prime;
        private readonly BigInteger generator;
        private readonly BigInteger factor;
        private readonly BigInteger x;

        private readonly BigInteger y;

        private BigInteger partnerKey;
        private bool disposedValue;

        public ManagedDiffieHellman(byte[] prime, byte[] generator, byte[] factor)
        {
            keyLength = prime.Length;

            this.prime = ParseBigInteger(prime);
            this.generator = ParseBigInteger(generator);
            this.factor = ParseBigInteger(factor);

            x = GeneratePrime();

            y = this.generator.ModPow(x, this.prime);

            PublicKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Public,
                Generator = Depad(this.generator.GetBytes()),
                Modulus = Depad(this.prime.GetBytes()),
                PublicComponent = Depad(y.GetBytes()),
                Factor = Depad(this.factor.GetBytes()),
                KeyLength = prime.Length
            };

            PrivateKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Private,
                Generator = Depad(this.generator.GetBytes()),
                Modulus = Depad(this.prime.GetBytes()),
                PublicComponent = Depad(y.GetBytes()),
                Factor = Depad(this.factor.GetBytes()),
                PrivateComponent = Depad(x.GetBytes()),
                KeyLength = prime.Length
            };
        }

        private BigInteger GeneratePrime()
        {
            // RSA's P and Q parameters are prime, but len(P+Q) = keylength
            // so generate an RSA key twice as large as required and just
            // use P as the prime.

            // P in RSA is a safer prime than primes used in DH so it's
            // good enough here, though it's costlier to generate.

            using (var alg = new RSACryptoServiceProvider(keyLength * 2 * 8))
            {
                var rsa = alg.ExportParameters(true);

                return ParseBigInteger(rsa.P.Reverse().ToArray());
            }
        }

        private static BigInteger ParseBigInteger(byte[] arr)
        {
            var pv = arr;

            if (pv[0] != 0)
            {
                var copy = new byte[pv.Length + 1];

                pv.CopyTo(copy, 1);

                pv = copy;
            }

            return new BigInteger(pv);
        }

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        public byte[] GenerateAgreement()
        {
            var z = partnerKey.ModPow(x, prime);

            var ag = z.GetBytes().ToArray();

            var agreement = Depad(ag);

            agreement = Pad(agreement, keyLength);

            return agreement;
        }

        public void ImportPartnerKey(IExchangeKey publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            partnerKey = ParseBigInteger(publicKey.PublicComponent);
        }

        private byte[] Depad(byte[] data)
        {
            int leadingZeros;

            for(leadingZeros = 0; leadingZeros < data.Length; ++leadingZeros) {                
                if(!(data[leadingZeros] == 0 && data.Length > keyLength)) {
                    break;
                }
            }

            byte[] result = new byte[data.Length - leadingZeros];

            Array.Copy(data, leadingZeros, result, 0, result.Length);

            return result;
        }

        private static byte[] Pad(byte[] agreement, int keyLength)
        {
            var copy = new byte[keyLength];

            agreement.CopyTo(copy, keyLength - agreement.Length);

            return copy;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
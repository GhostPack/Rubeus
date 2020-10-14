// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    public enum KeyAgreementAlgorithm
    {
        None = 0,
        DiffieHellmanModp2,
        DiffieHellmanModp14,
        EllipticCurveDiffieHellmanP256,
        EllipticCurveDiffieHellmanP384,
        EllipticCurveDiffieHellmanP521,
    }
}
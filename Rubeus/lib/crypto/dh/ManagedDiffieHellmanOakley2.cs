// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    public class ManagedDiffieHellmanOakley2 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakley2()
            : base(Oakley.Group2.Prime, Oakley.Group2.Generator, Oakley.Group2.Factor)
        {
        }
    }
}
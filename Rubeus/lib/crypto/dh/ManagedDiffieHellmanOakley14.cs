// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    public class ManagedDiffieHellmanOakley14 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakley14()
            : base(Oakley.Group14.Prime, Oakley.Group14.Generator, Oakley.Group14.Factor)
        {
        }
    }
}
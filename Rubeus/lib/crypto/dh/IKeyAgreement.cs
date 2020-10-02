// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public interface IKeyAgreement : IDisposable
    {
        IExchangeKey PublicKey { get; }

        IExchangeKey PrivateKey { get; }

        byte[] GenerateAgreement();

        void ImportPartnerKey(IExchangeKey publicKey);
    }
}
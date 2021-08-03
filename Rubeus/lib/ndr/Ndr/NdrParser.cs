//  Copyright 2018 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using Rubeus.Utilities.Memory;
using Rubeus.Win32;
//using NtApiDotNet.Win32.Debugger;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace Rubeus.Ndr
{
#pragma warning disable 1591
    [Flags]
    [Serializable]
    public enum NdrInterpreterOptFlags : byte
    {
        ServerMustSize = 0x01,
        ClientMustSize = 0x02,
        HasReturn = 0x04,
        HasPipes = 0x08,
        HasAsyncUuid = 0x20,
        HasExtensions = 0x40,
        HasAsyncHandle = 0x80,
    }

    [Flags]
    [Serializable]
    public enum NdrInterpreterOptFlags2 : byte
    {
        HasNewCorrDesc = 0x01,
        ClientCorrCheck = 0x02,
        ServerCorrCheck = 0x04,
        HasNotify = 0x08,
        HasNotify2 = 0x10,
        HasComplexReturn = 0x20,
        HasRangeOnConformance = 0x40,
        HasBigByValParam = 0x80,
        Valid = HasNewCorrDesc | ClientCorrCheck | ServerCorrCheck | HasNotify | HasNotify2 | HasRangeOnConformance
    }

#pragma warning restore 1591



    /// <summary>
    /// Flags for the parser.
    /// </summary>
    [Flags]
    public enum NdrParserFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// Ignore processing any complex user marshal types.
        /// </summary>
        IgnoreUserMarshal = 1,
    }

   
}

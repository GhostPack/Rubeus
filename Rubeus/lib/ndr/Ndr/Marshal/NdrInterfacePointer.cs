//  Copyright 2019 Google Inc. All Rights Reserved.
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

using Rubeus.Win32.Rpc;

namespace Rubeus.Ndr.Marshal
{
    /// <summary>
    /// Class to represent an NDR interface pointer.
    /// </summary>
    public struct NdrInterfacePointer : INdrConformantStructure
    {
        /// <summary>
        /// The marshaled interface data.
        /// </summary>
        public byte[] Data { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">The marshaled interface data.</param>
        public NdrInterfacePointer(byte[] data)
        {
            Data = data;
        }

        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }

        void INdrStructure.Marshal(NdrMarshalBuffer marshal)
        {
            RpcUtils.CheckNull(Data, "Data");
            marshal.WriteInt32(Data.Length);
            marshal.WriteConformantByteArray(Data, Data.Length);
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer unmarshal)
        {
            unmarshal.ReadInt32(); // length.
            Data = unmarshal.ReadConformantByteArray();
        }

        int INdrStructure.GetAlignment()
        {
            return 4;
        }
    }
}

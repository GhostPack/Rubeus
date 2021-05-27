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

using System;
using System.IO;
using Rubeus.Win32.Rpc;

namespace Rubeus.Ndr.Marshal
{
    /// <summary>
    /// Represents an NDR pickled type.
    /// </summary>
    public class NdrPickledType
    {
        /// <summary>
        /// Constructor from a type 1 serialized buffer.
        /// </summary>
        /// <param name="encoded">The type 1 serialized encoded buffer.</param>
        public NdrPickledType(byte[] encoded)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(encoded));
            if (reader.ReadByte() != 1)
            {
                throw new ArgumentException("Only support version 1 serialization");
            }
            if (reader.ReadByte() != 0x10)
            {
                throw new ArgumentException("Only support little-endian NDR data.");
            }
            if (reader.ReadInt16() != 8)
            {
                throw new ArgumentException("Unexpected header length");
            }
            // Padding.
            reader.ReadInt32();
            int length = reader.ReadInt32();
            // Padding.
            reader.ReadInt32();
            Data = reader.ReadAllBytes(length);
            DataRepresentation = new NdrDataRepresentation()
            {
                IntegerRepresentation =  NdrIntegerRepresentation.LittleEndian,
                CharacterRepresentation = NdrCharacterRepresentation.ASCII,
                FloatingPointRepresentation = NdrFloatingPointRepresentation.IEEE
            };
        }

        internal NdrPickledType(byte[] data, NdrDataRepresentation data_representation)
        {
            DataRepresentation = data_representation;
            if (DataRepresentation.CharacterRepresentation != NdrCharacterRepresentation.ASCII ||
                DataRepresentation.FloatingPointRepresentation != NdrFloatingPointRepresentation.IEEE)
            {
                throw new ArgumentException("Invalid data representation for type 1 serialized buffer");
            }
            Data = data;
        }

        internal byte[] Data { get; }

        internal NdrDataRepresentation DataRepresentation { get; }

        /// <summary>
        /// Convert the pickled type to a type 1 serialized encoded buffer.
        /// </summary>
        /// <returns>The type 1 serialized encoded buffer.</returns>
        public byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);

            writer.Write((byte)1);
            writer.Write((byte)(DataRepresentation.IntegerRepresentation == NdrIntegerRepresentation.LittleEndian ? 0x10 : 0));
            writer.Write((short)8);
            writer.Write(0xCCCCCCCCU);

            writer.Write(Data.Length);
            writer.Write(0);
            writer.Write(Data);
            return stm.ToArray();
        }
    }
}

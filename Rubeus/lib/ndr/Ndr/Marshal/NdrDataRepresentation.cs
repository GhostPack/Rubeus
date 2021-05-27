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

namespace Rubeus.Ndr.Marshal
{
#pragma warning disable 1591
    /// <summary>
    /// NDR integer representation.
    /// </summary>
    public enum NdrIntegerRepresentation
    {
        LittleEndian,
        BigEndian
    }

    /// <summary>
    /// NDR character representation.
    /// </summary>
    public enum NdrCharacterRepresentation
    {
        ASCII,
        EBCDIC
    }

    /// <summary>
    /// NDR floating point representation.
    /// </summary>
    public enum NdrFloatingPointRepresentation
    {
        IEEE,
        VAX,
        Cray,
        IBM
    }

    /// <summary>
    /// Definition of the NDR data representation for an NDR stream.
    /// </summary>
    public struct NdrDataRepresentation
    {
        /// <summary>
        /// The integer representation of the NDR data.
        /// </summary>
        public NdrIntegerRepresentation IntegerRepresentation { get; set; }
        /// <summary>
        /// The character representation of the NDR data.
        /// </summary>
        public NdrCharacterRepresentation CharacterRepresentation { get; set; }
        /// <summary>
        /// The floating representation of the NDR data.
        /// </summary>
        public NdrFloatingPointRepresentation FloatingPointRepresentation { get; set; }
    }
#pragma warning restore 1591
}

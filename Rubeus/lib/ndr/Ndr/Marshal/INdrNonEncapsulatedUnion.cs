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
    /// <summary>
    /// Interface for a marshalled non-encapsulated NDR union.
    /// </summary>
    /// <remarks>This interface is primarily for internal use only.</remarks>
    public interface INdrNonEncapsulatedUnion : INdrStructure
    {
        /// <summary>
        /// Marshal the union to a stream.
        /// </summary>
        /// <param name="selector">The selector for union arm.</param>
        /// <param name="marshal">The marshal stream.</param>
        void Marshal(NdrMarshalBuffer marshal, long selector);
    }
}

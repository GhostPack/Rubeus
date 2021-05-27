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

namespace Rubeus.Ndr.Marshal
{
    /// <summary>
    /// Structure to represent a context handle.
    /// </summary>
    public struct NdrContextHandle
    {
        /// <summary>
        /// Context handle attributes.
        /// </summary>
        public int Attributes { get; }

        /// <summary>
        /// Context handle UUID.
        /// </summary>
        public Guid Uuid { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="attributes">Context handle attributes.</param>
        /// <param name="uuid">Context handle UUID.</param>
        public NdrContextHandle(int attributes, Guid uuid)
        {
            Attributes = attributes;
            Uuid = uuid;
        }

        /// <summary>
        /// Overidden ToString method.
        /// </summary>
        /// <returns>The handle as string.</returns>
        public override string ToString()
        {
            return $"Handle: {Uuid} - Attributes: {Attributes}";
        }
    }
}

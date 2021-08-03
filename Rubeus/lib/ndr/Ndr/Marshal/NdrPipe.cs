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
    /// Placeholder for a NDR pipe type.
    /// </summary>
    /// <typeparam name="T">The base type of pipe blocks.</typeparam>
    public class NdrPipe<T> where T : struct
    {
        /// <summary>
        /// Pull a block from a pipe.
        /// </summary>
        /// <param name="count">The maximum number of elements to pull.</param>
        /// <returns>The pulled block.</returns>
        public T[] Pull(int count)
        {
            throw new NotImplementedException("Pipe support not implemented");
        }

        /// <summary>
        /// Push a block to a pipe.
        /// </summary>
        /// <param name="data">The block to push.</param>
        public void Push(T[] data)
        {
            throw new NotImplementedException("Pipe support not implemented");
        }
    }
}

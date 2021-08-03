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
    /// A class which represents an embedded pointer.
    /// </summary>
    /// <typeparam name="T">The underlying type.</typeparam>
    public class NdrEmbeddedPointer<T>
    {
        private T _value;

        private NdrEmbeddedPointer(T value)
        {
            _value = value;
        }

        /// <summary>
        /// Operator to convert from a value to an embedded pointer.
        /// </summary>
        /// <param name="value">The value to point to.</param>
        public static implicit operator NdrEmbeddedPointer<T>(T value)
        {
            return new NdrEmbeddedPointer<T>(value);
        }

        /// <summary>
        /// Operator to convert from an embedded pointer to a value.
        /// </summary>
        /// <param name="pointer">The embedded pointer.</param>
        public static implicit operator T (NdrEmbeddedPointer<T> pointer)
        {
            if (pointer == null)
            {
                return default;
            }
            return pointer._value;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The string form of the value.</returns>
        public override string ToString()
        {
            return _value.ToString();
        }

        /// <summary>
        /// Get the value from the embedded pointer.
        /// </summary>
        /// <returns>The value of the pointer.</returns>
        public T GetValue()
        {
            return _value;
        }

        internal static Tuple<NdrEmbeddedPointer<T>, Action> CreateDeferredReader(Func<T> unmarshal_func)
        {
            NdrEmbeddedPointer<T> ret = new NdrEmbeddedPointer<T>(default);
            return Tuple.Create(ret, new Action(() => ret._value = unmarshal_func()));
        }

        internal static Tuple<NdrEmbeddedPointer<T>, Action> CreateDeferredReader<U>(Func<U, T> unmarshal_func, U arg)
        {
            NdrEmbeddedPointer<T> ret = new NdrEmbeddedPointer<T>(default);
            return Tuple.Create(ret, new Action(() => ret._value = unmarshal_func(arg)));
        }

        internal static Tuple<NdrEmbeddedPointer<T>, Action> CreateDeferredReader<U, V>(Func<U, V, T> unmarshal_func, U arg, V arg2)
        {
            NdrEmbeddedPointer<T> ret = new NdrEmbeddedPointer<T>(default);
            return Tuple.Create(ret, new Action(() => ret._value = unmarshal_func(arg, arg2)));
        }
    }
}

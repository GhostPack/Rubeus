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
    /// Structure which represents an NDR FC_INT3264
    /// </summary>
    public struct NdrInt3264 : IFormattable
    {
        /// <summary>
        /// Value of the structure.
        /// </summary>
        public readonly int Value;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public NdrInt3264(int value) 
        {
            Value = value;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public NdrInt3264(IntPtr value)
        {
            Value = (int)value.ToInt64();
        }

        /// <summary>
        /// Convert to a native IntPtr.
        /// </summary>
        /// <param name="i">The value to convert from.</param>
        public static implicit operator IntPtr(NdrInt3264 i)
        {
            return new IntPtr(i.Value);
        }

        /// <summary>
        /// Overridden ToString.
        /// </summary>
        /// <returns>The value as a string.</returns>
        public override string ToString()
        {
            return Value.ToString();
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <param name="format">The formatting string.</param>
        /// <returns>The value as a string.</returns>
        public string ToString(string format)
        {
            return Value.ToString(format);
        }

        /// <summary>
        /// IFormattable ToString.
        /// </summary>
        /// <param name="format">The formatting string.</param>
        /// <param name="formatProvider">Formatting provider.</param>
        /// <returns>The value as a string.</returns>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            return Value.ToString(format, formatProvider);
        }
    }

    /// <summary>
    /// Structure which represents an NDR FC_UINT3264
    /// </summary>
    public struct NdrUInt3264 : IFormattable
    {
        /// <summary>
        /// Value of the structure.
        /// </summary>
        public readonly uint Value;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public NdrUInt3264(uint value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public NdrUInt3264(int value) 
            : this((uint)value)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public NdrUInt3264(IntPtr value)
        {
            Value = (uint)(value.ToInt64() & uint.MaxValue);
        }

        /// <summary>
        /// Convert to a native IntPtr.
        /// </summary>
        /// <param name="i">The value to convert from.</param>
        public static implicit operator IntPtr(NdrUInt3264 i)
        {
            if (IntPtr.Size == 8)
            {
                return new IntPtr(i.Value);
            }
            return new IntPtr((int)i.Value);
        }

        /// <summary>
        /// Overridden ToString.
        /// </summary>
        /// <returns>The value as a string.</returns>
        public override string ToString()
        {
            return Value.ToString();
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <param name="format">The formatting string.</param>
        /// <returns>The value as a string.</returns>
        public string ToString(string format)
        {
            return Value.ToString(format);
        }

        /// <summary>
        /// IFormattable ToString.
        /// </summary>
        /// <param name="format">The formatting string.</param>
        /// <param name="formatProvider">Formatting provider.</param>
        /// <returns>The value as a string.</returns>
        public string ToString(string format, IFormatProvider formatProvider)
        {
            return Value.ToString(format, formatProvider);
        }
    }
}

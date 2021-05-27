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
    /// Class to represent a 16 bit enumerated type.
    /// </summary>
    public struct NdrEnum16 : IFormattable, IEquatable<NdrEnum16>
    {
        /// <summary>
        /// Value of the structure.
        /// </summary>
        public readonly int Value;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value"></param>
        public NdrEnum16(int value)
        {
            Value = value;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public static implicit operator NdrEnum16(int value)
        {
            return new NdrEnum16(value);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public static implicit operator int(NdrEnum16 value)
        {
            return value.Value;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public static explicit operator NdrEnum16(uint value)
        {
            return new NdrEnum16((int)value);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public static explicit operator long(NdrEnum16 value)
        {
            return value.Value;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public static explicit operator NdrEnum16(long value)
        {
            return new NdrEnum16((int)value);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public static explicit operator NdrEnum16(Enum value)
        {
            Type enum_type = value.GetType().GetEnumUnderlyingType();
            if (enum_type == typeof(uint))
            {
                return (NdrEnum16)Convert.ToUInt32(value);
            }
            return new NdrEnum16(Convert.ToInt32(value));
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The value to construct from.</param>
        public static explicit operator uint(NdrEnum16 value)
        {
            return (uint)value.Value;
        }

        /// <summary>
        /// Equality operator.
        /// </summary>
        /// <param name="left">The left value.</param>
        /// <param name="right">The right value.</param>
        /// <returns>True if the values are equal.</returns>
        public static bool operator ==(NdrEnum16 left, NdrEnum16 right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Inequality operator.
        /// </summary>
        /// <param name="left">The left value.</param>
        /// <param name="right">The right value.</param>
        /// <returns>True if the values are not-equal.</returns>
        public static bool operator !=(NdrEnum16 left, NdrEnum16 right)
        {
            return !left.Equals(right);
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

        /// <summary>
        /// Equals operator.
        /// </summary>
        /// <param name="other">The other enum16.</param>
        /// <returns>True if the values are equal.</returns>
        public bool Equals(NdrEnum16 other)
        {
            return Value == other.Value;
        }

        /// <summary>
        /// Compare 
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj is NdrEnum16 e)
            {
                return Equals(e);
            }
            return false;
        }

        /// <summary>
        /// Overridden GetHashCode.
        /// </summary>
        /// <returns>The hash code of the enumeration.</returns>
        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }
    }
}

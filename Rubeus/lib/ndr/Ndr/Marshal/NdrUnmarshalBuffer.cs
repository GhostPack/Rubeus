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

using Rubeus.Utilities.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Rubeus.Ndr.Marshal
{
#pragma warning disable 1591
    /// <summary>
    /// A buffer to unmarshal NDR data from.
    /// </summary>
    /// <remarks>This class is primarily for internal use only.</remarks>
    public class NdrUnmarshalBuffer : IDisposable
    {
        #region Private Members

        private readonly MemoryStream _stm;
        private readonly BinaryReader _reader;
        private NdrDeferralStack _deferred_reads;
        private int[] _conformance_values;
        private Dictionary<int, object> _full_pointers;

        private string[] ReadStringArray(int[] refs, Func<string> reader)
        {
            string[] ret = new string[refs.Length];
            for (int i = 0; i < refs.Length; ++i)
            {
                if (refs[i] == 0)
                {
                    ret[i] = string.Empty;
                }
                else
                {
                    int pos = i;
                    _deferred_reads.Add(() => ret[pos] = reader());
                }
            }
            return ret;
        }

        private bool SetupConformance(int dimensions)
        {
            if (_conformance_values == null)
            {
                _conformance_values = new int[dimensions];
                for (int i = 0; i < dimensions; ++i)
                {
                    _conformance_values[i] = ReadInt32();
                }
                return true;
            }
            return false;
        }

        private int[] ReadConformance(int dimensions)
        {
            int[] ret;
            if (_conformance_values != null)
            {
                System.Diagnostics.Debug.Assert(_conformance_values.Length == dimensions);
                ret = _conformance_values;
                _conformance_values = null;
            }
            else
            {
                ret = new int[dimensions];
                for (int i = 0; i < dimensions; ++i)
                {
                    ret[i] = ReadInt32();
                }
            }
            return ret;
        }

        private T ReadFullPointer<T>(int referent, Func<T> unmarshal_func)
        {
            if (!_full_pointers.ContainsKey(referent))
            {
                _full_pointers[referent] = unmarshal_func();
            }

            return (T)_full_pointers[referent];
        }

        private T ReadStructInternal<T>() where T : new()
        {
            INdrStructure s = (INdrStructure)new T();
            Align(s.GetAlignment());
            s.Unmarshal(this);
            return (T)s;
        }

        private void Align(int alignment)
        {
            _stm.Position += NdrNativeUtils.CalculateAlignment((int)_stm.Position, alignment);
            System.Diagnostics.Debug.WriteLine($"Pos: {_stm.Position} - Align: {alignment}");
        }

        #endregion

        #region Constructors
        public NdrUnmarshalBuffer(byte[] buffer, NdrDataRepresentation data_represenation)
        {
            _stm = new MemoryStream(buffer);
            _reader = new BinaryReader(_stm, Encoding.Unicode);
            _deferred_reads = new NdrDeferralStack();
            _full_pointers = new Dictionary<int, object>();
            CheckDataRepresentation(data_represenation);
        }
        public NdrUnmarshalBuffer(byte[] buffer) 
            : this(buffer,  new NdrDataRepresentation())
        {
        }

 
        public NdrUnmarshalBuffer(NdrPickledType pickled_type) 
            : this(pickled_type.Data, pickled_type.DataRepresentation)
        {
        }

        #endregion

        #region Misc Methods

        public NdrContextHandle ReadContextHandle()
        {
            int attributes = ReadInt32();
            Guid uuid = ReadGuid();
            return new NdrContextHandle(attributes, uuid);
        }

        public NdrUnsupported ReadUnsupported(string name)
        {
            throw new NotImplementedException($"Reading type {name} is unsupported");
        }

        public NdrEmpty ReadEmpty()
        {
            return new NdrEmpty();
        }

        public NdrInterfacePointer ReadInterfacePointer()
        {
            return ReadStruct<NdrInterfacePointer>();
        }

        public NdrPipe<T> ReadPipe<T>() where T : struct
        {
            throw new NotImplementedException("Pipe support is not implemented");
        }

        internal static void CheckDataRepresentation(NdrDataRepresentation data_represenation)
        {
            if (data_represenation.IntegerRepresentation != NdrIntegerRepresentation.LittleEndian ||
                data_represenation.FloatingPointRepresentation != NdrFloatingPointRepresentation.IEEE ||
                data_represenation.CharacterRepresentation != NdrCharacterRepresentation.ASCII)
            {
                throw new ArgumentException("Unsupported NDR data representation");
            }
        }

        #endregion

        #region Primitive Types

        public byte ReadByte()
        {
            return _reader.ReadByte();
        }

        public sbyte ReadSByte()
        {
            return _reader.ReadSByte();
        }

        public short ReadInt16()
        {
            Align(2);
            return _reader.ReadInt16();
        }

        public ushort ReadUInt16()
        {
            Align(2);
            return _reader.ReadUInt16();
        }

        public int ReadInt32()
        {
            Align(4);
            return _reader.ReadInt32();
        }

        public uint ReadUInt32()
        {
            Align(4);
            return _reader.ReadUInt32();
        }

        public long ReadInt64()
        {
            Align(8);
            return _reader.ReadInt64();
        }

        public ulong ReadUInt64()
        {
            Align(8);
            return _reader.ReadUInt64();
        }

        public float ReadFloat()
        {
            Align(4);
            return _reader.ReadSingle();
        }

        public NdrInt3264 ReadInt3264()
        {
            return new NdrInt3264(ReadInt32());
        }

        public NdrUInt3264 ReadUInt3264()
        {
            return new NdrUInt3264(ReadUInt32());
        }

        public double ReadDouble()
        {
            Align(8);
            return _reader.ReadDouble();
        }

        public char ReadChar()
        {
            Align(2);
            return _reader.ReadChar();
        }

        public NdrEnum16 ReadEnum16()
        {
            return ReadInt16();
        }

        #endregion

        #region Fixed Array Types

        public byte[] ReadFixedByteArray(int count)
        {
            byte[] ret = _reader.ReadBytes(count);
            if (ret.Length < count)
            {
                throw new EndOfStreamException();
            }
            return ret;
        }

        public char[] ReadFixedCharArray(int count)
        {
            char[] chars = _reader.ReadChars(count);
            if (chars.Length < count)
            {
                throw new EndOfStreamException();
            }
            return chars;
        }

        public T[] ReadFixedPrimitiveArray<T>(int actual_count) where T : struct
        {
            int size = NdrNativeUtils.GetPrimitiveTypeSize<T>();
            Align(size);
            byte[] total_buffer = ReadFixedByteArray(size * actual_count);
            T[] ret = new T[actual_count];
            Buffer.BlockCopy(total_buffer, 0, ret, 0, total_buffer.Length);
            return ret;
        }

        public T[] ReadFixedArray<T>(Func<T> reader, int actual_count)
        {
            T[] ret = new T[actual_count];
            for (int i = 0; i < actual_count; ++i)
            {
                ret[i] = reader();
            }
            return ret;
        }

        public T[] ReadFixedStructArray<T>(int actual_count) where T : INdrStructure, new()
        {
            using (var queue = _deferred_reads.Push())
            {
                return ReadFixedArray(ReadStruct<T>, actual_count);
            }
        }

        #endregion

        #region Conformant Array Types

        public byte[] ReadConformantByteArray()
        {
            int max_count = ReadConformance(1)[0];
            return ReadFixedByteArray(max_count);
        }

        public char[] ReadConformantCharArray()
        {
            int max_count = ReadConformance(1)[0];
            return ReadFixedCharArray(max_count);
        }

        public T[] ReadConformantPrimitiveArray<T>() where T : struct
        {
            int max_count = ReadConformance(1)[0];
            return ReadFixedPrimitiveArray<T>(max_count);
        }

        public T[] ReadConformantArrayCallback<T>(Func<T> reader)
        {
            int max_count = ReadConformance(1)[0];
            T[] ret = new T[max_count];
            for (int i = 0; i < max_count; ++i)
            {
                ret[i] = reader();
            }
            return ret;
        }

        public T[] ReadConformantStructArray<T>() where T : INdrStructure, new()
        {
            using (var queue = _deferred_reads.Push())
            {
                return ReadConformantArrayCallback(() => ReadStructInternal<T>());
            }
        }

        public string[] ReadConformantStringArray(Func<string> reader)
        {
            using (var queue = _deferred_reads.Push())
            {
                return ReadStringArray(ReadConformantArrayCallback(ReadInt32), reader);
            }
        }

        public T[] ReadConformantArray<T>() where T : struct
        {
            if (typeof(T) == typeof(byte))
            {
                return ReadConformantByteArray().Cast<byte, T>();
            }
            else if (typeof(T) == typeof(char))
            {
                return ReadConformantCharArray().Cast<char, T>();
            }
            else if (typeof(T) == typeof(INdrStructure))
            {
                using (var queue = _deferred_reads.Push())
                {
                    return ReadConformantArrayCallback(ReadStructInternal<T>);
                }
            }
            else if (typeof(T).IsPrimitive)
            {
                return ReadConformantPrimitiveArray<T>();
            }
            throw new ArgumentException($"Invalid type {typeof(T)} for {nameof(ReadConformantArray)}");
        }

        #endregion

        #region Varying Array Types

        public byte[] ReadVaryingByteArray()
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            byte[] ret = new byte[offset + actual_count];
            if (_stm.Read(ret, offset, actual_count) != actual_count)
            {
                throw new EndOfStreamException();
            }

            return ret;
        }

        public char[] ReadVaryingCharArray()
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            if (offset == 0)
            {
                return ReadFixedCharArray(actual_count);
            }

            char[] tmp = ReadFixedCharArray(actual_count);
            char[] ret = new char[offset + actual_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadVaryingPrimitiveArray<T>() where T : struct
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            T[] tmp = ReadFixedPrimitiveArray<T>(actual_count);
            T[] ret = new T[offset + actual_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadVaryingArrayCallback<T>(Func<T> reader)
        {
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            T[] ret = new T[offset + actual_count];
            for (int i = 0; i < actual_count; ++i)
            {
                ret[i + offset] = reader();
            }
            return ret;
        }

        public T[] ReadVaryingStructArray<T>() where T : INdrStructure, new()
        {
            using (var queue = _deferred_reads.Push())
            {
                return ReadVaryingArrayCallback(ReadStruct<T>);
            }
        }

        public string[] ReadVaryingStringArray(Func<string> reader)
        {
            using (var queue = _deferred_reads.Push())
            {
                return ReadStringArray(ReadVaryingArrayCallback(ReadInt32), reader);
            }
        }

        public T[] ReadVaryingArray<T>() where T : struct
        {
            if (typeof(T) == typeof(byte))
            {
                return ReadVaryingByteArray().Cast<byte, T>();
            }
            else if (typeof(T) == typeof(char))
            {
                return ReadVaryingCharArray().Cast<char, T>();
            }
            else if (typeof(T) == typeof(INdrStructure))
            {
                using (var queue = _deferred_reads.Push())
                {
                    return ReadVaryingArrayCallback(ReadStructInternal<T>);
                }
            }
            else if (typeof(T).IsPrimitive)
            {
                return ReadVaryingPrimitiveArray<T>();
            }
            throw new ArgumentException($"Invalid type {typeof(T)} for {nameof(ReadVaryingArray)}");
        }

        #endregion

        #region Conformant Varying Array Types

        public byte[] ReadConformantVaryingByteArray()
        {
            int max_count = ReadConformance(1)[0];
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            byte[] ret = new byte[max_count];
            if (_stm.Read(ret, offset, actual_count) != actual_count)
            {
                throw new EndOfStreamException();
            }

            return ret;
        }

        public char[] ReadConformantVaryingCharArray()
        {
            int max_count = ReadConformance(1)[0];
            int offset = ReadInt32();
            int actual_count = ReadInt32();

            char[] tmp = ReadFixedCharArray(actual_count);

            if (max_count == actual_count && offset == 0)
            {
                return tmp;
            }

            char[] ret = new char[max_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadConformantVaryingPrimitiveArray<T>() where T : struct
        {
            int max_count = ReadConformance(1)[0];
            int offset = ReadInt32();
            int actual_count = ReadInt32();

            T[] tmp = ReadFixedPrimitiveArray<T>(actual_count);
            if (max_count == actual_count && offset == 0)
            {
                return tmp;
            }

            T[] ret = new T[max_count];
            Array.Copy(tmp, 0, ret, offset, actual_count);
            return ret;
        }

        public T[] ReadConformantVaryingArrayCallback<T>(Func<T> reader)
        {
            int max_count = ReadConformance(1)[0];
            int offset = ReadInt32();
            int actual_count = ReadInt32();
            T[] ret = new T[offset + actual_count];
            for (int i = 0; i < actual_count; ++i)
            {
                ret[i + offset] = reader();
            }
            return ret;
        }

        public T[] ReadConformantVaryingStructArray<T>() where T : INdrStructure, new()
        {
            using (var queue = _deferred_reads.Push())
            {
                return ReadConformantVaryingArrayCallback(ReadStructInternal<T>);
            }
        }

        public string[] ReadConformantVaryingStringArray(Func<string> reader)
        {
            using (var queue = _deferred_reads.Push())
            {
                return ReadStringArray(ReadConformantVaryingArrayCallback(ReadInt32), reader);
            }
        }

        public T[] ReadConformantVaryingArray<T>() where T : struct
        {
            if (typeof(T) == typeof(byte))
            {
                return ReadConformantVaryingByteArray().Cast<byte, T>();
            }
            else if (typeof(T) == typeof(char))
            {
                return ReadConformantVaryingCharArray().Cast<char, T>();
            }
            else if (typeof(T) == typeof(INdrStructure))
            {
                using (var queue = _deferred_reads.Push())
                {
                    return ReadConformantVaryingArrayCallback(ReadStructInternal<T>);
                }
            }
            else if (typeof(T).IsPrimitive)
            {
                return ReadConformantVaryingPrimitiveArray<T>();
            }
            throw new ArgumentException($"Invalid type {typeof(T)} for {nameof(ReadConformantVaryingArray)}");
        }

        #endregion

        #region String Types

        public string ReadFixedString(int count)
        {
            return new string(ReadFixedCharArray(count));
        }

        public string ReadFixedAnsiString(int count)
        {
            return BinaryEncoding.Instance.GetString(ReadFixedByteArray(count));
        }

        public string ReadConformantVaryingAnsiString()
        {
            return BinaryEncoding.Instance.GetString(ReadConformantVaryingByteArray()).TrimEnd('\0');
        }

        public string ReadConformantVaryingString()
        {
            return new string(ReadConformantVaryingCharArray()).TrimEnd('\0');
        }

        public string ReadVaryingString()
        {
            return new string(ReadVaryingCharArray()).TrimEnd('\0');
        }

        public string ReadVaryingAnsiString()
        {
            return BinaryEncoding.Instance.GetString(ReadVaryingByteArray()).TrimEnd('\0');
        }

        #endregion

        #region Pointer Types

        public T? ReadReferentValue<T>(Func<T> unmarshal_func, bool full_pointer) where T : struct
        {
            int referent = ReadInt32();
            if (referent == 0)
            {
                return null;
            }

            return full_pointer ? ReadFullPointer(referent, unmarshal_func) : unmarshal_func();
        }

        public T? ReadReferentValue<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg) where T : struct
        {
            return ReadReferentValue(() => unmarshal_func(arg), full_pointer);
        }

        public T? ReadReferentValue<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg1, V arg2) where T : struct
        {
            return ReadReferentValue(() => unmarshal_func(arg1, arg2), full_pointer);
        }

        public T ReadReferent<T>(Func<T> unmarshal_func, bool full_pointer) where T : class
        {
            int referent = ReadInt32();
            if (referent == 0)
            {
                return null;
            }
            return full_pointer ? ReadFullPointer(referent, unmarshal_func) : unmarshal_func();
        }

        public T ReadReferent<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg) where T : class
        {
            return ReadReferent(() => unmarshal_func(arg), full_pointer);
        }

        public T ReadReferent<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg1, V arg2) where T : class
        {
            return ReadReferent(() => unmarshal_func(arg1, arg2), full_pointer);
        }

        public NdrEmbeddedPointer<T> ReadEmbeddedPointer<T>(Func<T> unmarshal_func, bool full_pointer)
        {
            int referent = ReadInt32();
            if (referent == 0)
            {
                return null;
            }

            if (full_pointer)
            {
                unmarshal_func = () => ReadFullPointer(referent, unmarshal_func);
            }

            var deferred_reader = NdrEmbeddedPointer<T>.CreateDeferredReader(unmarshal_func);
            _deferred_reads.Add(deferred_reader.Item2);
            return deferred_reader.Item1;
        }

        public NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U>(Func<U, T> unmarshal_func, bool full_pointer, U arg)
        {
            return ReadEmbeddedPointer(() => unmarshal_func(arg), full_pointer);
        }

        public NdrEmbeddedPointer<T> ReadEmbeddedPointer<T, U, V>(Func<U, V, T> unmarshal_func, bool full_pointer, U arg, V arg2)
        {
            return ReadEmbeddedPointer(() => unmarshal_func(arg, arg2), full_pointer);
        }

        #endregion

        #region Structure Types

        public Guid ReadGuid()
        {
            Align(4);
            return new Guid(ReadFixedByteArray(16));
        }

        public T ReadStruct<T>() where T : INdrStructure, new()
        {
            INdrStructure s = (INdrStructure)new T();
            bool conformant = false;
            if (s is INdrConformantStructure conformant_struct)
            {
                conformant = SetupConformance(conformant_struct.GetConformantDimensions());
                System.Diagnostics.Debug.Assert(_conformance_values != null);
            }

            T ret;
            using (var queue = _deferred_reads.Push())
            {
                ret = ReadStructInternal<T>();
            }

            if (conformant)
            {
                System.Diagnostics.Debug.Assert(_conformance_values == null);
            }

            return ret;
        }

        #endregion

        #region Dispose Support
        public virtual void Dispose()
        {
         
        }
        #endregion
    }
#pragma warning restore 1591
}

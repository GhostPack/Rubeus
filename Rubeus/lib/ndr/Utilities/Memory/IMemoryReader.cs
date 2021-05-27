//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace Rubeus.Utilities.Memory
{
    internal interface IConvertToNative<T> where T : struct
    {
        T Convert();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IntPtr32 : IConvertToNative<IntPtr>
    {
        public int value;

        public IntPtr Convert()
        {
            return new IntPtr(value);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UIntPtr32 : IConvertToNative<UIntPtr>
    {
        public uint value;

        public UIntPtr Convert()
        {
            return new UIntPtr(value);
        }
    }

    internal interface IMemoryReader
    {
        byte ReadByte(IntPtr address);
        byte[] ReadBytes(IntPtr address, int length);
        short ReadInt16(IntPtr address);
        IntPtr ReadIntPtr(IntPtr address);
        int ReadInt32(IntPtr address);
        T ReadStruct<T>(IntPtr address) where T : struct;
        T[] ReadArray<T>(IntPtr address, int count) where T : struct;
        BinaryReader GetReader(IntPtr address);
        bool InProcess { get; }
        int PointerSize { get; }
        string ReadAnsiStringZ(IntPtr address);
    }
}

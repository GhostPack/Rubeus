//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Text;

namespace Rubeus.Utilities.Text
{
    /// <summary>
    /// Class to build a hex dump from a stream of bytes.
    /// </summary>
    public sealed class HexDumpBuilder
    {
        private readonly Stream _data = null;
        private readonly bool _can_write;
        private readonly StringBuilder _builder = new StringBuilder();
        private readonly bool _print_address;
        private readonly bool _print_ascii;
        private readonly bool _hide_repeating;
        private readonly long _address_offset;
        private const int CHUNK_LIMIT = 256;
        private byte[] _last_line = null;
        private int _repeat_count = 0;

        private int GetDataLeft()
        {
            return (int)(_data.Length - _data.Position);
        }

        private bool IsRepeatingLine(byte[] line)
        {
            if (!_hide_repeating)
                return false;
            byte[] last_line = _last_line;
            _last_line = line;
            if (last_line == null)
            {
                return false;
            }
            if (last_line.Length != line.Length)
            {
                return false;
            }

            for (int i = 0; i < last_line.Length; ++i)
            {
                if (last_line[i] != line[i])
                    return false;
            }
            return true;
        }

        private void AppendChunks()
        {
            while (GetDataLeft() >= 16)
            {
                long curr_pos = _data.Position + _address_offset;
                byte[] line = new byte[16];
                _data.Read(line, 0, 16);

                if (IsRepeatingLine(line))
                {
                    _repeat_count++;
                    continue;
                }
                else if(_repeat_count > 0)
                {
                    _builder.AppendLine($"-> REPEATED {_repeat_count} LINES");
                    _repeat_count = 0;
                }

                if (_print_address)
                {
                    if (curr_pos < uint.MaxValue)
                    {
                        _builder.AppendFormat("{0:X08}: ", curr_pos);
                    }
                    else
                    {
                        _builder.AppendFormat("{0:X016}: ", curr_pos);
                    }
                }
                for (int j = 0; j < 16; ++j)
                {
                    _builder.AppendFormat("{0:X02} ", line[j]);
                }

                if (_print_ascii)
                {
                    _builder.Append(" - ");
                    for (int j = 0; j < 16; ++j)
                    {
                        byte b = line[j];
                        char c = b >= 32 && b < 127 ? (char)b : '.';
                        _builder.Append(c);
                    }
                }
                _builder.AppendLine();
            }
        }

        private void AppendTrailing()
        {
            int line_length = GetDataLeft();
            System.Diagnostics.Debug.Assert(line_length < 16);
            if (line_length == 0)
            {
                return;
            }

            if (_repeat_count > 0)
            {
                _builder.AppendLine($"-> REPEATED {_repeat_count} LINES");
            }

            int j = 0;
            if (_print_address)
            {
                long address = _data.Position + _address_offset;
                if (address < uint.MaxValue)
                {
                    _builder.AppendFormat("{0:X08}: ", address);
                }
                else
                {
                    _builder.AppendFormat("{0:X016}: ", address);
                }
            }

            byte[] line = new byte[line_length];
            _data.Read(line, 0, line.Length);

            for (; j < line_length; ++j)
            {
                _builder.AppendFormat("{0:X02} ", line[j]);
            }
            for (; j < 16; ++j)
            {
                _builder.Append("   ");
            }
            if (_print_ascii)
            {
                _builder.Append(" - ");
                for (j = 0; j < line_length; ++j)
                {
                    byte b = line[j];
                    char c = b >= 32 && b < 127 ? (char)b : '.';
                    _builder.Append(c);
                }
            }
            _builder.AppendLine();
        }

        /// <summary>
        /// Append an array of bytes to the hex dump.
        /// </summary>
        /// <param name="ba">The byte array.</param>
        public void Append(byte[] ba)
        {
            if (!_can_write)
                throw new InvalidOperationException();
            long curr_pos = _data.Position;
            _data.Position = _data.Length;
            _data.Write(ba, 0, ba.Length);
            _data.Position = curr_pos;
            if (GetDataLeft() >= CHUNK_LIMIT)
            {
                AppendChunks();
            }
        }

        /// <summary>
        /// Complete the hex dump string.
        /// </summary>
        public void Complete()
        {
            AppendChunks();
            AppendTrailing();
        }

        /// <summary>
        /// Finish builder and convert to a string.
        /// </summary>
        /// <returns>The hex dump.</returns>
        public override string ToString()
        {
            return _builder.ToString();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="print_header">Print a header.</param>
        /// <param name="print_address">Print the address.</param>
        /// <param name="print_ascii">Print the ASCII text.</param>
        /// <param name="hide_repeating">Hide repeating lines.</param>
        /// <param name="address_offset">Offset for address printing.</param>
        public HexDumpBuilder(bool print_header, bool print_address, bool print_ascii, bool hide_repeating, long address_offset) 
            : this(new MemoryStream(), print_header, print_address, print_ascii, hide_repeating, address_offset)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="buffer">The safe buffer to print.</param>
        /// <param name="length">The length to display.</param>
        /// <param name="offset">The offset into the buffer to display.</param>
        /// <param name="print_header">Print a header.</param>
        /// <param name="print_address">Print the address.</param>
        /// <param name="print_ascii">Print the ASCII text.</param>
        /// <param name="hide_repeating">Hide repeating lines.</param>
        public HexDumpBuilder(SafeBuffer buffer, long offset, long length, bool print_header, bool print_address, bool print_ascii, bool hide_repeating)
            : this(new UnmanagedMemoryStream(buffer, offset, length == 0 ? (long)buffer.ByteLength : length), 
                  print_header, print_address, print_ascii, hide_repeating, buffer.DangerousGetHandle().ToInt64())
        {
            _address_offset = buffer.DangerousGetHandle().ToInt64();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="buffer">The safe buffer to print.</param>
        /// <param name="print_header">Print a header.</param>
        /// <param name="print_address">Print the address.</param>
        /// <param name="print_ascii">Print the ASCII text.</param>
        /// <param name="hide_repeating">Hide repeating lines.</param>
        public HexDumpBuilder(SafeBuffer buffer, bool print_header, bool print_address, bool print_ascii, bool hide_repeating)
            : this(buffer, 0, (long)buffer.ByteLength, print_header, print_address, print_ascii, hide_repeating)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="stm">The stream to print.</param>
        /// <param name="print_header">Print a header.</param>
        /// <param name="print_address">Print the address.</param>
        /// <param name="print_ascii">Print the ASCII text.</param>
        /// <param name="hide_repeating">Hide repeating lines.</param>
        /// <param name="address_offset">Offset for address printing.</param>
        public HexDumpBuilder(Stream stm, bool print_header, bool print_address, bool print_ascii, bool hide_repeating, long address_offset)
        {
            _address_offset = address_offset;
            _data = stm;
            _can_write = _data.CanSeek && _data.CanWrite;
            _print_address = print_address;
            _print_ascii = print_ascii;
            _hide_repeating = hide_repeating;
            if (print_header)
            {
                if (print_address)
                {
                    if (address_offset > uint.MaxValue)
                    {
                        _builder.Append(' ', 18);
                    }
                    else
                    {
                        _builder.Append(' ', 10);
                    }
                }

                _builder.Append("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F ");
                if (print_ascii)
                {
                    _builder.AppendLine(" - 0123456789ABCDEF");
                }
                else
                {
                    _builder.AppendLine();
                }
                int dash_count = 48;
                if (print_address)
                {
                    if (address_offset > uint.MaxValue)
                    {
                        dash_count += 18;
                    }
                    else
                    {
                        dash_count += 10;
                    }
                }
                if (print_ascii)
                {
                    dash_count += 19;
                }
                _builder.Append('-', dash_count);
                _builder.AppendLine();
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public HexDumpBuilder() 
            : this(false, false, false, false, 0)
        {
        }
    }
}

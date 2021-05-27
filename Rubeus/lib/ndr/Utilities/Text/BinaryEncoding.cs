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

using System.Text;

namespace Rubeus.Utilities.Text
{
    /// <summary>
    /// Encoding object which converts 1 to 1 with bytes.
    /// </summary>
    public sealed class BinaryEncoding : Encoding
    {
        /// <summary>
        /// Default instance of the encoding.
        /// </summary>
        public static readonly BinaryEncoding Instance = new BinaryEncoding();

        /// <summary>
        /// Get the encoding name.
        /// </summary>
        public override string EncodingName => "Binary";

        /// <summary>
        /// Get byte count for characters.
        /// </summary>
        /// <param name="chars">The character array.</param>
        /// <param name="index">Index into the array.</param>
        /// <param name="count">Number of characters in the array to use.</param>
        /// <returns>The number of bytes this character array requires.</returns>
        public override int GetByteCount(char[] chars, int index, int count) => count;

        /// <summary>
        /// Get bytes for characters.
        /// </summary>
        /// <param name="chars">The character array.</param>
        /// <param name="charIndex">Index into the array.</param>
        /// <param name="charCount">Number of characters in the array to use.</param>
        /// <param name="byteIndex">The index into the byte array.</param>
        /// <param name="bytes">The byte array to copy into.</param>
        /// <returns>The number of bytes generated.</returns>
        public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
        {
            for (int i = 0; i < charCount; ++i)
            {
                bytes[byteIndex + i] = (byte)chars[charIndex + i];
            }

            return charCount;
        }

        /// <summary>
        /// Get the character count for bytes.
        /// </summary>
        /// <param name="bytes">The byte array.</param>
        /// <param name="index">Index into the array.</param>
        /// <param name="count">Number of bytes in the array to use.</param>
        /// <returns>The number of characters this byte array requires.</returns>
        public override int GetCharCount(byte[] bytes, int index, int count) => count;

        /// <summary>
        /// Get byte count for characters.
        /// </summary>
        /// <param name="chars">The character array.</param>
        /// <param name="charIndex">Index into the array.</param>
        /// <param name="byteCount">Number of bytes in the array to use.</param>
        /// <param name="byteIndex">The index into the byte array.</param>
        /// <param name="bytes">The byte array to copy into.</param>
        /// <returns>The number of characters generated.</returns>
        public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
        {
            for (int i = 0; i < byteCount; ++i)
            {
                chars[charIndex + i] = (char)bytes[byteIndex + i];
            }

            return byteCount;
        }

        /// <summary>
        /// Get maximum bytes for a number of characters.
        /// </summary>
        /// <param name="charCount"></param>
        /// <returns></returns>
        public override int GetMaxByteCount(int charCount) => charCount;

        /// <summary>
        /// Get maximum characters for a number of bytes.
        /// </summary>
        /// <param name="byteCount"></param>
        /// <returns></returns>
        public override int GetMaxCharCount(int byteCount) => byteCount;

        /// <summary>
        /// Indicates if the encoding is a single byte.
        /// </summary>
        public override bool IsSingleByte => true;
    }
}

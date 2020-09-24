using System;

namespace Rubeus.Asn1 {
    public static class Asn1Extensions {

        public static byte[] DepadLeft(this byte[] data) {

            int leadingZeros = 0;
            for (var i = 0; i < data.Length; i++) {
                if (data[i] == 0) {
                    leadingZeros++;
                } else {
                    break;
                }
            }

            byte[] result = new byte[data.Length - leadingZeros];
            Array.Copy(data, leadingZeros, result, 0, data.Length - leadingZeros);
            return result;
        }

        public static byte[] PadLeft(this byte[] data, int totalSize) {

            if(data.Length == totalSize) {
                return data;
            }

            if(totalSize < data.Length) {
                throw new ArgumentException("data bigger than totalSize, cannot pad with 0's");
            }

            byte[] result = new byte[totalSize];
            data.CopyTo(result, totalSize - data.Length);
            return result;
        }

        public static byte[] PadRight(this byte[] data, int length) {
            if (data.Length == length) {
                return data;
            }

            var copy = new byte[length];
            data.CopyTo(copy, length - data.Length);
            return copy;
        }
    }
}

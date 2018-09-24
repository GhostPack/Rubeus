using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Asn1 {

public static class AsnIO {

	public static byte[] FindDER(byte[] buf)
	{
		return FindBER(buf, true);
	}

	public static byte[] FindBER(byte[] buf)
	{
		return FindBER(buf, false);
	}

	/*
	 * Find a BER/DER object in the provided buffer. If the data is
	 * not already in the right format, conversion to string then
	 * Base64 decoding is attempted; in the latter case, PEM headers
	 * are detected and skipped. In any case, the returned buffer
	 * must begin with a well-formed tag and length, corresponding to
	 * the object length.
	 *
	 * If 'strictDER' is true, then the function furthermore insists
	 * on the object to use a defined DER length.
	 *
	 * The returned buffer may be the source buffer itself, or a newly
	 * allocated buffer.
	 *
	 * On error, null is returned.
	 */
	public static byte[] FindBER(byte[] buf, bool strictDER)
	{
		string pemType = null;
		return FindBER(buf, strictDER, out pemType);
	}

	/*
	 * Find a BER/DER object in the provided buffer. If the data is
	 * not already in the right format, conversion to string then
	 * Base64 decoding is attempted; in the latter case, PEM headers
	 * are detected and skipped. In any case, the returned buffer
	 * must begin with a well-formed tag and length, corresponding to
	 * the object length.
	 *
	 * If 'strictDER' is true, then the function furthermore insists
	 * on the object to use a defined DER length.
	 *
	 * If the source was detected to use PEM, then the object type
	 * indicated by the PEM header is written in 'pemType'; otherwise,
	 * that variable is set to null.
	 *
	 * The returned buffer may be the source buffer itself, or a newly
	 * allocated buffer.
	 *
	 * On error, null is returned.
	 */
	public static byte[] FindBER(byte[] buf,
		bool strictDER, out string pemType)
	{
		pemType = null;

		/*
		 * If it is already (from the outside) a BER object,
		 * return it.
		 */
		if (LooksLikeBER(buf, strictDER)) {
			return buf;
		}

		/*
		 * Convert the blob to a string. We support UTF-16 with
		 * and without a BOM, UTF-8 with and without a BOM, and
		 * ASCII-compatible encodings. Non-ASCII characters get
		 * truncated.
		 */
		if (buf.Length < 3) {
			return null;
		}
		string str = null;
		if ((buf.Length & 1) == 0) {
			if (buf[0] == 0xFE && buf[1] == 0xFF) {
				// Starts with big-endian UTF-16 BOM
				str = ConvertBi(buf, 2, true);
			} else if (buf[0] == 0xFF && buf[1] == 0xFE) {
				// Starts with little-endian UTF-16 BOM
				str = ConvertBi(buf, 2, false);
			} else if (buf[0] == 0) {
				// First byte is 0 -> big-endian UTF-16
				str = ConvertBi(buf, 0, true);
			} else if (buf[1] == 0) {
				// Second byte is 0 -> little-endian UTF-16
				str = ConvertBi(buf, 0, false);
			}
		}
		if (str == null) {
			if (buf[0] == 0xEF
				&& buf[1] == 0xBB
				&& buf[2] == 0xBF)
			{
				// Starts with UTF-8 BOM
				str = ConvertMono(buf, 3);
			} else {
				// Assumed ASCII-compatible mono-byte encoding
				str = ConvertMono(buf, 0);
			}
		}
		if (str == null) {
			return null;
		}

		/*
		 * Try to detect a PEM header and footer; if we find both
		 * then we remove both, keeping only the characters that
		 * occur in between.
		 */
		int p = str.IndexOf("-----BEGIN ");
		int q = str.IndexOf("-----END ");
		if (p >= 0 && q >= 0) {
			p += 11;
			int r = str.IndexOf((char)10, p) + 1;
			int px = str.IndexOf('-', p);
			if (px > 0 && px < r && r > 0 && r <= q) {
				pemType = string.Copy(str.Substring(p, px - p));
				str = str.Substring(r, q - r);
			}
		}

		/*
		 * Convert from Base64.
		 */
		try {
			buf = Convert.FromBase64String(str);
			if (LooksLikeBER(buf, strictDER)) {
				return buf;
			}
		} catch {
			// ignored: not Base64
		}

		/*
		 * Decoding failed.
		 */
		return null;
	}

	/* =============================================================== */

	/*
	 * Decode a tag; returned value is true on success, false otherwise.
	 * On success, 'off' is updated to point to the first byte after
	 * the tag.
	 */
	static bool DecodeTag(byte[] buf, int lim, ref int off)
	{
		int p = off;
		if (p >= lim) {
			return false;
		}
		int v = buf[p ++];
		if ((v & 0x1F) == 0x1F) {
			do {
				if (p >= lim) {
					return false;
				}
				v = buf[p ++];
			} while ((v & 0x80) != 0);
		}
		off = p;
		return true;
	}

	/*
	 * Decode a BER length. Returned value is:
	 *   -2   no decodable length
	 *   -1   indefinite length
	 *    0+  definite length
	 * If a definite or indefinite length could be decoded, then 'off'
	 * is updated to point to the first byte after the length.
	 */
	static int DecodeLength(byte[] buf, int lim, ref int off)
	{
		int p = off;
		if (p >= lim) {
			return -2;
		}
		int v = buf[p ++];
		if (v < 0x80) {
			off = p;
			return v;
		} else if (v == 0x80) {
			off = p;
			return -1;
		}
		v &= 0x7F;
		if ((lim - p) < v) {
			return -2;
		}
		int acc = 0;
		while (v -- > 0) {
			if (acc > 0x7FFFFF) {
				return -2;
			}
			acc = (acc << 8) + buf[p ++];
		}
		off = p;
		return acc;
	}

	/*
	 * Get the length, in bytes, of the object in the provided
	 * buffer. The object begins at offset 'off' but does not extend
	 * farther than offset 'lim'. If no such BER object can be
	 * decoded, then -1 is returned. The returned length includes
	 * that of the tag and length fields.
	 */
	static int BERLength(byte[] buf, int lim, int off)
	{
		int orig = off;
		if (!DecodeTag(buf, lim, ref off)) {
			return -1;
		}
		int len = DecodeLength(buf, lim, ref off);
		if (len >= 0) {
			if (len > (lim - off)) {
				return -1;
			}
			return off + len - orig;
		} else if (len < -1) {
			return -1;
		}

		/*
		 * Indefinite length: we must do some recursive exploration.
		 * End of structure is marked by a "null tag": object has
		 * total length 2 and its tag byte is 0.
		 */
		for (;;) {
			int slen = BERLength(buf, lim, off);
			if (slen < 0) {
				return -1;
			}
			off += slen;
			if (slen == 2 && buf[off] == 0) {
				return off - orig;
			}
		}
	}

	static bool LooksLikeBER(byte[] buf, bool strictDER)
	{
		return LooksLikeBER(buf, 0, buf.Length, strictDER);
	}

	static bool LooksLikeBER(byte[] buf, int off, int len, bool strictDER)
	{
		int lim = off + len;
		int objLen = BERLength(buf, lim, off);
		if (objLen != len) {
			return false;
		}
		if (strictDER) {
			DecodeTag(buf, lim, ref off);
			return DecodeLength(buf, lim, ref off) >= 0;
		} else {
			return true;
		}
	}

	static string ConvertMono(byte[] buf, int off)
	{
		int len = buf.Length - off;
		char[] tc = new char[len];
		for (int i = 0; i < len; i ++) {
			int v = buf[off + i];
			if (v < 1 || v > 126) {
				v = '?';
			}
			tc[i] = (char)v;
		}
		return new string(tc);
	}

	static string ConvertBi(byte[] buf, int off, bool be)
	{
		int len = buf.Length - off;
		if ((len & 1) != 0) {
			return null;
		}
		len >>= 1;
		char[] tc = new char[len];
		for (int i = 0; i < len; i ++) {
			int b0 = buf[off + (i << 1) + 0];
			int b1 = buf[off + (i << 1) + 1];
			int v = be ? ((b0 << 8) + b1) : (b0 + (b1 << 8));
			if (v < 1 || v > 126) {
				v = '?';
			}
			tc[i] = (char)v;
		}
		return new string(tc);
	}
}

}

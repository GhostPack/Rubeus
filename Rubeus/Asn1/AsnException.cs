using System;
using System.IO;

namespace Asn1 {

public class AsnException : IOException {

	public AsnException(string message)
		: base(message)
	{
	}

	public AsnException(string message, Exception nested)
		: base(message, nested)
	{
	}
}

}

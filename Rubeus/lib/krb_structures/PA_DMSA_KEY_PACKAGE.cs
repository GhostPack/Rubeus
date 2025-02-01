using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Asn1;

namespace Rubeus
{
	public class PA_DMSA_KEY_PACKAGE
	{
		// KERB-DMSA-KEY-PACKAGE::= SEQUENCE {
		//	current-keys[0] SEQUENCE OF EncryptionKey,
		//  previous-keys[1] SEQUENCE OF EncryptionKey OPTIONAL,
		//  expiration-interval[2] KerberosTime,
		// fetch-interval[4] KerberosTime,
		// }


		public PA_DMSA_KEY_PACKAGE()
		{
			currentKeys = new PA_KEY_LIST_REP();
			previousKeys = new PA_KEY_LIST_REP();
			expirationInterval = DateTime.UtcNow;
			fetchInterval = DateTime.UtcNow;
        }

		public PA_DMSA_KEY_PACKAGE(AsnElt body) 
		{
			currentKeys = new PA_KEY_LIST_REP(body.Sub[0].Sub[0]);
			previousKeys = new PA_KEY_LIST_REP(body.Sub[1].Sub[0]);
			expirationInterval = body.Sub[2].Sub[0].GetTime();
			fetchInterval = body.Sub[3].Sub[0].GetTime();
		}

		public AsnElt Encode()
		{

			AsnElt currentKeysAsn = currentKeys.Encode();
			AsnElt currentKeysSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { currentKeysAsn });

			AsnElt previousKeysAsn = previousKeys.Encode();
			AsnElt previousKeysSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { previousKeysAsn });

			AsnElt expirationIntervalAsn = AsnElt.MakeTime(AsnElt.GeneralizedTime, expirationInterval);
			AsnElt fetchIntervalAsn = AsnElt.MakeTime(AsnElt.GeneralizedTime, fetchInterval);

			
			AsnElt dmsaKeyPackageSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { currentKeysSeq, previousKeysSeq, expirationIntervalAsn, fetchIntervalAsn });
			return dmsaKeyPackageSeq;
		}

		public PA_KEY_LIST_REP currentKeys { get; set; }
		public PA_KEY_LIST_REP previousKeys { get; set; }
		public DateTime expirationInterval { get; set; }
		public DateTime fetchInterval { get; set; }
	}
}


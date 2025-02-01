using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Asn1;

namespace Rubeus
{
	class PA_SUPERSEDED_BY_USER
	{
		// KERB-SUPERSEDED-BY-USER::= SEQUENCE {
		//	name[0] PrincipalName,
		// realm[1] Realm
		//

		public PA_SUPERSEDED_BY_USER()
		{
			name = new PrincipalName();
			realm = null;
		}

		
		public PA_SUPERSEDED_BY_USER(AsnElt body)
		{
			name = new PrincipalName(body.Sub[0].Sub[0]);
			realm = Encoding.UTF8.GetString(body.Sub[1].Sub[0].GetOctetString());
		}

		public PrincipalName name { get; set; }
		public  string realm { get; set; }
	}
}

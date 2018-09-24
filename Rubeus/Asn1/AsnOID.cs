using System;
using System.Collections.Generic;
using System.Text;

namespace Asn1 {

public class AsnOID {

	static Dictionary<string, string> OIDToName =
		new Dictionary<string, string>();
	static Dictionary<string, string> NameToOID =
		new Dictionary<string, string>();

	static AsnOID()
	{
		/*
		 * From RFC 5280, PKIX1Explicit88 module.
		 */
		Reg("1.3.6.1.5.5.7", "id-pkix");
		Reg("1.3.6.1.5.5.7.1", "id-pe");
		Reg("1.3.6.1.5.5.7.2", "id-qt");
		Reg("1.3.6.1.5.5.7.3", "id-kp");
		Reg("1.3.6.1.5.5.7.48", "id-ad");
		Reg("1.3.6.1.5.5.7.2.1", "id-qt-cps");
		Reg("1.3.6.1.5.5.7.2.2", "id-qt-unotice");
		Reg("1.3.6.1.5.5.7.48.1", "id-ad-ocsp");
		Reg("1.3.6.1.5.5.7.48.2", "id-ad-caIssuers");
		Reg("1.3.6.1.5.5.7.48.3", "id-ad-timeStamping");
		Reg("1.3.6.1.5.5.7.48.5", "id-ad-caRepository");

		Reg("2.5.4", "id-at");
		Reg("2.5.4.41", "id-at-name");
		Reg("2.5.4.4", "id-at-surname");
		Reg("2.5.4.42", "id-at-givenName");
		Reg("2.5.4.43", "id-at-initials");
		Reg("2.5.4.44", "id-at-generationQualifier");
		Reg("2.5.4.3", "id-at-commonName");
		Reg("2.5.4.7", "id-at-localityName");
		Reg("2.5.4.8", "id-at-stateOrProvinceName");
		Reg("2.5.4.10", "id-at-organizationName");
		Reg("2.5.4.11", "id-at-organizationalUnitName");
		Reg("2.5.4.12", "id-at-title");
		Reg("2.5.4.46", "id-at-dnQualifier");
		Reg("2.5.4.6", "id-at-countryName");
		Reg("2.5.4.5", "id-at-serialNumber");
		Reg("2.5.4.65", "id-at-pseudonym");
		Reg("0.9.2342.19200300.100.1.25", "id-domainComponent");

		Reg("1.2.840.113549.1.9", "pkcs-9");
		Reg("1.2.840.113549.1.9.1", "id-emailAddress");

		/*
		 * From RFC 5280, PKIX1Implicit88 module.
		 */
		Reg("2.5.29", "id-ce");
		Reg("2.5.29.35", "id-ce-authorityKeyIdentifier");
		Reg("2.5.29.14", "id-ce-subjectKeyIdentifier");
		Reg("2.5.29.15", "id-ce-keyUsage");
		Reg("2.5.29.16", "id-ce-privateKeyUsagePeriod");
		Reg("2.5.29.32", "id-ce-certificatePolicies");
		Reg("2.5.29.33", "id-ce-policyMappings");
		Reg("2.5.29.17", "id-ce-subjectAltName");
		Reg("2.5.29.18", "id-ce-issuerAltName");
		Reg("2.5.29.9", "id-ce-subjectDirectoryAttributes");
		Reg("2.5.29.19", "id-ce-basicConstraints");
		Reg("2.5.29.30", "id-ce-nameConstraints");
		Reg("2.5.29.36", "id-ce-policyConstraints");
		Reg("2.5.29.31", "id-ce-cRLDistributionPoints");
		Reg("2.5.29.37", "id-ce-extKeyUsage");

		Reg("2.5.29.37.0", "anyExtendedKeyUsage");
		Reg("1.3.6.1.5.5.7.3.1", "id-kp-serverAuth");
		Reg("1.3.6.1.5.5.7.3.2", "id-kp-clientAuth");
		Reg("1.3.6.1.5.5.7.3.3", "id-kp-codeSigning");
		Reg("1.3.6.1.5.5.7.3.4", "id-kp-emailProtection");
		Reg("1.3.6.1.5.5.7.3.8", "id-kp-timeStamping");
		Reg("1.3.6.1.5.5.7.3.9", "id-kp-OCSPSigning");

		Reg("2.5.29.54", "id-ce-inhibitAnyPolicy");
		Reg("2.5.29.46", "id-ce-freshestCRL");
		Reg("1.3.6.1.5.5.7.1.1", "id-pe-authorityInfoAccess");
		Reg("1.3.6.1.5.5.7.1.11", "id-pe-subjectInfoAccess");
		Reg("2.5.29.20", "id-ce-cRLNumber");
		Reg("2.5.29.28", "id-ce-issuingDistributionPoint");
		Reg("2.5.29.27", "id-ce-deltaCRLIndicator");
		Reg("2.5.29.21", "id-ce-cRLReasons");
		Reg("2.5.29.29", "id-ce-certificateIssuer");
		Reg("2.5.29.23", "id-ce-holdInstructionCode");
		Reg("2.2.840.10040.2", "WRONG-holdInstruction");
		Reg("2.2.840.10040.2.1", "WRONG-id-holdinstruction-none");
		Reg("2.2.840.10040.2.2", "WRONG-id-holdinstruction-callissuer");
		Reg("2.2.840.10040.2.3", "WRONG-id-holdinstruction-reject");
		Reg("2.5.29.24", "id-ce-invalidityDate");

		/*
		 * These are the "right" OID. RFC 5280 mistakenly defines
		 * the first OID element as "2".
		 */
		Reg("1.2.840.10040.2", "holdInstruction");
		Reg("1.2.840.10040.2.1", "id-holdinstruction-none");
		Reg("1.2.840.10040.2.2", "id-holdinstruction-callissuer");
		Reg("1.2.840.10040.2.3", "id-holdinstruction-reject");

		/*
		 * From PKCS#1.
		 */
		Reg("1.2.840.113549.1.1", "pkcs-1");
		Reg("1.2.840.113549.1.1.1", "rsaEncryption");
		Reg("1.2.840.113549.1.1.7", "id-RSAES-OAEP");
		Reg("1.2.840.113549.1.1.9", "id-pSpecified");
		Reg("1.2.840.113549.1.1.10", "id-RSASSA-PSS");
		Reg("1.2.840.113549.1.1.2", "md2WithRSAEncryption");
		Reg("1.2.840.113549.1.1.4", "md5WithRSAEncryption");
		Reg("1.2.840.113549.1.1.5", "sha1WithRSAEncryption");
		Reg("1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
		Reg("1.2.840.113549.1.1.12", "sha384WithRSAEncryption");
		Reg("1.2.840.113549.1.1.13", "sha512WithRSAEncryption");
		Reg("1.3.14.3.2.26", "id-sha1");
		Reg("1.2.840.113549.2.2", "id-md2");
		Reg("1.2.840.113549.2.5", "id-md5");
		Reg("1.2.840.113549.1.1.8", "id-mgf1");

		/*
		 * From NIST: http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html
		 */
		Reg("2.16.840.1.101.3", "csor");
		Reg("2.16.840.1.101.3.4", "nistAlgorithms");
		Reg("2.16.840.1.101.3.4.0", "csorModules");
		Reg("2.16.840.1.101.3.4.0.1", "aesModule1");

		Reg("2.16.840.1.101.3.4.1", "aes");
		Reg("2.16.840.1.101.3.4.1.1", "id-aes128-ECB");
		Reg("2.16.840.1.101.3.4.1.2", "id-aes128-CBC");
		Reg("2.16.840.1.101.3.4.1.3", "id-aes128-OFB");
		Reg("2.16.840.1.101.3.4.1.4", "id-aes128-CFB");
		Reg("2.16.840.1.101.3.4.1.5", "id-aes128-wrap");
		Reg("2.16.840.1.101.3.4.1.6", "id-aes128-GCM");
		Reg("2.16.840.1.101.3.4.1.7", "id-aes128-CCM");
		Reg("2.16.840.1.101.3.4.1.8", "id-aes128-wrap-pad");
		Reg("2.16.840.1.101.3.4.1.21", "id-aes192-ECB");
		Reg("2.16.840.1.101.3.4.1.22", "id-aes192-CBC");
		Reg("2.16.840.1.101.3.4.1.23", "id-aes192-OFB");
		Reg("2.16.840.1.101.3.4.1.24", "id-aes192-CFB");
		Reg("2.16.840.1.101.3.4.1.25", "id-aes192-wrap");
		Reg("2.16.840.1.101.3.4.1.26", "id-aes192-GCM");
		Reg("2.16.840.1.101.3.4.1.27", "id-aes192-CCM");
		Reg("2.16.840.1.101.3.4.1.28", "id-aes192-wrap-pad");
		Reg("2.16.840.1.101.3.4.1.41", "id-aes256-ECB");
		Reg("2.16.840.1.101.3.4.1.42", "id-aes256-CBC");
		Reg("2.16.840.1.101.3.4.1.43", "id-aes256-OFB");
		Reg("2.16.840.1.101.3.4.1.44", "id-aes256-CFB");
		Reg("2.16.840.1.101.3.4.1.45", "id-aes256-wrap");
		Reg("2.16.840.1.101.3.4.1.46", "id-aes256-GCM");
		Reg("2.16.840.1.101.3.4.1.47", "id-aes256-CCM");
		Reg("2.16.840.1.101.3.4.1.48", "id-aes256-wrap-pad");

		Reg("2.16.840.1.101.3.4.2", "hashAlgs");
		Reg("2.16.840.1.101.3.4.2.1", "id-sha256");
		Reg("2.16.840.1.101.3.4.2.2", "id-sha384");
		Reg("2.16.840.1.101.3.4.2.3", "id-sha512");
		Reg("2.16.840.1.101.3.4.2.4", "id-sha224");
		Reg("2.16.840.1.101.3.4.2.5", "id-sha512-224");
		Reg("2.16.840.1.101.3.4.2.6", "id-sha512-256");

		Reg("2.16.840.1.101.3.4.3", "sigAlgs");
		Reg("2.16.840.1.101.3.4.3.1", "id-dsa-with-sha224");
		Reg("2.16.840.1.101.3.4.3.2", "id-dsa-with-sha256");

		Reg("1.2.840.113549", "rsadsi");
		Reg("1.2.840.113549.2", "digestAlgorithm");
		Reg("1.2.840.113549.2.7", "id-hmacWithSHA1");
		Reg("1.2.840.113549.2.8", "id-hmacWithSHA224");
		Reg("1.2.840.113549.2.9", "id-hmacWithSHA256");
		Reg("1.2.840.113549.2.10", "id-hmacWithSHA384");
		Reg("1.2.840.113549.2.11", "id-hmacWithSHA512");

		/*
		 * From X9.57: http://oid-info.com/get/1.2.840.10040.4
		 */
		Reg("1.2.840.10040.4", "x9algorithm");
		Reg("1.2.840.10040.4", "x9cm");
		Reg("1.2.840.10040.4.1", "dsa");
		Reg("1.2.840.10040.4.3", "dsa-with-sha1");

		/*
		 * From SEC: http://oid-info.com/get/1.3.14.3.2
		 */
		Reg("1.3.14.3.2.2", "md4WithRSA");
		Reg("1.3.14.3.2.3", "md5WithRSA");
		Reg("1.3.14.3.2.4", "md4WithRSAEncryption");
		Reg("1.3.14.3.2.12", "dsaSEC");
		Reg("1.3.14.3.2.13", "dsaWithSHASEC");
		Reg("1.3.14.3.2.27", "dsaWithSHA1SEC");

		/*
		 * From Microsoft: http://oid-info.com/get/1.3.6.1.4.1.311.20.2
		 */
		Reg("1.3.6.1.4.1.311.20.2", "ms-certType");
		Reg("1.3.6.1.4.1.311.20.2.2", "ms-smartcardLogon");
		Reg("1.3.6.1.4.1.311.20.2.3", "ms-UserPrincipalName");
		Reg("1.3.6.1.4.1.311.20.2.3", "ms-UPN");
	}

	static void Reg(string oid, string name)
	{
		if (!OIDToName.ContainsKey(oid)) {
			OIDToName.Add(oid, name);
		}
		string nn = Normalize(name);
		if (NameToOID.ContainsKey(nn)) {
			throw new Exception("OID name collision: " + nn);
		}
		NameToOID.Add(nn, oid);

		/*
		 * Many names start with 'id-??-' and we want to support
		 * the short names (without that prefix) as aliases. But
		 * we must take care of some collisions on short names.
		 */
		if (name.StartsWith("id-")
			&& name.Length >= 7 && name[5] == '-')
		{
			if (name.StartsWith("id-ad-")) {
				Reg(oid, name.Substring(6) + "-IA");
			} else if (name.StartsWith("id-kp-")) {
				Reg(oid, name.Substring(6) + "-EKU");
			} else {
				Reg(oid, name.Substring(6));
			}
		}
	}

	static string Normalize(string name)
	{
		StringBuilder sb = new StringBuilder();
		foreach (char c in name) {
			int d = (int)c;
			if (d <= 32 || d == '-') {
				continue;
			}
			if (d >= 'A' && d <= 'Z') {
				d += 'a' - 'A';
			}
			sb.Append((char)c);
		}
		return sb.ToString();
	}

	public static string ToName(string oid)
	{
		return OIDToName.ContainsKey(oid) ? OIDToName[oid] : oid;
	}

	public static string ToOID(string name)
	{
		if (IsNumericOID(name)) {
			return name;
		}
		string nn = Normalize(name);
		if (!NameToOID.ContainsKey(nn)) {
			throw new AsnException(
				"unrecognized OID name: " + name);
		}
		return NameToOID[nn];
	}

	public static bool IsNumericOID(string oid)
	{
		/*
		 * An OID is in numeric format if:
		 * -- it contains only digits and dots
		 * -- it does not start or end with a dot
		 * -- it does not contain two consecutive dots
		 * -- it contains at least one dot
		 */
		foreach (char c in oid) {
			if (!(c >= '0' && c <= '9') && c != '.') {
				return false;
			}
		}
		if (oid.StartsWith(".") || oid.EndsWith(".")) {
			return false;
		}
		if (oid.IndexOf("..") >= 0) {
			return false;
		}
		if (oid.IndexOf('.') < 0) {
			return false;
		}
		return true;
	}
}

}

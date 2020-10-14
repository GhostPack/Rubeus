using System;
using Asn1;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Rubeus.lib.Interop;


namespace Rubeus
{
    public class Interop
    {
        // constants

        // From https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L61
        public const int KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1;
        public const int KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3;
        public const int KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA = 4;
        public const int KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR = 7;
        public const int KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8;
        public const int KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11;
        public const int KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART = 13;
        public const int KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14;

        // Enums

        [Flags]
        public enum TicketFlags : UInt32
        {
            reserved = 2147483648,
            forwardable = 0x40000000,
            forwarded = 0x20000000,
            proxiable = 0x10000000,
            proxy = 0x08000000,
            may_postdate = 0x04000000,
            postdated = 0x02000000,
            invalid = 0x01000000,
            renewable = 0x00800000,
            initial = 0x00400000,
            pre_authent = 0x00200000,
            hw_authent = 0x00100000,
            ok_as_delegate = 0x00040000,
            name_canonicalize = 0x00010000,
            //cname_in_pa_data = 0x00040000,
            enc_pa_rep = 0x00010000,
            reserved1 = 0x00000001
            // TODO: constrained delegation?
        }

        // TODO: order flipped? https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/KerberosV5Spec2.asn#L167-L190
        // Correcting some of these from here, which packet captures suggest is correct: https://github.com/dotnet/Kerberos.NET/blob/develop/Kerberos.NET/Entities/Krb/KdcOptions.cs
        [Flags]
        public enum KdcOptions : uint
        {
            VALIDATE = 0x00000001,
            RENEW = 0x00000002,
            UNUSED29 = 0x00000004,
            ENCTKTINSKEY = 0x00000008,
            RENEWABLEOK = 0x00000010,
            DISABLETRANSITEDCHECK = 0x00000020,
            UNUSED16 = 0x0000FFC0,
            CONSTRAINED_DELEGATION = 0x00020000,
            CANONICALIZE = 0x00010000,
            CNAMEINADDLTKT = 0x00004000,
            OK_AS_DELEGATE = 0x00040000,
            UNUSED12 = 0x00080000,
            OPTHARDWAREAUTH = 0x00100000,
            PREAUTHENT = 0x00200000,
            INITIAL = 0x00400000,
            RENEWABLE = 0x00800000,
            UNUSED7 = 0x01000000,
            POSTDATED = 0x02000000,
            ALLOWPOSTDATE = 0x04000000,
            PROXY = 0x08000000,
            PROXIABLE = 0x10000000,
            FORWARDED = 0x20000000,
            FORWARDABLE = 0x40000000,
            RESERVED = 0x80000000
        }

        // from https://tools.ietf.org/html/rfc4120#section-7.5.7
        public enum KERB_MESSAGE_TYPE : long
        {
            AS_REQ = 10,
            AS_REP = 11,
            TGS_REQ = 12,
            TGS_REP = 13,
            AP_REQ = 14,
            AP_REP = 15,
            TGT_REQ = 16, // KRB-TGT-REQUEST for U2U
            TGT_REP = 17, // KRB-TGT-REPLY for U2U
            SAFE = 20,
            PRIV = 21,
            CRED = 22,
            ERROR = 30
        }

        // from https://tools.ietf.org/html/rfc3961
        public enum KERB_ETYPE : Int32
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65,
            old_exp = -135
        }

        [Flags]
        public enum SUPPORTED_ETYPE : Int32
        {
            RC4_HMAC_DEFAULT = 0x0,
            DES_CBC_CRC = 0x1,
            DES_CBC_MD5 = 0x2,
            RC4_HMAC = 0x4,
            AES128_CTS_HMAC_SHA1_96 = 0x08,
            AES256_CTS_HMAC_SHA1_96 = 0x10
        }

        public enum KADMIN_PASSWD_ERR : UInt32
        {
            KRB5_KPASSWD_SUCCESS = 0,
            KRB5_KPASSWD_MALFORMED = 1,
            KRB5_KPASSWD_HARDERROR = 2,
            KRB5_KPASSWD_AUTHERROR = 3,
            KRB5_KPASSWD_SOFTERROR = 4,
            KRB5_KPASSWD_ACCESSDENIED = 5,
            KRB5_KPASSWD_BAD_VERSION = 6,
            KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
        }

        public enum KERB_CHECKSUM_ALGORITHM
        {
            KERB_CHECKSUM_RSA_MD5 = 7,
            KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15,
            KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16,
            KERB_CHECKSUM_HMAC_SHA1_96_AES256_X509 = 26,
            KERB_CHECKSUM_DES_MAC = -133,
            KERB_CHECKSUM_HMAC_MD5 = -138,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CHECKSUM
        {
            public int Type;
            public int Size;
            public int Flag;
            public IntPtr Initialize;
            public IntPtr Sum;
            public IntPtr Finalize;
            public IntPtr Finish;
            public IntPtr InitializeEx;
            public IntPtr unk0_null;
        }

        // from https://tools.ietf.org/html/rfc4120#section-6.2
        public enum PRINCIPAL_TYPE : long
        {
            NT_UNKNOWN = 0,
            NT_PRINCIPAL = 1,
            NT_SRV_INST = 2,
            NT_SRV_HST = 3,
            NT_SRV_XHST = 4,
            NT_UID = 5,
            NT_X500_PRINCIPAL = 6,
            NT_SMTP_NAME = 7,
            NT_ENTERPRISE = 10
        }

        // from https://github.com/ps4dev/freebsd-include-mirror/blob/master/krb5_asn1.h
        public enum PADATA_TYPE : UInt32
        {
            NONE = 0,
            TGS_REQ = 1,
            AP_REQ = 1,
            ENC_TIMESTAMP = 2,
            PW_SALT = 3,
            ENC_UNIX_TIME = 5,
            SANDIA_SECUREID = 6,
            SESAME = 7,
            OSF_DCE = 8,
            CYBERSAFE_SECUREID = 9,
            AFS3_SALT = 10,
            ETYPE_INFO = 11,
            SAM_CHALLENGE = 12,
            SAM_RESPONSE = 13,
            PK_AS_REQ_19 = 14,
            PK_AS_REP_19 = 15,
            PK_AS_REQ_WIN = 15,
            PK_AS_REQ = 16,
            PK_AS_REP = 17,
            PA_PK_OCSP_RESPONSE = 18,
            ETYPE_INFO2 = 19,
            USE_SPECIFIED_KVNO = 20,
            SVR_REFERRAL_INFO = 20,
            SAM_REDIRECT = 21,
            GET_FROM_TYPED_DATA = 22,
            SAM_ETYPE_INFO = 23,
            SERVER_REFERRAL = 25,
            TD_KRB_PRINCIPAL = 102,
            PK_TD_TRUSTED_CERTIFIERS = 104,
            PK_TD_CERTIFICATE_INDEX = 105,
            TD_APP_DEFINED_ERROR = 106,
            TD_REQ_NONCE = 107,
            TD_REQ_SEQ = 108,
            PA_PAC_REQUEST = 128,
            S4U2SELF = 129,
            PA_S4U_X509_USER = 130,
            PA_PAC_OPTIONS = 167,
            PK_AS_09_BINDING = 132,
            CLIENT_CANONICALIZED = 133
        }

        // from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/cd9d5ca7-ce20-4693-872b-2f5dd41cbff6
        public enum PA_S4U_X509_USER_OPTIONS : Int32
        {
            CHECK_LOGON_RESTRICTIONS = 0x40000000,
            SIGN_REPLY = 0x20000000
        }

        // adapted from https://github.com/skelsec/minikerberos/blob/master/minikerberos/kerberoserror.py#L18-L76
        public enum KERBEROS_ERROR : UInt32
        {
            KDC_ERR_NONE = 0x0, //No error
            KDC_ERR_NAME_EXP = 0x1, //Client's entry in KDC database has expired
            KDC_ERR_SERVICE_EXP = 0x2, //Server's entry in KDC database has expired
            KDC_ERR_BAD_PVNO = 0x3, //Requested Kerberos version number not supported
            KDC_ERR_C_OLD_MAST_KVNO = 0x4, //Client's key encrypted in old master key
            KDC_ERR_S_OLD_MAST_KVNO = 0x5, //Server's key encrypted in old master key
            KDC_ERR_C_PRINCIPAL_UNKNOWN = 0x6, //Client not found in Kerberos database
            KDC_ERR_S_PRINCIPAL_UNKNOWN = 0x7, //Server not found in Kerberos database
            KDC_ERR_PRINCIPAL_NOT_UNIQUE = 0x8, //Multiple principal entries in KDC database
            KDC_ERR_NULL_KEY = 0x9, //The client or server has a null key (master key)
            KDC_ERR_CANNOT_POSTDATE = 0xA, // Ticket (TGT) not eligible for postdating
            KDC_ERR_NEVER_VALID = 0xB, // Requested start time is later than end time
            KDC_ERR_POLICY = 0xC, //Requested start time is later than end time
            KDC_ERR_BADOPTION = 0xD, //KDC cannot accommodate requested option
            KDC_ERR_ETYPE_NOTSUPP = 0xE, // KDC has no support for encryption type
            KDC_ERR_SUMTYPE_NOSUPP = 0xF, // KDC has no support for checksum type
            KDC_ERR_PADATA_TYPE_NOSUPP = 0x10, //KDC has no support for PADATA type (pre-authentication data)
            KDC_ERR_TRTYPE_NO_SUPP = 0x11, //KDC has no support for transited type
            KDC_ERR_CLIENT_REVOKED = 0x12, // Client’s credentials have been revoked
            KDC_ERR_SERVICE_REVOKED = 0x13, //Credentials for server have been revoked
            KDC_ERR_TGT_REVOKED = 0x14, //TGT has been revoked
            KDC_ERR_CLIENT_NOTYET = 0x15, // Client not yet valid—try again later
            KDC_ERR_SERVICE_NOTYET = 0x16, //Server not yet valid—try again later
            KDC_ERR_KEY_EXPIRED = 0x17, // Password has expired—change password to reset
            KDC_ERR_PREAUTH_FAILED = 0x18, //Pre-authentication information was invalid
            KDC_ERR_PREAUTH_REQUIRED = 0x19, // Additional preauthentication required
            KDC_ERR_SERVER_NOMATCH = 0x1A, //KDC does not know about the requested server
            KDC_ERR_SVC_UNAVAILABLE = 0x1B, // KDC is unavailable
            KRB_AP_ERR_BAD_INTEGRITY = 0x1F, // Integrity check on decrypted field failed
            KRB_AP_ERR_TKT_EXPIRED = 0x20, // The ticket has expired
            KRB_AP_ERR_TKT_NYV = 0x21, //The ticket is not yet valid
            KRB_AP_ERR_REPEAT = 0x22, // The request is a replay
            KRB_AP_ERR_NOT_US = 0x23, //The ticket is not for us
            KRB_AP_ERR_BADMATCH = 0x24, //The ticket and authenticator do not match
            KRB_AP_ERR_SKEW = 0x25, // The clock skew is too great
            KRB_AP_ERR_BADADDR = 0x26, // Network address in network layer header doesn't match address inside ticket
            KRB_AP_ERR_BADVERSION = 0x27, // Protocol version numbers don't match (PVNO)
            KRB_AP_ERR_MSG_TYPE = 0x28, // Message type is unsupported
            KRB_AP_ERR_MODIFIED = 0x29, // Message stream modified and checksum didn't match
            KRB_AP_ERR_BADORDER = 0x2A, // Message out of order (possible tampering)
            KRB_AP_ERR_BADKEYVER = 0x2C, // Specified version of key is not available
            KRB_AP_ERR_NOKEY = 0x2D, // Service key not available
            KRB_AP_ERR_MUT_FAIL = 0x2E, // Mutual authentication failed
            KRB_AP_ERR_BADDIRECTION = 0x2F, // Incorrect message direction
            KRB_AP_ERR_METHOD = 0x30, // Alternative authentication method required
            KRB_AP_ERR_BADSEQ = 0x31, // Incorrect sequence number in message
            KRB_AP_ERR_INAPP_CKSUM = 0x32, // Inappropriate type of checksum in message (checksum may be unsupported)
            KRB_AP_PATH_NOT_ACCEPTED = 0x33, // Desired path is unreachable
            KRB_ERR_RESPONSE_TOO_BIG = 0x34, // Too much data
            KRB_ERR_GENERIC = 0x3C, // Generic error; the description is in the e-data field
            KRB_ERR_FIELD_TOOLONG = 0x3D, // Field is too long for this implementation
            KDC_ERR_CLIENT_NOT_TRUSTED = 0x3E, // The client trust failed or is not implemented
            KDC_ERR_KDC_NOT_TRUSTED = 0x3F, // The KDC server trust failed or could not be verified
            KDC_ERR_INVALID_SIG = 0x40, // The signature is invalid
            KDC_ERR_KEY_TOO_WEAK = 0x41, //A higher encryption level is needed
            KRB_AP_ERR_USER_TO_USER_REQUIRED = 0x42, // User-to-user authorization is required
            KRB_AP_ERR_NO_TGT = 0x43, // No TGT was presented or available
            KDC_ERR_WRONG_REALM = 0x44, //Incorrect domain or principal
        }

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            /// <summary>
            /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
            /// </summary>
            TokenUser = 1,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
            /// </summary>
            TokenGroups,

            /// <summary>
            /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
            /// </summary>
            TokenPrivileges,

            /// <summary>
            /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
            /// </summary>
            TokenOwner,

            /// <summary>
            /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
            /// </summary>
            TokenPrimaryGroup,

            /// <summary>
            /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
            /// </summary>
            TokenDefaultDacl,

            /// <summary>
            /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
            /// </summary>
            TokenSource,

            /// <summary>
            /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
            /// </summary>
            TokenType,

            /// <summary>
            /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
            /// </summary>
            TokenImpersonationLevel,

            /// <summary>
            /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
            /// </summary>
            TokenStatistics,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
            /// </summary>
            TokenRestrictedSids,

            /// <summary>
            /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token. 
            /// </summary>
            TokenSessionId,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
            /// </summary>
            TokenGroupsAndPrivileges,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenSessionReference,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            /// </summary>
            TokenSandBoxInert,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenAuditPolicy,

            /// <summary>
            /// The buffer receives a TOKEN_ORIGIN value. 
            /// </summary>
            TokenOrigin,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
            /// </summary>
            TokenElevationType,

            /// <summary>
            /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
            /// </summary>
            TokenLinkedToken,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
            /// </summary>
            TokenElevation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            /// </summary>
            TokenHasRestrictions,

            /// <summary>
            /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
            /// </summary>
            TokenAccessInformation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            /// </summary>
            TokenVirtualizationAllowed,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            /// </summary>
            TokenVirtualizationEnabled,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level. 
            /// </summary>
            TokenIntegrityLevel,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            /// </summary>
            TokenUIAccess,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
            /// </summary>
            TokenMandatoryPolicy,

            /// <summary>
            /// The buffer receives the token's logon security identifier (SID).
            /// </summary>
            TokenLogonSid,

            /// <summary>
            /// The maximum value for this enumeration
            /// </summary>
            MaxTokenInfoClass
        }

        [Flags]
        public enum KERB_CACHE_OPTIONS : UInt64
        {
            KERB_RETRIEVE_TICKET_DEFAULT = 0x0,
            KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1,
            KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2,
            KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4,
            KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8,
            KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10,
            KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20,
            KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40,
        }

        public enum KERB_PROTOCOL_MESSAGE_TYPE : UInt32
        {
            KerbDebugRequestMessage = 0,
            KerbQueryTicketCacheMessage = 1,
            KerbChangeMachinePasswordMessage = 2,
            KerbVerifyPacMessage = 3,
            KerbRetrieveTicketMessage = 4,
            KerbUpdateAddressesMessage = 5,
            KerbPurgeTicketCacheMessage = 6,
            KerbChangePasswordMessage = 7,
            KerbRetrieveEncodedTicketMessage = 8,
            KerbDecryptDataMessage = 9,
            KerbAddBindingCacheEntryMessage = 10,
            KerbSetPasswordMessage = 11,
            KerbSetPasswordExMessage = 12,
            KerbVerifyCredentialsMessage = 13,
            KerbQueryTicketCacheExMessage = 14,
            KerbPurgeTicketCacheExMessage = 15,
            KerbRefreshSmartcardCredentialsMessage = 16,
            KerbAddExtraCredentialsMessage = 17,
            KerbQuerySupplementalCredentialsMessage = 18,
            KerbTransferCredentialsMessage = 19,
            KerbQueryTicketCacheEx2Message = 20,
            KerbSubmitTicketMessage = 21,
            KerbAddExtraCredentialsExMessage = 22,
            KerbQueryKdcProxyCacheMessage = 23,
            KerbPurgeKdcProxyCacheMessage = 24,
            KerbQueryTicketCacheEx3Message = 25,
            KerbCleanupMachinePkinitCredsMessage = 26,
            KerbAddBindingCacheEntryExMessage = 27,
            KerbQueryBindingCacheMessage = 28,
            KerbPurgeBindingCacheMessage = 29,
            KerbQueryDomainExtendedPoliciesMessage = 30,
            KerbQueryS4U2ProxyCacheMessage = 31
        }

        public enum LogonType : uint
        {
            Interactive = 2,        // logging on interactively.
            Network,                // logging using a network.
            Batch,                  // logon for a batch process.
            Service,                // logon for a service account.
            Proxy,                  // Not supported.
            Unlock,                 // Tattempt to unlock a workstation.
            NetworkCleartext,       // network logon with cleartext credentials
            NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
            RemoteInteractive,      // terminal server session that is both remote and interactive
            CachedInteractive,      // attempt to use the cached credentials without going out across the network
            CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
            CachedUnlock            // attempt to unlock a workstation
        }

        public enum LOGON_PROVIDER
        {
            LOGON32_PROVIDER_DEFAULT,
            LOGON32_PROVIDER_WINNT35,
            LOGON32_PROVIDER_WINNT40,
            LOGON32_PROVIDER_WINNT50
        }

        // from https://github.com/alexbrainman/sspi/blob/master/syscall.go#L113-L129
        [Flags]
        public enum ISC_REQ : int
        {
            DELEGATE = 1,
            MUTUAL_AUTH = 2,
            REPLAY_DETECT = 4,
            SEQUENCE_DETECT = 8,
            CONFIDENTIALITY = 16,
            USE_SESSION_KEY = 32,
            PROMPT_FOR_CREDS = 64,
            USE_SUPPLIED_CREDS = 128,
            ALLOCATE_MEMORY = 256,
            USE_DCE_STYLE = 512,
            DATAGRAM = 1024,
            CONNECTION = 2048,
            EXTENDED_ERROR = 16384,
            STREAM = 32768,
            INTEGRITY = 65536,
            MANUAL_CRED_VALIDATION = 524288,
            HTTP = 268435456
        }

        public enum SecBufferType
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_EMPTY = 0,
            SECBUFFER_DATA = 1,
            SECBUFFER_TOKEN = 2
        }

        // from https://directory.apache.org/apacheds/gen-docs/2.0.0-M15/apidocs/src-html/org/apache/directory/shared/kerberos/codec/types/HostAddrType.html
        public enum HostAddressType : long
        {
            NULL = 0,
            ADDRTYPE_UNIX = 1,
            ADDRTYPE_INET = 2,
            ADDRTYPE_IMPLINK = 3,
            ADDRTYPE_PUP = 4,
            ADDRTYPE_CHAOS = 5,
            ADDRTYPE_XNS = 6,
            ADDRTYPE_IPX = 6,
            ADDRTYPE_OSI = 7,
            ADDRTYPE_ECMA = 8,
            ADDRTYPE_DATAKIT = 9,
            ADDRTYPE_CCITT = 10,
            ADDRTYPE_SNA = 11,
            ADDRTYPE_DECNET = 12,
            ADDRTYPE_DLI = 13,
            ADDRTYPE_LAT = 14,
            ADDRTYPE_HYLINK = 15,
            ADDRTYPE_APPLETALK = 16,
            ADDRTYPE_VOICEVIEW = 18,
            ADDRTYPE_FIREFOX = 19,
            ADDRTYPE_NETBIOS = 20,
            ADDRTYPE_BAN = 21,
            ADDRTYPE_ATM = 22,
            ADDRTYPE_INET6 = 24
        }

        // from https://tools.ietf.org/html/rfc4120#section-5.2.6
        public enum AuthorizationDataType : long
        {
            AD_IF_RELEVANT = 1,
            AD_KDCISSUED = 4,
            AD_AND_OR = 5,
            AD_MANDATORY_FOR_KDC = 8,
            AD_WIN2K_PAC = 128,
            KERB_AUTH_DATA_TOKEN_RESTRICTIONS = 141,
            KERB_LOCAL = 142,
            AD_AUTH_DATA_AP_OPTIONS = 143

        }

        // from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ec551137-c5e5-476a-9c89-e0029473c41b
        public enum LSAP_TOKEN_INFO_INTEGRITY_FLAGS : UInt32
        {
            FULL = 0,
            UAC_RESTRICTED = 1
        }

        public enum LSAP_TOKEN_INFO_INTEGRITY_TOKENIL : UInt32
        {
            UNTRUSTED = 0,
            LOW = 4096,
            MEDIUM = 8192,
            HIGH = 12288,
            SYSTEM = 16384,
            PROTECTED = 20480
        }

        // structs

        // // typedef struct _LSAP_TOKEN_INFO_INTEGRITY {
        //    unsigned long Flags;
        //    unsigned long TokenIL;
        //    unsigned char MachineID[32];  # KILE implements a 32-byte binary random string machine ID
        // }
        // LSAP_TOKEN_INFO_INTEGRITY,
        //   *PLSAP_TOKEN_INFO_INTEGRITY;
        public struct LSAP_TOKEN_INFO_INTEGRITY
        {
            public LSAP_TOKEN_INFO_INTEGRITY_FLAGS Flags;
            public LSAP_TOKEN_INFO_INTEGRITY_TOKENIL TokenIL;
            public byte[] machineID;
        }

        // From Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1773-L1794
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ECRYPT
        {
            int Type0;
            public int BlockSize;
            int Type1;
            public int KeySize;
            public int Size;
            int unk2;
            int unk3;
            public IntPtr AlgName;
            public IntPtr Initialize;
            public IntPtr Encrypt;
            public IntPtr Decrypt;
            public IntPtr Finish;
            public IntPtr HashPassword;
            IntPtr RandomKey;
            IntPtr Control;
            IntPtr unk0_null;
            IntPtr unk1_null;
            IntPtr unk2_null;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        public struct SYSTEMTIME
        {
            public ushort wYear, wMonth, wDayOfWeek, wDay,
               wHour, wMinute, wSecond, wMilliseconds;
        }


        // LSA structures

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_SUBMIT_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
            public int KerbCredSize;
            public int KerbCredOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_PURGE_TKT_CACHE_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            LSA_STRING_IN ServerName;
            LSA_STRING_IN RealmName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public int Length;
            public int Offset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_OUT
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public String Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_RESPONSE
        {
            public KERB_EXTERNAL_TICKET Ticket;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_EXTERNAL_TICKET
        {
            public IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public LSA_STRING_OUT DomainName;
            public LSA_STRING_OUT TargetDomainName;
            public LSA_STRING_OUT AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public UInt32 TicketFlags;
            public UInt32 Flags;
            public Int64 KeyExpirationTime;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewUntil;
            public Int64 TimeSkew;
            public Int32 EncodedTicketSize;
            public IntPtr EncodedTicket;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY
        {
            public Int32 KeyType;
            public Int32 Length;
            public IntPtr Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public UNICODE_STRING TargetName;
            public UInt32 TicketFlags;
            public UInt32 CacheOptions;
            public Int32 EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public int CountOfTickets;
            public IntPtr Tickets;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO
        {
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT RealmName;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO_EX
        {
            public LSA_STRING_OUT ClientName;
            public LSA_STRING_OUT ClientRealm;
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT ServerRealm;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO_EX2
        {
            public LSA_STRING_OUT ClientName;
            public LSA_STRING_OUT ClientRealm;
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT ServerRealm;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;

            public UInt32 SessionKeyType;
            public UInt32 BranchId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO_EX3
        {
            public LSA_STRING_OUT ClientName;
            public LSA_STRING_OUT ClientRealm;
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT ServerRealm;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;

            public UInt32 SessionKeyType;
            public UInt32 BranchId;

            public UInt32 CacheFlags;
            public LSA_STRING_OUT KdcCalled;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_EXTERNAL_NAME
        {
            public Int16 NameType;
            public UInt16 NameCount;

            [MarshalAs(UnmanagedType.ByValArray,
                SizeConst = 3)]
            public LSA_STRING_OUT[] Names;
            //public LSA_STRING_OUT[] Names;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public UInt32 Size;
            public LUID LoginID;
            public LSA_STRING_OUT Username;
            public LSA_STRING_OUT LoginDomain;
            public LSA_STRING_OUT AuthenticationPackage;
            public UInt32 LogonType;
            public UInt32 Session;
            public IntPtr PSiD;
            public UInt64 LoginTime;
            public LSA_STRING_OUT LogonServer;
            public LSA_STRING_OUT DnsDomainName;
            public LSA_STRING_OUT Upn;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public long ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_ORIGIN
        {
            public LUID OriginatingLogonSession;
        }

        // the following are adapted from https://www.pinvoke.net/default.aspx/secur32.InitializeSecurityContext
        [StructLayout(LayoutKind.Sequential)]
        public struct SecHandle //=PCtxtHandle
        {
            IntPtr dwLower; // ULONG_PTR translates to IntPtr not to uint
            IntPtr dwUpper; // this is crucial for 64-Bit Platforms
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBuffer : IDisposable
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;


            public SecBuffer(int bufferSize)
            {
                cbBuffer = bufferSize;
                BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(bufferSize);
            }

            public SecBuffer(byte[] secBufferBytes)
            {
                cbBuffer = secBufferBytes.Length;
                BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
            {
                cbBuffer = secBufferBytes.Length;
                BufferType = (int)bufferType;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }
        }

        public struct MultipleSecBufferHelper
        {
            public byte[] Buffer;
            public SecBufferType BufferType;

            public MultipleSecBufferHelper(byte[] buffer, SecBufferType bufferType)
            {
                if (buffer == null || buffer.Length == 0)
                {
                    throw new ArgumentException("buffer cannot be null or 0 length");
                }

                Buffer = buffer;
                BufferType = bufferType;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBufferDesc : IDisposable
        {

            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; //Point to SecBuffer

            public SecBufferDesc(int bufferSize)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
                Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
            }

            public SecBufferDesc(byte[] secBufferBytes)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
                Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
            }

            public SecBufferDesc(MultipleSecBufferHelper[] secBufferBytesArray)
            {
                if (secBufferBytesArray == null || secBufferBytesArray.Length == 0)
                {
                    throw new ArgumentException("secBufferBytesArray cannot be null or 0 length");
                }

                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = secBufferBytesArray.Length;

                //Allocate memory for SecBuffer Array....
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)) * cBuffers);

                for (int Index = 0; Index < secBufferBytesArray.Length; Index++)
                {
                    //Super hack: Now allocate memory for the individual SecBuffers
                    //and just copy the bit values to the SecBuffer array!!!
                    SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytesArray[Index].Buffer, secBufferBytesArray[Index].BufferType);

                    //We will write out bits in the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Note that we won't be releasing the memory allocated by ThisSecBuffer until we
                    //are disposed...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    Marshal.WriteInt32(pBuffers, CurrentOffset, ThisSecBuffer.cbBuffer);
                    Marshal.WriteInt32(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer), ThisSecBuffer.BufferType);
                    Marshal.WriteIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer) + Marshal.SizeOf(ThisSecBuffer.BufferType), ThisSecBuffer.pvBuffer);
                }
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    if (cBuffers == 1)
                    {
                        SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                        ThisSecBuffer.Dispose();
                    }
                    else
                    {
                        for (int Index = 0; Index < cBuffers; Index++)
                        {
                            //The bits were written out the following order:
                            //int cbBuffer;
                            //int BufferType;
                            //pvBuffer;
                            //What we need to do here is to grab a hold of the pvBuffer allocate by the individual
                            //SecBuffer and release it...
                            int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                            IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                            Marshal.FreeHGlobal(SecBufferpvBuffer);
                        }
                    }

                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            public byte[] GetSecBufferByteArray()
            {
                byte[] Buffer = null;

                if (pBuffers == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Object has already been disposed!!!");
                }

                if (cBuffers == 1)
                {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                    if (ThisSecBuffer.cbBuffer > 0)
                    {
                        Buffer = new byte[ThisSecBuffer.cbBuffer];
                        Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                    }
                }
                else
                {
                    int BytesToAllocate = 0;

                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //What we need to do here calculate the total number of bytes we need to copy...
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                    }

                    Buffer = new byte[BytesToAllocate];

                    for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //Now iterate over the individual buffers and put them together into a
                        //byte array...
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                        BufferIndex += BytesToCopy;
                    }
                }

                return (Buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
            public SECURITY_INTEGER(int dummy)
            {
                LowPart = 0;
                HighPart = 0;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
            public SECURITY_HANDLE(int dummy)
            {
                LowPart = HighPart = IntPtr.Zero;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SecPkgContext_Sizes
        {
            public uint cbMaxToken;
            public uint cbMaxSignature;
            public uint cbBlockSize;
            public uint cbSecurityTrailer;
        };



        // functions
        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCheckSum);

        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCheckSum(KERB_CHECKSUM_ALGORITHM type, out IntPtr pCheckSum);

        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1753-L1767
        public delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
        public delegate int KERB_ECRYPT_Encrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        public delegate int KERB_ECRYPT_Decrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        public delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);

        public delegate int KERB_ECRYPT_HashPassword(UNICODE_STRING Password, UNICODE_STRING Salt, int count, byte[] output);

        //https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1760-L1767
        public delegate int KERB_CHECKSUM_Initialize(int unk0, out IntPtr pContext);
        public delegate int KERB_CHECKSUM_Sum(IntPtr pContext, int Size, byte[] Buffer);
        public delegate int KERB_CHECKSUM_Finalize(IntPtr pContext, byte[] Buffer);
        public delegate int KERB_CHECKSUM_Finish(ref IntPtr pContext);
        public delegate int KERB_CHECKSUM_InitializeEx(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);


        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DsGetDcName(
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            [MarshalAs(UnmanagedType.U4)] DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO);

        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("kernel32.dll")]
        public extern static void GetSystemTime(ref SYSTEMTIME lpSystemTime);

        // LSA functions

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaConnectUntrusted(
            [Out] out IntPtr LsaHandle
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaLookupAuthenticationPackage(
            [In] IntPtr LsaHandle,
            [In] ref LSA_STRING_IN PackageName,
            [Out] out int AuthenticationPackage
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalAlloc(
            uint uFlags,
            uint uBytes
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaNtStatusToWinError(
            uint status
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaFreeMemory(
            IntPtr buffer
        );

        [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        public static extern void CopyMemory(
            IntPtr dest,
            IntPtr src,
            uint count
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            int AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaDeregisterLogonProcess(
            [In] IntPtr LsaHandle
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaRegisterLogonProcess(
            LSA_STRING_IN LogonProcessName,
            out IntPtr LsaHandle,
            out ulong SecurityMode
        );

        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            UInt32 logonFlags,
            String applicationName,
            String commandLine,
            UInt32 creationFlags,
            UInt32 environment,
            String currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern int LsaEnumerateLogonSessions(
            out UInt64 LogonSessionCount,
            out IntPtr LogonSessionList
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaGetLogonSessionData(
            IntPtr luid,
            out IntPtr ppLogonSessionData
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer(
            IntPtr buffer
        );

        // adapted from https://www.pinvoke.net/default.aspx/secur32.InitializeSecurityContext
        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int AcquireCredentialsHandle(
            string pszPrincipal, //SEC_CHAR*
            string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID,//PLUID
            IntPtr pAuthData,//PVOID
            int pGetKeyFn, //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument, //PVOID
            ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
            ref SECURITY_INTEGER ptsExpiry  //PTimeStamp //TimeStamp ref
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,//PCredHandle
            IntPtr phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput, //PSecBufferDesc SecBufferDesc
            int Reserved2,
            out SECURITY_HANDLE phNewContext, //PCtxtHandle
            out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsExpiry  //PTimeStamp
        );

        [DllImport("secur32.dll")]
        public static extern int DeleteSecurityContext(
            ref SECURITY_HANDLE phContext
        );

        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        public static extern int FreeCredentialsHandle(
            [In] ref SECURITY_HANDLE phCredential
        );

        [DllImport("Secur32.dll")]
        public static extern int FreeContextBuffer(
            ref IntPtr pvContextBuffer
        );
    }
}
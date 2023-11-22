# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1]

### Added

* `/nofullpacsig` switch to the `silver` command to exclude the inclusion of the new FullPacChecksum in service tickets (@0xe7)
* `/extendedupndns` switch to both `golden` and `silver` to include the extended version of the UpnDsn info buffer (0xe7)
* automated including proper UPN exists flag (*1* or *0*) within UpnDns info buffer based on LDAP results (0xe7)

### Changed

* default UpnDns Flag from *0* (UPN_SET) to *1* (NO_UPN_SET) in `golden` and `silver` (0xe7)

### Fixed

* typos for `kerberos` usage, changed from `/preauth` to `/nopreauth` (0xe7)
* parsing of _logoncount_ and _badpwdcount_ from LDAP with exception handling and set to 0 if exception happens (0xe7)

## [2.2.0]

### Added

* `preauthscan` command to scan for accounts that do not require Kerberos pre-authentication
* `/preauth` argument to the `kerberoast` command, to kerberoast with an account that does not require Kerberos pre-authentication
* `/nopreauth` flag to the `asktgt` command, to request a TGT without providing pre-authentication
* `/service` argument to the `asktgt` command, to request service tickets using an AS-REQ

## [2.1.0]

### Added

* `logonsession` command to list information about the current logon session

## [2.0.3]

### Added

* A `/debug` flag that outputs base64 encodings of the inputs to/outputs from the ASN.1 decoding/encoding functions
* `/createnetonly` parameter to S4U (@tyranid)
* `/ticket` option to createnetonly to import a ticket into the new process without requiring privileges (@tyranid)

### Fixed

* Handling for KERB_ERRORs
  
## [2.0.2]

### Added

* Support for making requests through a KDC proxy using the `/proxyurl:` argument for `asktgt`, `asktgs` and `s4u` (@0xe7)

### Changed

* `KDC_ERR_SVC_UNAVAILABLE` KERBEROS_ERROR, added `KDC_ERR_MUST_USE_USER2USER` and `KDC_ERR_PATH_NOT_ACCEPTED` (@0xe7)

## [2.0.0] - 2021-08-04

### Added

* Full PAC encoding/decoding (@CCob & @0xe7)
* `golden` and `silver` commands for ticket forging with `/ldap` switch to automate retrieving PAC information (@CCob & @0xe7)
* `Networking.GetLdapConnection` with LDAPS support using `LdapConnection` (for `kerberoast`/`asreproast`/`golden`/`silver`) (@0xe7)
* `/getcredentials` for `asktgt` (sends U2U request and automatically extracts NT hash) (@0xe7)
* `/u2u` for `asktgs` to send User-to-User requests (@0xe7)
* `/targetuser` for `asktgs` for sending S4U2self requests (@0xe7)
* `/targetdomain` for `asktgs` for forcing a specific domain for the request (@0xe7)
* `/targetuser` for `changepw` for changing the password of other users (upgraded `EncKrbPrivPart` to version **-128**) (@CCob)
* `/servicekey`, `/krbkey` and `/asrepkey` to `describe` for showing PAC and verifying checksums (@CCob & @0xe7)
* `/serviceuser` and `/servicedomain` to `describe` to create crackable "hashes" from **AES** encrypted tickets (@0xe7)
* `/autoenterprise` now works with the kerberoasting `KerberosRequestorSecurityToken.GetRequest` method (@0xe7)
* `/ldaps` to `kerberoast` and `asreproast` for querying LDAPS (@0xe7)
* `/servicekey` to `asktgt` and `asktgs` to decrypt the EncTicketPart (@CCob & @0xe7)
* `/krbkey` and `/krbenctype` to `asktgs` for verifying the KDCChecksum and TicketChecksum (@0xe7)
* `/printargs` switch to `asktgs` for printing the arguments required for building a similar PAC with `golden` or `silver` (@0xe7)
* `Networking.GetGptTmplContent` for parsing domain policy files using when forging tickets (and `/ldap` is used) (@0xe7)
* `Helpers.GetADObjects` for converting returned LDAP results into a common format (`List<IDictionary<string, Object>>`) (0xe7)

### Fixed

* Complete rewrite of `Networking.SendBytes` (@CCob)
* Fixed `PA_S4U_X509_USER` pa data section for `s4u /opsec` (@0xe7)
* Added check after `S4U2self` to throw error if not received, avoids unhandled exception calling `S4U2proxy` without a ticket, on `s4u` command (@0xe7)
* Handled `KDC_ERR_KEY_EXPIRED` for `brute` command (@0xe7)

### Changed

* Complete rewrite `AuthorizationData` sections (@0xe7)
* Added `keyUsage`  argument to `Crypto.KerberosChecksum` to create `PA_S4U_X509_USER` checksum (@0xe7)
* Aliased `brute` to `spray` (@0xe7)
* Changed `System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName` to `System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name` for `asktgt` when automatically resolving the domain (works in more situations) (@0xe7)


## [1.6.3] - 2021-03-26

### Change

* Only final cert in chain used to verify when signing PKINIT requests, /verifycerts flag added for full verification

### Fixed

* Replaced /certificate info for help and README


## [1.6.2] - 2021-03-12

### Added

* Adapted/integrated the PR from @RiccardoAncarani for `/delay:MILLISECONDS` and `/jitter:%` (1-100) flags for `kerberoast`
* Rubeus.yar yara rule from FireEye's red team tool countermeasure repo

### Changed

* arguments can now use `/arg=value` form in addition to `/arg:value`

### Fixed

* few kerberoasting fixes


## [1.6.1] - 2020-12-09

### Added

* /autoenterprise flag to automate retrying failed kerberoasting attempts (@0xe7)
* support for CVE-2020-17049 using the /bronzebit switch (@0xe7)
* initial support for basic silver tickets, without a PAC (@0xe7)

### Fixed

* Cross domain enterprise principal kerberoasting (@0xe7)
* Kerberoasting using DC IP and supplying a TGT (@0xe7)


## [1.6.0] - 2020-11-06

### Added

* OPSEC
    * `/opsec` switch to make `asktgt` / `asktgs` / `s4u` build requests more realistic (@0xe7)
    * Randomized sequence numbers (@0xe7)
    * Added proper checksums (@0xe7)
    * Added enc-authorization-data to TGS-REQs (@0xe7)
    * Don't send AS-REQ when preauth is disabled (@0xe7)
    * Automation of requesting forwarded TGT when requesting a service ticket for unconstrained systems (@0xe7)
    * Added PA-DATA PA-PAC-OPTIONS to normal TGS-REQ when using `/opsec` (@0xe7)
* Start of smartcard/PKINIT support (@CCob)
    * `/password` support
* Support for `/spns` option when kerberoasting (@0xe7)
* Support for NT-Enterprise principals for service ticket requests on both the `asktgs` and `kerberoast` commands (@0xe7)
* Support for modifying S4U2Self tickets to be able to impersonate any user on the requesting machine (@0xe7)
* Cross-domain `s4u` / `asktgs` support (@0xe7)
* `/runfor:X` flag for the `monitor` command (@G0ldenGunSec)
* IPv6support (@royreinders)

### Changed

* `kerberoast /user:X` now takes multiple comma separated values

### Fixed

* Casing fix for AES key salts
* Kerberoasting when using TGT to authenticate but not supplying SPNs (@0xe7)
* GetDCName() issue on non-domain-joined systems
* Nonced randomized
* Fixes for issues from non domain machines (@VbScrub)
* Replaced checks for "NT Authority\System" string with SID comparison
* /rc4opsec service name fix
* LDAP paged searching (@cnotin)
* TGS-REQ AES formatting (@Ion Todd)



## [1.5.0] - 2020-01-31

### Added

* to any command that outputs base64 ticket blobs
    * the universal `/nowrap` argument prevents base64 ticket blobs from being display-wrapped

* the **/consoleoutfile** argument to redirect console output to a file, and the public `MainString("command")` function to work over PSRemoting (see end of README.md)

* **brute** action (from @Zer1t0)
    * Performs password bruteforcing attacks using raw AS-REQs

* to **triage**/**klist**/**dump** actions
    * More flexible targeting with **/user**/**/LUID**/**/service**/**/server**/

* to the **kerberoast** action
    * **/pwdsetafter**, **/pwdsetbefore**, and **/resultlimit** arguments for better targeting (from @pkb1s)
    * **/stats** flag to list statistics of user accounts without actually roasting them
    * **/ldapfilter** argument for adding custom LDAP filters to the user search query
    * **/simple** argument for output file formatting but to the console

* to the **asreproast** action
    * **/ldapfilter** argument for adding custom LDAP filters to the user search query

* to the **asktgt**/**asktgs**/**s4u** actions
    * option to save .kirbi file to disk (from @audrummer15)

* to the **s4u** action
    * the cross-domain s4u support (from @0xe7)

* **currentluid** command to display the current logon sesion ID

### Changed
* LSA.cs got a complete overhaul for reusability and flexibility (thanks for the help @leechristensen !)
* **kerberoast** action updated to exclude disabled accounts by default
* **harvest** mode's **/interval** argument is now in seconds, to match **/monitor**
* **harvest** / **/monitor** modes revamped
    * now no longer depend on searching the event logs for 4624 events
    * full set of current TGTs are extracted each monitor round

### Fixed

* Some timestamp converting code in the ticket extraction section
* KERB_RETRIEVE_TKT_REQUEST fix for x32 systems (from @0xRCA)
* Fixed AES salt generation (from @monoxgas)
* Fixed accidental ticket request behavior when dumping from LsaCallAuthenticationPackage
* Fixed `renew` command invocation
* Fixed `asreproast` LDAP querying (broke at some point)


## [1.4.2] - 2019-03-01

### Added

* **tgssub** action
    * Substitutes in alternate sname (cifs) or SPN (ldap/computer.domain.com) into an existing service ticket


## [1.4.1] - 2019-02-25

### Added
* to **asktgs** action
    * /enctype:[RC4/AES128/AES256/DES] now forces that particular encryption type in the TGS-REQ

### Changed
* **asktgt** action
    * Returned tickets now run through the **describe** command
* **describe** action
    * Kerberoast hash now only extracted from RC4_HMAC tickets


## [1.4.0] - 2019-02-16

### Added
* **hash** action
    * hashes a given password to rc4_hmac form, and if /user and /domain supplied, calculates aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, and des_cbc_md5 forms 

### Changed
* **kerberoast** action
    * Fixed query that checks that rc4_hmac is flipped in msds-supportedencryption types, because "lol Microsoft"
* **asktgt** action
    * /aes128 and /aes now supported for **/enctype** when used with **/password**
* **crypto** 
    * Replaced @qlemaire's PR of Kevin-Robertson' Get-KerberosAESKey hash code with @gentilkiwi's KERB_ECRYPT HashPassword approach
* **README**
    * added @elad_shamir into the references


## [1.3.6] - 2019-02-14

### Added
* **kerberoast** action
    * /rc4opsec option to use **tgtdeleg** and filter out AES-enabled accounts
    * /aes option to AES roast only AES-enabled accounts

### Changed
* **kerberoast** action
    * Default user query searches for accounts with RC4 enabled
    * Default behavior when using the /tgtdeleg flag requests RC4 for ALL accounts (including AES)
    * Display "Supported ETypes" in enumerated output
* **tgtdeleg** action
    * Changed the default requested SPN from HOST/dc.domain.com to cifs/dc.domain.com

### Fixed
* Kerberoast hash display for some option combinations


## [1.3.5] - 2019-02-13

### Changed
* **kerberoast** action
    * now has /ticket option to use an existing TGT for Kerberoasting
    * now has /usetgtdeleg option to use **tgtdeleg** option as the TGT for Kerberoasting
    * LDAP user search path and number of found users now output
* **describe** action
    * Kerberoast hash output now generated for service tickets

### Fixed
* Kerberoast hash display but when /spn and /outfile were specified
* Kerberoast samaccountname now properly put into hash output


## [1.3.4] - 2019-02-12

### Changed
* **kerberoast** action now has /domain and /dc like **asreproast** action
* **kerberoast** and **asreproast** now properly work over domain trusts
* **triage** command now works for the current non-elevated user, outputting current LUID as well
* Current LUID output also added for non-elevated **dump** and **klist** commands
* Added Opsec section in README.md


## [1.3.3] - 2019-02-11
### Changed
* Landed @leechristensen's cleanup of the Monitor4624 code
* Restructed the README.md to match the help output, updated all examples, added table of contents


## [1.3.3] - 2019-02-07
### Added
* **triage** action
    * Quickly triages the users and present tickets on a machine

### Changed
* **dump** and **klist** changed default LUID output to hex format


## [1.3.2] - 2019-02-06
### Added
* **kerberoast** and **asreproast** actions
    * Added /outfile:X to output hashes to a file, one hash per line

### Changed
* **asreproast** changed asreproast's default behavior to match **kerberoast**
* Clustered the default output help menu around function (things were getting crowded)


## [1.3.1] - 2019-02-06
### Fixed
* Changed underlying LUID logic to handle UInt64s


## [1.3.0] - 2019-02-05
### Added
* **klist** action
    * lists current user's (or if elevated, all users') ticket information

### Changed
* **s4u** landed @eladshamir's pull requests
    * RBCD support
    * support loading TGS from Kirbi to skip S4U2Self and perform S4U2Proxy only
    * perform S4U2Self only
    * print output for each stage
* **asreproast** landed @rvrsh3ll's pull request
    * added hashcat output format
* **asktgt** landed @qlemaire's pull request
    * now accepts a /password:X parameter
* **monitor** and **harvest** landed @djhohnstein's pull request
    * ticket extraction can now be saved to the registry with the "/registry:X" flag

### Fixed
* **dump** display of service tickets with multiple slashes
* response buffer size in lib/Networking.cs increased for large ticket responses
* landed @BlueSkeye's fixes for PTT bug fix, TicketFlags display, and dead code removal in PA_DATA.Encode


## [1.2.1] - 2018-10-09
### Changed
* Merged @mark-s' PR that broke out Program.cs' commands into 'Command' classes for easier command addition.
* Commands that pass /dc:X are now passed through Networking.GetDCIP(), which resolves the DC name (if null) and returns the DC IP. Code refactored to use this centralized resolver.
* The /user:USER flag can now be /user:DOMAIN.COM\USER (auto-completes /domain:Y).
* The **harvest** command now returns the user ticket with the latest renew_till time on intial extraction.


## [1.2.0] - 2018-10-03
### Added
* **changepw** action
    * implements the AoratoPw user password reset from a TGT .kirbi
    * equivalent to Kekeo's misc::changepw function


## [1.1.0] - 2018-09-31
### Added
* **asktgs** action - takes /ptt:X, /dc:X, /ticket:X flags like asktgt, /service:X takes one or more SPN specifications
* **tgtdeleg** action - reimplements @gentilkiwi's Kekeo tgt::deleg function
    * uses the GSS-API Kerberos specification (RFC 4121) to request a "fake" delegation context that stores a KRB-CRED in the Authenticator Checksum. Combined with extracting the service session key from the local cache, this allows us to recover usable TGTs for the current user without elevation.
* Added CHANGELOG.md

### Changed
* **s4u** action now accepts multiple alternate snames (/altservice:X,Y,...)
    * This executes the S4U2self/S4U2proxy process only once, and substitutes the multiple alternate service names
        into the final resulting service ticket structure(s) for as many snames as specified
* **asreproast** action
    * added eventual hashcat output format, use "/format:<john/hashcat>" (default of "john")

### Fixed
* **dump** action now correctly extracts ServiceName/TargetName strings
* **asreproast** action - fixed salt demarcation line for "asreproast" hashes
* **kerberoast** action
    * Added reference for @machsosec for the KerberosRequestorSecurityToken.GetRequest Kerberoasting Method()
    * Corrected encType extraction for the hash output


## [1.0.0] - 2018-08-24

* Initial release

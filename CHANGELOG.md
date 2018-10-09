# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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

# Naming and terminology

Palisade is an educational, vendor-neutral project. Issues, code, docs and commit messages
must not name commercial products, vendors or their trademarked feature names.

| Use this | Not this |
|---|---|
| OS-native code integrity policy (XML → binary, base/supplemental) | vendor product names for the OS policy engine |
| OS-native legacy rule-collection policy (Application Identity service) | vendor product names for the legacy engine |
| `CertifiedDriver`, `CertifiedDriverPublisher`, `CertifiedDriverFilePublisher` | the OS vendor's hardware-certification level names |
| `RequireCertifiedDrivers` (policy option 7) | the OS vendor's option literal |
| hypervisor-enforced code integrity | vendor marketing names |
| OS download-reputation check | vendor marketing names |
| office suite / word processor / spreadsheet / PDF reader / browser | product names |
| application containment | vendor names for per-app restrictions |
| owner-based trust | vendor names for NTFS-owner trust |
| HTTP event collector, cloud SIEM data-collection API, team-chat webhook, ITSM ticketing via REST | product names |
| file reputation lookup provider (pluggable) | product names |

The compilers in `palisade-policy` map neutral names to the exact identifiers the operating
system's policy schemas require. Those literals live only in compiler code and test fixtures.

OS components, open standards and government frameworks are fine to name: Windows,
PowerShell, Authenticode, ETW, NTFS, UAC, AMSI, Windows Installer (MSI), Group Policy,
Active Directory, LDAP, OIDC, SAML, SCIM, syslog, CEF, LEEF, OpenTelemetry, OpenAPI,
gRPC, Postgres, Essential Eight, ASD, ISM.

# palisade-fileid

File identity: PE parsing, hashing (SHA-256, Authenticode, page and flat hashes), signature and certificate chain extraction, version-info metadata, and Windows Installer package identity.

**Status:** early. PE header and version-resource parsing, flat hashing, the Authenticode image hash, page hashes, Authenticode signature verification, certificate chains, signer trust and signer identity, timestamps, expiry and revocation, catalog parsing, catalog signatures and the catalog member index, content-based file type detection, Windows Installer package identity and signatures, and script signature blocks and signed metadata work; the rest of [#3](https://github.com/jusso-dev/palisade/issues/3) is still to come.

## What is here

- `pe`: a hardened PE32 / PE32+ parser ([#45](https://github.com/jusso-dev/palisade/issues/45)).
  `pe::parse(&bytes)` reads the DOS, COFF and optional headers, all 16 data
  directories, the section table, the debug directory (CodeView PDB path, GUID
  and age, `REPRO`, POGO), the certificate table location, overlay, PE checksum
  (stored and computed) and per-section entropy. It walks the resource tree and
  parses the version resource: `VS_FIXEDFILEINFO`, every `StringFileInfo`
  language block, language selection and the file-name fallback chain.
  It also reads the import table (module and function names; the listing
  is capped at 10,000 functions, but module names are still checked past
  that cap) and the export
  table (names, ordinals and forwarders; `CPlApplet`, `DllRegisterServer`,
  `DllGetClassObject` and `ServiceMain` are found by the loader's binary
  search over the whole name table; a name the search cannot read leaves
  the answer unknown and marks the table truncated and malformed, so a
  `false` is reliable only when `ExportInfo::truncated` is not set). Kernel modules are found anywhere in
  the first 65,536 import descriptors (`MAX_IMPORT_DESCRIPTORS`). Any other
  module is found only among the names kept: descriptors past that limit
  are not read, at most 1 MiB of module names is kept
  (`MAX_MODULE_NAME_BYTES`), and a name cut at 512 bytes, or one that is
  not valid UTF-8, never matches. So
  a negative `ImportInfo::imports_module` answer is reliable only when
  `ImportInfo::truncated` is not set. It classifies kernel drivers:
  subsystem native plus a kernel import, an `INIT` section or
  `IMAGE_FILE_SYSTEM`, with the reasons. It parses the application
  manifest (`requestedExecutionLevel`, `uiAccess`, `autoElevate`,
  `dpiAware`, assembly identity, `supportedOS`) with a bounded XML parser
  that rejects DTDs and undefined entities (XML 1.0 in UTF-8 only; XML 1.1
  and UTF-16 manifests are errors, and so is an undeclared namespace
  prefix), and gives the `requires_elevation` heuristic with its reason. The
  installer heuristics apply only when there is no manifest; a process
  manifest that is present but unreadable counts as requiring elevation. `NormalizedName` gives the
  trimmed, whitespace-collapsed NFC and case-folded forms of a version
  string for matching, keeping the original. `pe::legacy::parse` reads the
  identity of 16-bit NE and 32-bit LE / LX files: the format, the target OS,
  the module name (the first resident name) and the description (the first
  non-resident name). A name outside the file or its declared table is absent,
  with a warning. Bytes that are not printable ASCII become U+FFFD and are
  flagged, so a rule never matches a guessed code page. Big-endian linear
  headers are identified but their names are not read.
- `hash`: flat SHA-256, SHA-1, MD5, SHA-384 and SHA-512, computed together in
  one streaming pass ([#46](https://github.com/jusso-dev/palisade/issues/46)).
  SHA-256 is the primary identity. SHA-1 and MD5 are not collision resistant
  and are computed only for interop; they must never be the sole basis of an
  allow decision ([ADR 0008](../../docs/adr/0008-cryptographic-algorithms.md)).

  The hash cache (#46) keeps digests while a file is unchanged.
  `hash::HashCache` is an LRU bounded by entries and bytes (defaults 1,000,000
  and 256 MiB). Entries are keyed by a `FileKey`: volume serial, 128-bit file ID,
  change journal ID, USN, last-write time and size. On volumes without a change journal the key
  is the normalised path, size and times, marked weak. Any change to a key
  component is a miss. Values are tiered (flat hashes, Authenticode image
  digests), and each tier carries a version, so a library change invalidates
  only the tiers it affects. Persisted records carry an HMAC-SHA-256 tag under
  an agent-held key. A record that fails it is discarded and counted as a
  tamper event, and the file is rehashed. `HashVerifyMode` (`Cached`,
  `Recompute`, `RecomputeUntrustedLocations`) says when a cached digest may
  be used at execution time. `hash::hash_through` opens a file once and
  stamps, hashes and stamps again through that one handle, so a link
  swapped mid-way cannot pair one file's key with another's content. It
  uses the cache or hashes the file, rehashes a file that changed while it
  was read, up to three times, before giving up as `Unstable`, and never
  caches a digest whose size differs from the key's. Each attempt rewinds the
  handle first. A rename moves a file's USN, so it misses unless the change
  journal consumer carries the entry over (`HashCache::key_of` finds the
  cached key by file ID; `HashCache::rekey_after_rename` accepts only a
  later USN with the same journal, size and last-write time). `HashLimiter` bounds
  concurrent hashes (default: half the CPUs). `HashMetrics` counts bytes
  hashed, hit ratio, average latency, evictions, tamper events and unstable
  files. `skip_for_inventory` leaves cloud placeholders unread during
  inventory scans.
- `win::file` (Windows, `os-trust` feature): the hash cache's Windows
  backend (#46). `open_for_hashing` shares read, write and delete and sets
  `FILE_FLAG_SEQUENTIAL_SCAN`, so hashing never blocks a writer.
  `WinStamps` implements `hash::FileStamp` from the opened handle: the
  strong key from `FileIdInfo`, the change journal ID and the file's USN, or
  the weak key (the normalised final path of the handle) when the volume
  has no active journal. `FileFacts` reads the file ID, USN, the four
  timestamps, attributes, link count, size and volume. `hash_open_file`
  hashes an open handle through a memory mapping, 8 MiB at a time, for
  files of 16 MiB or more on a local fixed volume, and with buffered reads
  otherwise, and defers cloud placeholders during inventory scans.
  `hash_streams` hashes each alternate data stream on its own as a
  `path:stream` identity. The variable-length OS records (the stream list
  and the USN record) are parsed by the portable `fsctx::ntfs`, which is
  bounded, tested and fuzzed on every OS.
- `authenticode`: the Authenticode PE image hash
  ([#47](https://github.com/jusso-dev/palisade/issues/47)), which stays the
  same when a file is signed, re-signed or stripped. `HashRanges::from_pe`
  lists the bytes hashed (the whole file minus the `CheckSum` field, the
  certificate table entry and the certificate table, zero-padded to 8 bytes
  when unsigned), and `RangeHasher` streams the file through them in one
  pass, alongside the flat hashes if wanted. SHA-256 and SHA-1 are always
  computed. Images whose layout departs from the specification (gaps or
  overlaps between sections, data after or a misaligned certificate table,
  and so on) are reported as `AuthenticodeStatus::NonConformant`, and their
  flat hash is the identity to use.
- `authenticode::page`: page hash tables (#47). `page_hash_table(data, info,
  alg)` builds the SHA-1 (version 1) or SHA-256 (version 2) table a signer
  embeds: one entry per 4 KiB page (the headers minus the `CheckSum` field
  and certificate table entry, then each section's raw data), each page
  zero-padded, then a zero entry at the end of the section data. The tests
  check it entry for entry against tables an open-source signer made over
  synthetic images. `verify_signature_page_hashes` checks a signature's
  table against the file and reports the first page that differs; it
  checks only tables from signatures that verify cryptographically.
  `AuthenticodeHashes::page_sha256` / `page_sha1` give the code integrity
  "page hash" rule value (the header page's digest). On Windows CI a test
  runs the OS policy cmdlets and compares every Authenticode and page hash
  rule they emit with these values. Images that are not
  Authenticode-conformant, or whose headers exceed one page, have no table.
- One read for every digest: `authenticode::hash_image_file` and
  `hash_image_reader` parse the PE headers from the first bytes
  (`pe::parse_prefix`) and then compute the flat hashes, Authenticode
  digests and page hash tables from the same sequential read. With
  `ImageHashOptions::parallel` each digest runs on its own thread over the
  same buffers. A file whose length changes while it is read is an error
  (`HashError::SizeChanged`).
- `authenticode` signatures
  ([#48](https://github.com/jusso-dev/palisade/issues/48)): `verify_pe`,
  `verify_signatures` and `verify_certificate_table` read every
  `WIN_CERTIFICATE` entry (revision 1.0 or 2.0, type PKCS_SIGNED_DATA; other
  entries are recorded and skipped), decode each PKCS#7 SignedData and its
  nested signatures (`1.3.6.1.4.1.311.2.4.1`), and check each one: the
  `messageDigest` attribute against the `SpcIndirectDataContent`, the
  signature over the authenticated attributes with the signer certificate's
  key, and the signed image digest against the file's Authenticode digest.
  The `SignatureReport` holds one `SignatureInfo` per signature (index and
  total, kind, algorithms, key size, digest match, signature check, status,
  program name, more-info URL, statement type, signing time, signer
  certificate, every certificate in the blob, page hash table, timestamp
  tokens, OS code integrity compatibility and warnings), the primary
  signature (the first valid one with the strongest digest; SHA-2 beats
  SHA-1) and the file's `SigningState` (`Unsigned`, `Valid` or
  `Invalid(reason)`). `VerifyOptions::tolerate_digest_mismatch` (off by
  default) reports the signer attributes of a mismatched signature, marked
  `untrusted_signer_attrs`, and records every use in the report.

  A `Valid` signature is cryptographically sound and signs this file. It
  does **not** mean the signer is trusted: certificate chains, EKUs and
  signer attributes are judged by `evaluate_trust` (#49), and timestamps,
  expiry and revocation by `evaluate_validity` (#50).

  Cryptography goes through one thin module over `ring` (ADR 0008), which
  verifies RSA PKCS#1 v1.5 (SHA-1, SHA-256, SHA-384, SHA-512; 1024 to 8192
  bits, 2048 and up for SHA-384), RSA-PSS (SHA-256, SHA-384, SHA-512, with
  MGF1 over the same digest and a salt as long as it; 2048 to 8192 bits) and
  ECDSA P-256 and P-384 with SHA-256 or SHA-384. **ECDSA P-521, Ed25519,
  Ed448, other pairings and other PSS parameters are reported as
  `Unsupported`, never as valid.** MD2 and MD5 signatures are parsed and
  reported as `WeakAlgorithm`, never trusted. OS code integrity accepts only
  RSA signers up to 4096 bits, so `os_ci_compatible()` is false, with the
  reasons, for ECC signers, larger RSA keys and MD2 or MD5.

- `fsctx`: file-system context
  ([#54](https://github.com/jusso-dev/palisade/issues/54)), the attributes
  that come from where a file is stored rather than from its content. All of
  it is pure and runs on every OS:
  - `fsctx::path`: one canonical form for every way of naming a file, so a
    name cannot dodge or borrow a path rule by being spelt differently
    (threat model T-engine-04, AT-04). This is name normalisation only: it
    does not say which file a name opens. Through a link, `C:\trusted\link.exe`
    can open `C:\untrusted\payload.exe`, so a caller must match the opened
    file on the handle's final path (`PathForms::canonical`, filled from
    `win::fsctx::final_path`), not on the normalised name (T-agent-13). It handles `\\?\`, `\??\`, `\\.\`,
    `GLOBALROOT`, NT device paths, volume GUID paths, UNC, `.` and `..`,
    trailing dots and spaces, reserved device names, alternate data stream
    syntax, NTFS-style case folding and paths up to 32,767 UTF-16 units.
    Possible 8.3 short names must be expanded through the
    `ShortNameResolver` hook before a path yields a match key.
  - `fsctx::acl`: a hardened self-relative security descriptor parser, and
    the writability decision: which write-type rights any non-administrator
    may hold on a file and on each ancestor folder. Deny ACEs, ACE order,
    inherit-only ACEs, generic rights and the owner's implicit rights are
    handled; anything the model cannot decide is reported as possibly
    writable. It also reports the rights that rule out owner-based trust,
    because NTFS keeps a file's owner when its content is overwritten in
    place (T-engine-11, AT-03.3, AT-19.5b). The administrator SID list
    defaults to the one the OS uses for path-rule protection.
  - `fsctx::sid`, `fsctx::volume`, `fsctx::vars`, `fsctx::motw`: SIDs,
    volume and location classification, path variables (`%WINDIR%` and so
    on) and the `Zone.Identifier` mark-of-the-web parser. A mark may make a
    file less trusted, never more. Location classes fail closed to `Unknown`
    when an input is missing. Owners count only on NTFS or ReFS local fixed
    disks, never on removable media, virtual disks or network shares.
  - `fsctx::writable`: `WritabilityCache` evaluates each distinct
    security descriptor once (keyed by the SHA-256 of its bytes and the
    object kind; `evict` for security-change journal records, #60).
    `assess_ancestors` is `assess_path` over an iterator, so the chain is
    not built first, and can stop at the first user-writable folder.
    `enumerate_user_writable_dirs` walks folders breadth first, bounded in
    depth and count, through a `DirectorySource`, and lists the ones a
    principal set may write to (for #17 and #212).
  - `win::fsctx` (Windows, `os-trust` feature): reads a file's final path
    (links resolved, short names expanded) and its `Zone.Identifier` stream.
  - `win::security` and `win::access` (Windows, `os-trust` feature): the
    owner, group and DACL from a handle (`GetSecurityInfo`), account names
    (`LookupAccountSidW`, cached), owner classification that is reported
    only on local NTFS or ReFS, writability of a real path and every folder
    above it (the folders the opened file really lives in, from its
    final path, plus the path's own folders; a final link or any reparse
    point on a chain fails closed), and the OS access check
    (`AuthzAccessCheck` with a synthetic token of the standard user's SIDs).
    `cross_check_writability` compares that check with the portable
    evaluator: the evaluator must never miss a right the OS grants.
    `OsDirectories` lets `enumerate_user_writable_dirs` walk real folders
    without following junctions or mount points. Windows tests build a
    weak-ACL fixture tree (a user-writable folder under a locked one, an
    explicit deny, a `WRITE_DAC` grant to Users) and compare every result
    with the OS access check, and check the stock system folders too.
  - `win::volume` (Windows, `os-trust` feature): `read_volume` fills a
    `VolumeInfo` for the volume an open handle is on (drive type, bus and
    hot-plug state from the storage queries, OS volume by GUID, file
    system and journal support), and `is_case_sensitive_dir` reads the
    per-directory case-sensitivity flag. A file is a network file if any
    of three signs says so (the remote-protocol query, the handle's NT path
    under a redirector device, the name it was opened by), and a handle with
    no local volume root keeps only its serial, so a share never reads as
    local NTFS. Windows tests attach a VHD and share a local folder over
    SMB.
  - `fsctx::dfs` and `win::paths` (Windows, `os-trust` feature): the OS
    path forms of an opened file (NT, volume GUID, final, long with every
    8.3 name expanded by `OsShortNames`, the UNC form of a mapped drive in
    the caller's logon session) and DFS targets through `DfsCache`, which
    bounds each lookup to 2 s and caches referrals and failures.
    `PathForms::network_key` gives one key for a mapped drive, a DFS path
    and a short-name spelling of one file on a share.
  - `fsctx::streams`, `fsctx::reparse`, `fsctx::meta` and `win::links`
    (Windows, `os-trust` feature): alternate data streams with a tag for
    well-known names, and each stream's content classified by the bounded
    streaming classifier with the stream's own name as the hint (a tag is
    not a pass: tagged streams are classified too; a stream that was not
    read, or whose kind the classifier could not establish, counts as
    possibly executable); reparse points
    (symbolic links, junctions, volume mount points, app execution aliases
    with the package family name, app ID and target they claim (unverified
    until checked against the installed package, #53), cloud placeholders,
    deduplication), parsed by a bounded, fuzzed parser; hard links, counted
    and listed up to 16 when the path still names the opened file; and the
    file ID, USN, timestamps and attributes.
    `win::links::read_details` fills them into an `FsContext`. Windows tests
    make a symbolic link, a relative link, a junction, a mount point and an
    app execution alias, 21 hard links and tagged and executable streams.
- `authenticode` certificate chains, signer trust and identity
  ([#49](https://github.com/jusso-dev/palisade/issues/49)):
  - `CertSummary::from_der` parses an X.509 v1, v2 or v3 certificate. It
    keeps the subject and issuer as ordered RDNs with their raw DER, typed
    components (`CN`, `O`, `OU`, `L`, `S`, `C`, `E`, `serialNumber`,
    `businessCategory`, `jurisdictionC` and others) and a DN string in the
    order OS tooling prints (`CN=…, O=…, L=…, S=…, C=…`). It also extracts
    the serial, validity, signature and key algorithms, key size, SHA-1 and
    SHA-256 thumbprints, the TBS hash under the certificate's own digest
    (40, 64, 96 or 128 hex characters) and always under SHA-256, key
    identifiers, basic constraints, key usage, EKUs, certificate policies,
    CRL distribution points, OCSP and CA-issuer URLs, and whether it is
    self-signed. The TBS hash covers the exact `tbsCertificate` bytes in the
    file; nothing is re-encoded. DER is strict: explicitly encoded DEFAULT
    values (a v1 version field, `critical` FALSE, `cA` FALSE) are rejected,
    and ECDSA signature algorithms must have no parameters. Name values
    decode exactly or are flagged lossy: TeletexString is read as UTF-8
    when valid and as 8-bit text otherwise, as the OS renders it, and a
    BMPString surrogate is lossy (BMPString is UCS-2). So is a character
    outside a restricted type's repertoire (a letter in a NumericString,
    an `&` in a PrintableString): such a name is shown but never used as
    an identity. Extensions that
    are only reported (alternative names, CRL distribution points, AIA,
    and certificate policies with a qualifier other than a CPS pointer or
    user notice) count as unhandled when critical. `CertSummary` serialises
    to JSON with stable field names (serde), and `pem()` exports it.
  - `eku` is the EKU catalogue: Code Signing, Time Stamping, Lifetime
    Signing, the hardware (driver) certification EKU, OS component, Protected
    Process (Light), Early Launch Antimalware, kernel-mode code signing, HAL
    extension, package store signing, document signing and others. Unknown
    EKUs keep their OID. `Eku::os_policy_value` gives the `01`, length, OID
    body form that OS-native policy writes.
  - `build_chain` orders the certificates embedded beside a signer into the
    **as-provided chain**, with no online lookups, and builds the **full
    chain** against a `TrustConfig`: trust anchors and intermediates that
    policy ships (#6, #9), and the well-known root table, which is data from
    policy too. It reports `chain_complete`, `anchored_to`, `anchor_source`
    and `well_known_root_id`. The intermediates, the "PCA" (the highest
    certificate in the file below the root) and the root come from the full
    chain's embedded part. The embedded certificate set is not signed, so a
    certificate someone added that is not on the trusted path can never
    become the PCA.
  - Every link must match by issuer name (byte for byte) and key
    identifier. The issuer must be a CA with `keyCertSign` (if it has a key
    usage) and room in its path length, and the child's signature must
    verify with the issuer's key, so a forged issuer name never links.
    Anchors are held to the same rules when they issue: a pinned end-entity
    certificate can be trusted as itself but issues nothing. Only a v1 or
    v2 anchor, which has no extensions to say so, is taken as a CA. No
    certificate may carry a critical extension this crate does not process,
    except a configured anchor.
  - Trust is decided **downwards from the anchors**: each certificate
    whose issuer name matches a trusted certificate is checked with that
    trusted key, and only links verified this way can make an anchored
    path. Only certificates reachable upwards from the leaf by name are
    looked at, so unrelated policy entries cost nothing and appear in no
    report. At most 64 embedded certificates are tried (parsed or not),
    each checked at most once per trusted key whose name it claims. The
    trust phase has its own budget, which earlier and nested signatures
    cannot spend. Links into the leaf and policy certificates come first,
    on a pool of their own (4096 candidate steps and 4096 checks per chain)
    that links into other embedded certificates never spend, so nothing a
    file adds can starve them. That pool is spent only by the leaf and
    policy certificates, so only the trust configuration itself (more than
    64 trusted keys sharing one subject name) can exhaust it; that fails
    closed, untrusted, with `WorkLimitReached` in the chain's issues.
    Verified results are cached per key, not per certificate.
  - The as-provided chain (and, when nothing is anchored, the full chain)
    is then searched upwards with whatever keys the file holds: every path
    is enumerated, loops are detected, paths stop at 10 certificates, and
    the 8 best are kept (anchored, then complete, then permitting code
    signing, then shortest), with
    cross-signed paths as alternatives. These checks spend at most 128 per
    chain and 512 per file. Running out fails closed and never affects
    trust.
  - `evaluate_trust` builds the chain of every valid signature in a
    `SignatureReport` and chooses the primary signature **after** trust:
    the first trusted signature with the strongest digest (the weaker of
    its image and signer digests, as in #48). A signer is
    trusted when its chain reaches a configured anchor, every certificate in
    it permits code signing, and its key usage allows digital signatures.
    An untrusted signer, including a nested signature anyone could have
    appended, never becomes primary. The trusted primary yields a
    `SignerIdentity`: `publisher_name` (leaf `CN`, or `O`, recording which;
    never a blank, inexact or control-character name), `publisher_dn` (only
    when every attribute decodes exactly), `publisher_product` (with
    `ProductName`),
    `publisher_os_rule` (PCA TBS hash or well-known root ID, plus leaf `CN`)
    and `file_publisher_os_rule` (plus file name and minimum version, both
    only for an `os_ci_compatible` signer), with the reason for any that
    cannot be made. A file with no trusted signer
    gets a `VendorHint` from `CompanyName` instead, marked unverified. It is
    a separate type, so it can never satisfy a publisher rule.
  - Constraint checks for policy: `leaf_has_eku`, `chain_has_eku`,
    `permits_code_signing`, `meets_min_key_bits`, `cert_sig_algs_allowed`
    and `os_ci_compatible` (RSA keys of at most 4096 bits in the whole
    chain).
  - OS store certificates: `TrustConfig::add_os_store_anchor` and
    `add_os_store_intermediate` take certificates the Windows backend reads
    from the machine root and intermediate stores (`os-trust`, #48). A chain
    that reaches such an anchor reports `anchor_source = OsStore`, so policy
    can tell OS-store trust from policy-shipped trust.
  - Relaxations for one trusted certificate:
    `TrustConfig::ignore_basic_constraints(pin)` lets a certificate pinned by
    SHA-256 thumbprint or TBS hash issue although it is not a CA or its path
    length is exceeded. Its key usage must still allow `keyCertSign`, the
    child's signature must still verify, and trust is still decided from the
    anchors down. Every link that used it is listed in
    `ChainReport::basic_constraints_ignored`. `ChainReport::time_nesting_violations`
    lists certificates whose validity is not inside their issuer's; the OS
    ignores this for code signing, so it is reported, and #50's
    `require_time_nesting` decides whether it fails.
  - `SignerIdentity::attach_package_publisher` carries a packaged app's
    `PublisherDisplayName` (#53) onto the signer's identity, only when the
    manifest's `Identity@Publisher` is the signer's own DN. It is for
    display: rules never match on it.
  - Certificate extraction: `extract_certificates(bytes, selection)` lists
    the certificates a signed PE image (every certificate table entry and
    nested signature), signed cabinet or bare PKCS#7 (detached signature,
    catalog, package signature) carries: all of them, each signer (leaf), or
    the self-signed roots. `CertificateBundle` collects them from many files,
    once each, and writes a PEM bundle or one DER file per certificate (named
    by thumbprint), for building trust bundles offline. The `pal fileid
    certs` command (#55) wraps it.

  `SignatureReport::primary` is still #48's choice by cryptographic
  validity alone, and `TrustReport::primary` ignores time and revocation.
  Anything that decides whether to allow a file must use
  `ValidityReport::primary` (below). The OS trust store is never consulted
  for a decision; the `os-trust` cross-check below only compares. Catalog
  signing is `catalog` below.
- `authenticode::cross_check` and `win::trust` (the OS cross-check,
  [#48](https://github.com/jusso-dev/palisade/issues/48)):
  `win::trust::verify_file` (Windows, `os-trust` feature) asks the OS
  trust-verification API about the primary signature and each secondary
  (nested) signature of an open file, one call each, with no UI, no
  revocation check and no network retrieval. `cross_check` (portable)
  pairs each OS result with the signature the OS read and records whether
  they agree. It is a diagnostic: it takes the report by reference and
  never changes a verdict. An OS chain-trust failure (the test CA is
  untrusted) counts as "signature intact", since the OS checks the digest
  and signature first. This crate is stricter than the OS on
  non-conformant images and MD5, which show up as `OsAcceptsRustRejects`;
  `rust_accepts_os_rejects()` picks out the direction that could hide a
  bug. `tests/os_trust.rs` runs the differential over every signature
  fixture on the Windows CI runners.
- `authenticode` timestamps, expiry, revocation and the error taxonomy
  ([#50](https://github.com/jusso-dev/palisade/issues/50)):
  - `verify_timestamps` parses and verifies every timestamp on a
    signature: legacy Authenticode countersignatures (PKCS #9, whose
    `messageDigest` must be the hash of the signature value, with the
    `signingTime` as the time) and RFC 3161 tokens (both attribute OIDs),
    whose `TSTInfo` gives `genTime`, `messageImprint` (which must be the
    hash of the signature value), `policy`, `serialNumber`, `accuracy` and
    `tsa`. Each timestamp's own signature is verified, its signer is bound
    by the ESS `signingCertificate` attribute when present, and its
    certificate must chain to an anchor of a separate **TSA** `TrustConfig`,
    with the Time Stamping EKU in force for the whole chain and the time
    (widened by its accuracy) inside every chain certificate's validity.
    Every failure is a typed `TimestampStatus`; a copied or forged
    timestamp is `ImprintMismatch`.
  - `evaluate_validity(report, trust, context)` judges every signature:
    the **trusted signing time** is the earliest valid timestamp (the
    signer's own `signingTime` never counts). `ValidTimestamped` when that
    time is inside every chain certificate's validity, even if one has
    expired since; without a trusted time a signature is good only while
    its chain is valid now. A leaf with the Lifetime Signing EKU is
    `Expired` once expired, whatever the timestamp. `ExpiryPolicy` is
    `Ignore`, `TimestampAware` (the default) or `Strict`. SHA-1 timestamps
    after `sha1_timestamp_cutoff` are not used (code 20);
    `sign_time_after` and `requires_countersignature` need a trusted time.
    "Now" is never earlier than the caller's clock floor, so turning the
    clock back cannot revive an expired signer; a clock before the floor is
    reported as `clock_suspect`, and then "not yet valid" alone does not
    fail.
  - Revocation is **data from the caller**: no I/O happens here. A
    `RevocationSet` holds offline entries from policy (by SHA-256
    thumbprint, TBS hash, or issuer and serial; including an imported OS
    disallowed list), revoked file hashes (code 19), and CRLs. `Crl::from_der`
    parses a CRL strictly (at most 8 MiB and 100,000 entries, unprocessed
    critical extensions rejected); a CRL is used only for certificates its
    issuer issued, and only if its signature verifies with that issuer's
    key (at most 32 CRL signature checks per file; a certificate a CRL
    beyond that may cover fails closed). Only a current CRL (with
    `nextUpdate`) can show a certificate is not revoked; any CRL's entries
    revoke. Every certificate of the signer's and each TSA's chain is
    checked, for chains that can pass at all. Every matching entry is
    judged on its own: a certificate revoked after the trusted signing time
    still counts for signatures made before
    (`revocation_honours_timestamp`), unless the reason is a key, CA or AA
    compromise and `strict_key_compromise` is set, so a later compromise
    entry cannot hide behind an earlier, milder one. Hex is matched
    ignoring case. With no trusted time, any entry revokes. `RevocationMode` and
    `RevocationFailure` record how the caller fetched and whether a missing
    answer fails open (default) or closed (code 1006).
  - OCSP responses are revocation data too. `OcspResponse::from_der` parses
    an `OCSPResponse` (RFC 6960, basic type) strictly: at most 1 MiB, 256
    `SingleResponse`s and 8 responder certificates; SHA-1 or SHA-256
    `CertID`s; unprocessed critical extensions (a critical nonce included)
    rejected. `RevocationSet::add_ocsp` adds one. A response answers for a
    certificate only when its `CertID` names it under its issuer on the
    chain, and the issuer signed it or delegated to a responder (a
    certificate it issued, with the OCSP Signing EKU) that did; the
    responder ID must name the signing key. A `revoked` answer revokes
    like a CRL entry, with its date and reason, however old; a `good`
    answer covers the certificate only while current; `unknown` says
    nothing. OCSP signature checks share the 32-per-file budget with CRLs.
  - `CertificateOptions` pin one certificate (by thumbprint or TBS hash)
    with an `ErrorIgnoreFlags` mask: ignore expiry, ignore revocation
    unknown, ignore invalid usage, allow untrusted root, ignore time
    nesting and ignore basic constraints. Allow untrusted root relaxes only
    a complete chain: an incomplete one (issuers stripped from the unsigned
    certificate set) always fails. Ignore basic constraints pins the issuer
    itself: `ValidityPolicy::relax_trust` passes those options to the
    `TrustConfig` chains are built with (#49), and a chain that used a
    relaxation for an issuer no option allows fails with code 1008. When
    `ValidityPolicy::require_time_nesting` is set (default off, as the OS
    ignores it for code signing), a chain that is not time nested fails
    with code 1007 unless an option on the chain ignores it. Every
    relaxation used is recorded in `SignatureValidity::relaxed` for the
    decision trace.
  - Every outcome is one `VerificationError` from `palisade-core`: codes 0
    to 28 are the OS code integrity `VerificationError` values with the
    same meaning, and 1000 to 1008 are Palisade's own. `status_error` maps a
    #48 `SignatureStatus` into it. `ValidityReport::primary` is the first
    signature that passes everything, ranked by digest as in #48 and #49,
    with its `SignerIdentity`.

  Fetching CRLs and OCSP responses (proxy settings, the 5 s timeout and the
  24 h response cache) belongs to the agent and server; this crate takes
  what they fetched as data.
- `catalog`: catalog-signed files
  ([#51](https://github.com/jusso-dev/palisade/issues/51)). A catalog
  (`.cat`) is a PKCS#7 SignedData over a certificate trust list (CTL,
  `szOID_CTL`) of member digests.
  - `parse_catalog` decodes one and verifies its signature with the
    Authenticode machinery above: the same DER reader, SignedData decoder
    (content type `szOID_CTL` instead of `SPC_INDIRECT_DATA`, and the
    `contentType` attribute must agree), signer certificate lookup,
    `messageDigest` check (over the CTL) and signature check. The
    signature is a `SignatureKind::Catalog` entry in a `SignatureReport`,
    so `evaluate_trust` gives its chain, trust and signer identity
    unchanged. Nested signatures on a catalog are reported and checked as
    DER, but not read: only the catalog's own signature counts.
  - `parse_ctl` decodes the CTL: subject usage (must include
    `szOID_CATALOG_LIST`), list identifier, sequence number, effective
    dates, subject algorithm (`szOID_CATALOG_LIST_MEMBER` for v1 SHA-1
    catalogs, `..._MEMBER2` for v2 SHA-256), each member's tag (UTF-16
    hex text in v1, raw digest octets in v2),
    `SPC_INDIRECT_DATA` digest (algorithm, digest and data type:
    `SPC_PE_IMAGE_DATA` for PE members, whose digest is the Authenticode
    hash; other types for flat-hashed files), `CAT_NAMEVALUE` pairs
    (`File`, `OSAttr`, `HWID*` and others, text or binary) and
    `CAT_MEMBERINFO`, plus catalog-wide name-value extensions (`OS`).
    DER is strict (an encoded default version or `critical` FALSE is
    rejected), an unknown critical extension rejects the catalog, and
    limits bound members (262,144), attributes (64 per member), name-value
    pairs (32), value bytes (8 KiB) and warnings (64).
  - `CatalogStoreBuilder` loads catalogs from bytes, files or a directory
    tree (`*.cat`, name order, links not followed, bounded depth and entry
    count) into a `CatalogStore`, within `StoreLimits` (catalogs, bytes
    per catalog and in total, indexed members). A file's length is checked
    against those limits before any of it is read. Each `CatalogSource`
    (`System`, `DriverStore`, `Policy`) is its own namespace with its own
    `TrustConfig`, so an organisation catalog is trusted only under the
    organisation's anchors. The catalog ID is the file's SHA-256, and each
    `CatalogRecord` holds the path, source, status, signer (chain, trust
    and identity, shared between catalogs with the same certificates and
    signature digests), the catalog signature's digest algorithm,
    member counts, subject algorithm, `os_attr`, effective date and
    claimed signing time. Only catalogs whose signature is valid are
    indexed, in sorted in-memory tables (44 bytes per SHA-256 member, 32
    per SHA-1 member). Every limit fails closed: what is not indexed
    matches nothing.
  - `CatalogStore::lookup` takes a file's `FileDigests` (Authenticode
    SHA-256 and SHA-1 for a conformant PE image, flat SHA-256 and SHA-1
    for a non-empty file) and tries them in that order. An Authenticode
    digest matches only PE members and a flat digest only other members.
    A digest is used only in the field for its own algorithm. Each
    catalog that lists the file is returned once, trusted catalogs first,
    SHA-2-signed before SHA-1-signed, with which digest matched.
    `CatalogMatch::relies_on_sha1` is true when either the member digest
    or the catalog's signature is SHA-1, because no allow decision may
    rest on SHA-1 alone (ADR 0008).

  - Catalog signatures under the #50 checks: given `ValidityOptions`
    (validity policy, revocation data, TSA anchors, now and clock floor),
    `CatalogStoreBuilder::validity` judges each catalog's signature as of
    when it was made: its own RFC 3161 or legacy timestamps, expiry
    (`ValidTimestamped` after the signer expires), Lifetime Signing,
    revocation of its chain, and revocation of the catalog file by its
    SHA-256 (code 19). The verdict is `CatalogRecord::validity`, and
    `CatalogMatch::usable` is true only for a trusted catalog that passed
    it; lookups rank usable catalogs first. Without validity options no
    catalog is usable, so an unchecked catalog never vouches for a file.
  - `CatalogSettings`: `catalog_lookup_enabled` (default on),
    `catalog_scope` (`System`, `SystemAndDriverStore`, `All`, the default)
    and `skip_catalog_for_paths` (normalised paths; a skipped lookup says
    which entry, for the log). `CatalogStore::lookup_with` and
    `CatalogIndex::lookup_with` apply them.
  - `CatalogIndex` is the persistent index: per catalog its ID, path,
    source, status, trust, usability, publisher, signer thumbprint, member
    count, OS attribute and effective date, plus the sorted member tables.
    `encode` writes it with an HMAC-SHA-256 tag under an agent-held key;
    `decode` checks the tag first, and asks for a full rebuild for another
    index format or library version. `remove_path` and `merge` apply the
    change feed's added, changed and removed catalogs (#60). Until
    `finish_build`, a miss is `CatalogLookup::Indeterminate`, never "not
    catalog-signed".
  - `build_catalog(entries, name, os_attr, this_update)` writes an unsigned
    v2 catalog definition (DER, SHA-256 members, sorted and deduplicated,
    file names and `OSAttr` as name-value pairs) from a recorded set of
    files, for organisation catalogs; signing it is #13/#18.

  Watching catalog directories (#60) and scheduling the first build at low
  priority (#65) are the agent's; the OS catalog database cross-check
  (`CryptCATAdmin*`) is the Windows backend's (#48). Folding a catalog
  match into the file's signing state (`CatalogValid`) is #55.

- `installer`: Windows Installer packages
  ([#53](https://github.com/jusso-dev/palisade/issues/53)): `.msi`, `.msp`,
  `.mst` and `.msm`. `installer::parse_installer(&bytes)` reads the
  compound file with a bounded reader (`installer::cfb`) that rejects any
  sector claimed twice, any FAT or directory loop, a duplicate name and a
  truncated chain, so an ambiguous container is an error, never a guess.
  It decodes the stream names, the string pool (2- and 3-byte references,
  long strings), `_Tables`, `_Columns` and typed rows, and returns an
  `InstallerIdentity`: the kind (from the root CLSID; a database with
  `ModuleSignature` is a merge module), the `Property` rows ProductCode,
  UpgradeCode, ProductName, ProductVersion (also as a quad), Manufacturer,
  ProductLanguage, ALLUSERS, MSIINSTALLPERUSER and ARPSYSTEMCOMPONENT, every
  summary information field (the revision number is the PackageCode), patch
  codes, obsoleted patches, target product codes, transforms and
  `MsiPatchMetadata` for a patch, the target and upgraded product codes and
  versions and the validation flags for a transform, and an inventory of
  `Binary` streams, `CustomAction` rows (DLL, EXE and script actions flagged
  as embedded executable content) and embedded `#cab` cabinets.

  The `\u{5}DigitalSignature` stream is verified by the same Authenticode
  code as PE signatures (`SignatureKind::Msi`, indirect data `SPC_SIPINFO`
  for the installer subject type), over the package's content hash: every
  stream in sorted order without the signature streams, then each storage's
  CLSID. `\u{5}MsiDigitalSignatureEx`, when present, must equal the metadata
  hash, and is included in the content hash. A tampered stream, a moved
  signature or changed metadata is a digest mismatch, never valid; the
  report feeds `evaluate_trust` and `evaluate_validity` like any other.

  `normalised_sha256` is a documented, Palisade-specific identity (medium
  strength): SHA-256 over every stream except the signature and summary
  streams, by path, plus the summary information without its four
  timestamps. Two copies of a package that differ only in build, save or
  signing times have the same value and different flat hashes. The exact
  algorithm is in the module documentation, and
  `tests/fixtures/installer/normalised.py` implements it independently.
  The pure parser runs everywhere; on Windows, `tests/installer_os.rs`
  checks the product fields, the PackageCode and the signature verdict
  against the OS installer API and the OS signature check.

- `filetype`: content-based file type detection
  ([#44](https://github.com/jusso-dev/palisade/issues/44)).
  `filetype::classify(&mut reader, name_hint)` decides what a file is from
  its magic numbers and structure, never from its name alone, and returns
  a `Classification`: the content `FileKind`, what the extension claims
  (`ExtensionKind`), `mismatch` and `mismatch_severity` (`None`, `Benign`,
  `Suspicious` for a PE named `.pdf`, `Critical` for a bidirectional
  override character or a disguising double extension), a `Confidence`,
  `heuristic` and `extension_assisted` flags, informational
  `ContentFlags`, the text encoding, a `parse_error` reason and
  `classifier_version`. It recognises PE (with `PeDetails`: `Exe`, `Dll`,
  `Driver`, `Efi`, `Cpl`, `Scr`, `Ocx` and `ResourceOnly`, the CLR header
  as IL-only or mixed, and ARM64X, ARM64EC and CHPE layouts), NE, LE, LX
  and DOS `MZ` programs, DOS `.com` programs (by name and size, flagged
  `heuristic`), compound files by root CLSID (installer database, patch,
  transform and merge module, and macro-capable office suite documents as
  a flag), ZIP containers by entry name (app packages and bundles, Java
  archives, Python zip applications), cabinet, compiled help, shell links,
  ISO 9660 and UDF images, 7z, RAR, gzip, ELF, Mach-O (thin and fat),
  Python bytecode, HTML applications, registry files, and scripts
  (`ScriptKind`) from shebang lines, defining markers, signature block
  markers and keyword scores. A keyword guess never overrides the script
  language the extension claims. `is_executable_content()` is true for
  every kind that can run code, natively or through a host, and for a ZIP
  archive whose structure could not be read in one consistent way.

  The PE sub-kind reuses `pe::parse_prefix` on the header bytes only, then
  maps RVAs with the parser's loader layout and makes small reads of the
  import, export, resource root, CLR and load configuration directories.
  Its `Driver` rule includes every `pe` kernel driver signal (`INIT`,
  `IMAGE_FILE_SYSTEM`, kernel module imports), so an image for which
  `PeInfo::is_kernel_driver` is true is a `Driver` here too. (#44's rule
  also makes a native image that does not import `ntdll.dll` a `Driver`.)
  The import table ends where the loader ends it: at the first descriptor
  with no name or no import address table.
- `tags` (feature `content-rules`): content tagging
  ([#44](https://github.com/jusso-dev/palisade/issues/44)).
  `tags::scan(&mut reader, &rules, &limits)` looks for masked byte
  patterns and returns a `TagReport` of string tags. `ContentRules` holds
  the read-only built-in set (`BUILTIN_TAGS`: installer engines, including
  an installer database wrapper, a scripted setup system, a setup loader,
  a bundle bootstrapper and a setup stream; self-extracting cabinet, ZIP
  and 7z archives; embedded executables and archives; compiled automation
  scripts and frozen Python applications; and the standard anti-malware
  test file), plus an optional organisation `RuleSetSource` from policy,
  which is plain `serde` data with a version and a canonical SHA-256
  digest. Patterns have a fixed length (at most 256 bytes) and are found
  through their longest exact run with one `aho-corasick` automaton, so a
  scan is linear. `ScanLimits` (32 MiB scanned in full, 40 MiB read, 64 Mi
  steps, 2 s) bound every scan; a file over the size limit gets
  `content_scan_partial` (its start and last 1 MiB are scanned), a spent
  budget `content_scan_timeout`, and a read error or early end of file
  `content_scan_error` (a file over the size limit keeps
  `content_scan_partial` either way),
  never an error. Tags found before a stop are kept. YARA syntax (through
  `yara-x`) is not supported: it needs a newer Rust than the workspace
  minimum and would exceed the duplicate-crate budget; see the module
  docs.
- `script`: script signature blocks and signed metadata
  ([#52](https://github.com/jusso-dev/palisade/issues/52)).
  - `verify_script` reads the embedded signature block of a PowerShell
    script, module or data file (`# SIG # Begin signature block`), a
    PowerShell XML file (an XML comment around `SIG # ...`), a managed object format file
    (`/* SIG # ... */`), VBScript (`'' SIG ''`), JScript (`// SIG //`) or a
    Windows Script File (`<signature>` with `** SIG **` lines). It computes
    the digest the OS subject interface package does: UTF-16LE of the text
    without the block and the CRLF before it; the PowerShell package hashes a
    byte order mark as U+FEFF, the script host packages append the block's
    position in UTF-16 units. The SignedData is checked with the same code as
    PE signatures, and the result is one `SignatureKind::Script` signature
    for `evaluate_trust` and `evaluate_validity`. A changed script is
    `DigestMismatch`.
  - Fails conservative: text without a byte order mark is read only when it
    is ASCII (otherwise its digest depends on the machine's code page);
    VBScript, JScript and WSF text in UTF-8 is read only when it is ASCII
    (the OS's own verifier rejects other UTF-8 text even when its own signer
    signed it); and invalid UTF-8 or UTF-16, two blocks, marker text
    anywhere else in the file, a truncated, misplaced or non-CRLF block, a
    WSF block with no `</job>` after it, non-strict base64, trailing bytes
    and a signature for another format's package are all invalid, never
    signed. Encoded scripts (`.vbe`, `.jse`) are unsigned with
    an `UnsupportedEncoding` warning; files over 32 MiB (configurable) are
    `TooLargeForSignatureCheck`.
  - `SignedMetadata`: the signed metadata attributes (1.3.6.1.4.1.311.2.7.1
    to .10: internal name, file and product version, description, product,
    original file name, language, author, publish time, source URL), read
    from every signature, PE ones included, into
    `SignerAttributes::signed_metadata`. A value that is not an exact
    UTF8String is left out with a warning; a duplicate is malformed.
  - `evaluate_script_trust` builds the chain under a `ScriptAnchorPolicy`
    (`OsRootStore`, `PolicyAnchors` or `Either`, the default) and records
    which anchor set was used; the caller supplies the machine root store.
  - `ScriptReport::normalised_hash` is the tolerant `script_hash_normalised`
    (SHA-256 of the text without the block and byte order mark, line endings
    turned into LF), for opt-in rules only. `catalog_digests` is the hook
    for a catalog lookup.

  Still to come: reading the OS root store and the OS trust-verification
  cross-check (`os-trust`, #48/#95), catalog-signed scripts beyond the
  lookup hook (#51, #55), feeding signed metadata into the file identity
  record (#55), other package identity (#53) and interpreter enforcement
  (#92 to #95).

## Handling untrusted input

Every file this crate reads may be hostile, so the parser:

- never panics: all reads are bounds-checked and all offset arithmetic is
  checked (`unwrap`, unchecked indexing and lossy casts are linted);
- never allocates from a size the file declares: every collection is bounded by
  the input length or a fixed `MAX_*` limit, and resource loops are not
  followed;
- reads what the OS loader reads: RVAs map through each section's aligned
  virtual size, so oversized raw data cannot shadow the next section; and the
  version resource (`VS_VERSION_INFO`, ID 1) and standard manifests (IDs 1 to
  3) are found by loader-style lookup, which, like the OS, searches only a
  directory's numeric-ID entries, so named entries, decoys, floods or loops
  elsewhere in the tree cannot hide or replace them;
- fails with a typed `PeError` (with the file offset) only when the headers are
  unreadable, and otherwise returns everything it could read plus a list of
  `ParseWarning`s, each with an offset;
- records the file offset of every structure, so later stages such as the
  Authenticode hash work on exactly the bytes that were parsed.

The file type classifier reads the first 64 KiB, then makes targeted reads
(PE headers past the head, ZIP end records and central directory, the
compound file root entry, PE directories, the last 64 KiB of long text for
a signature block marker) whose total is capped at 4.25 MiB, so it never
loads a whole file. A ZIP central directory is read once, up to 4 MiB and
65,536 entries, and only when the end records and directory are consistent
with the APPNOTE layout. Any structure on which ZIP readers could disagree
(a second end record, trailing data, ZIP64 and 32-bit fields that differ, a
shifted or understated directory, a wrong entry count, another record
inside the directory) is reported as `ZipDirectoryAmbiguous`, and a broken
or cut-off one as `ZipDirectoryMalformed` or `ZipDirectoryTruncated`.
`is_executable_content()` is true for a ZIP with any of these, so a misread
fails closed. PE imports are read up to 256 descriptors and exports up to
4,096 names.
It never fails: a file it cannot make sense of is `Unknown`, and a broken
structure behind a recognised magic keeps the outer kind, with the reason
in `parse_error`. A PE whose headers do not parse, or that ends inside its
optional header or section table, stays executable (`Mz16`). A read that
fails or comes up short is reported in `parse_error` (a compound file root
entry cut short, a ZIP extra subfield cut short, an unreadable text tail, a
failed PE directory or zip application probe), never taken as a clean
negative. A reader that ends before the length it reported (a file
truncated while it is read) is `Io(UnexpectedEof)`, not a shorter file.

Signature data gets the same treatment. Its ASN.1 is read by one small
DER-only module (`authenticode/asn1.rs`), which rejects BER indefinite
lengths, non-minimal and oversized lengths with a typed `Asn1Error`, and
borrows from the input instead of allocating, so no declared length sizes an
allocation. Fixed limits bound everything else: 16 `WIN_CERTIFICATE` entries,
a 16 MiB table, nesting 8 deep, 32 signatures in total, 64 certificates and 8
timestamps per signature, and 32 warnings per signature. At most 32 timestamps
are verified per file, timestamp chains share the file's budget of 512 checks
with keys the file supplies, and CRLs are capped at 8 MiB and 100,000 entries
(`timestamp_crl` fuzzes both parsers).

The same rules apply to the path normaliser, the security descriptor parser
and the `Zone.Identifier` parser, which are also fuzzed (`fsctx_parse`), and
to catalog files, which are capped at 64 MiB and fuzzed with lookups
(`fuzz_ctl`), and to installer packages, which are capped at 1 GiB, 65,536
directory entries, 16 storage levels, 4,194,304 strings and 4,096 tables,
and fuzzed end to end (`fuzz_msi_tables`).

The parser has no `unsafe` code, and its modules say `#![forbid(unsafe_code)]`.

## Testing and fuzzing

**Fixture corpus (#25).** `tests/corpus/` builds a whole test corpus from Rust
at test time, on any OS:

- PE32 and PE32+ executables and DLLs for x64, ARM64 and x86, each with a
  version resource (original file name, product, company, file version).
- A throwaway test PKI: a root CA, an intermediate, RSA-3072 leaves, an ECDSA
  P-256 leaf, and expired, revoked-in-CRL, wrong-EKU and self-signed leaves,
  plus a CRL.
- Signed PEs, signed in pure Rust (`tests/corpus/sign.rs`): embedded
  Authenticode, dual signed, tampered after signing, a truncated certificate
  table, and a page-hash-bearing signature; and a signed catalog (`.cat`) with
  the unsigned PE it lists.
- A malformed corpus: zero length, truncated headers, overlapping sections,
  an absurd section count, a recursive resource directory and a huge
  `SizeOfImage`.
- Benign `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.wsf` and `.hta` scripts that
  only print a marker.

`tests/fixture_corpus.rs` parses every fixture with this crate and checks
what it was built to be: machine, format and version info; signatures that
verify and chain to the test root; the tampered one a digest mismatch; the
wrong-EKU and self-signed leaves refused for that reason; the CRL listing the
revoked leaf. `cargo xtask fixtures` writes the corpus to `target/fixtures/`,
`cargo xtask golden` checks its hashes against `testdata/golden/fixtures.txt`,
and `write_corpus_fuzz_seeds` feeds it to the PE, PKCS#7 and X.509 fuzz
targets.

Fixtures are synthetic PE images built byte by byte at test time
(`tests/common`); no PE binaries are checked in. The signature tests use
small PKCS#7 signatures in `tests/fixtures/authenticode`, made over that
synthetic image by osslsigncode with throwaway keys from a test-only CA, plus
one Ed25519 test certificate and one RSA-PSS signature value. The chain tests
use test certificates in `tests/fixtures/chain` (cross-signed, forged-issuer,
loop, depth, expired, ECC, self-signed and other chains, plus two
signatures), with reference thumbprints and TBS hashes computed by Python's
`hashlib`, independently of this crate. The page hash tests use page hash
signatures in `tests/fixtures/page_hash`, made the same way as the
signature fixtures over three more synthetic images. The validity tests use
signatures with fixed dates in `tests/fixtures/timestamp`: RFC 3161 and
legacy timestamps, an expired signer, a Lifetime Signing signer, SHA-1, a
TSA whose issuer restricts its EKU away, and CRLs (including one forged
under the root's name). The catalog tests use small catalogs in
`tests/fixtures/catalog` (v1 SHA-1, v2 SHA-256, the v2 list signed with
SHA-1, and an organisation catalog under its own test root). The tests
build each unsigned catalog byte by byte, listing the synthetic PE image and
a short text file, and osslsigncode signs them with throwaway test keys; a
test checks that each fixture signs exactly that content. No OS catalog is
committed. The installer tests build every package at test time
(`tests/common/msi.rs` writes compound files with tables, streams, storages
and summary information); `tests/fixtures/installer` holds that test product
signed by osslsigncode with SHA-256, SHA-1 and SHA-256 plus
`MsiDigitalSignatureEx`, under a throwaway test root, and its normalised
hash computed by an independent Python script. No vendor package is
committed. The script tests use scripts in `tests/fixtures/script`, written
by its `generate.sh` and signed by jsign with a throwaway test CA, in every
format, encoding (UTF-8, UTF-8 with BOM, UTF-16LE, UTF-16BE where the
package signs it) and line ending (CRLF, LF, CR); a second implementation
of the digest in the tests must agree with each. Cases no signer makes on
request (signed metadata, broken blocks, nested signatures) are signed by
the tests themselves with a key generated per run. On Windows, a test
compares the verdicts with the OS's own. No private keys and no third-party binaries are
committed; the `generate.sh` scripts document how every file was made and
regenerate them.

```sh
cargo test -p palisade-fileid
```

The `properties` tests (proptest) feed random and mutated images to the parsers
on every run. Coverage-guided fuzz targets live in `fuzz/`, a separate cargo-fuzz
workspace with its own `Cargo.lock`, that needs a nightly toolchain. CI runs
every target for 60 s on each pull request and for 30 minutes weekly. From the
repository root, `cargo xtask fuzz` seeds and runs them all the same way
([docs/testing.md](../../docs/testing.md#fuzzing)). By hand:

```sh
cd crates/palisade-fileid
# Seed the corpora from the synthetic fixtures.
for t in pe_parse version_info_parse authenticode_ranges; do
  PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/$t" \
    cargo test -p palisade-fileid --test properties -- --ignored write_fuzz_seeds
done
PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/authenticode_pkcs7" \
  cargo test -p palisade-fileid --test signature -- --ignored write_pkcs7_fuzz_seeds
PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/fuzz_ctl" \
  cargo test -p palisade-fileid --test catalog -- --ignored write_ctl_fuzz_seeds
PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/fuzz_classify" \
  cargo test -p palisade-fileid --test filetype -- --ignored write_fuzz_seeds
PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/fuzz_tags" \
  cargo test -p palisade-fileid --test tags -- --ignored write_tag_fuzz_seeds
cargo +nightly fuzz run pe_parse -- -dict=fuzz/pe.dict -max_total_time=60
cargo +nightly fuzz run version_info_parse -- -dict=fuzz/pe.dict -max_total_time=60
cargo +nightly fuzz run authenticode_ranges -- -dict=fuzz/pe.dict -max_total_time=60
cargo +nightly fuzz run authenticode_pkcs7 -- -dict=fuzz/pkcs7.dict -max_total_time=60
cargo +nightly fuzz run fsctx_parse -- -max_total_time=60
cargo +nightly fuzz run x509_chain -- -max_total_time=60
PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/timestamp_crl" \
  cargo test -p palisade-fileid --test validity -- --ignored write_timestamp_fuzz_seeds
cargo +nightly fuzz run timestamp_crl -- -dict=fuzz/pkcs7.dict -max_total_time=60
cargo +nightly fuzz run fuzz_ctl -- -max_total_time=60
cargo +nightly fuzz run fuzz_classify -- -timeout=1 -max_total_time=60
PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/fuzz_msi_tables" \
  cargo test -p palisade-fileid --test installer -- --ignored write_installer_fuzz_seeds
cargo +nightly fuzz run fuzz_msi_tables -- -max_total_time=60
cargo +nightly fuzz run fuzz_tags -- -timeout=1 -max_total_time=60
```

`benches/hash_and_parse.rs` (criterion) measures flat hashing, streamed
hashing, PE parsing and the Authenticode hash over the same synthetic inputs:
`cargo bench -p palisade-fileid`.

## Allowed dependencies

`palisade-core` (for the shared `VerificationError` table, with its `serde`
feature), plus the RustCrypto `sha2`, `sha1` and `md-5` crates,
`ring` for signature verification and the hash cache record MAC (ADR 0008),
used only inside `authenticode/crypto.rs` and `hash/mac.rs`, `serde`
(derive only, no format crate) so certificate and chain reports serialise
with stable field names, `quick-xml` for the application manifest (no
default features, no DTD support) and `unicode-normalization` for NFC. The
workspace rules are enforced by
`cargo xtask check-deps`.

`ring` is not pure Rust (it has C and assembly), and on aarch64 Windows it
depends on `windows-sys` for CPU-feature detection. `check-deps` bans
`windows-sys` from `palisade-policy`'s graph, so a future `palisade-policy`
dependency on this crate would be rejected. Resolving that needs an ADR 0003
or 0008 amendment, either a narrowed carve-out or verification behind a
separate crate (#19). Because every `ring` call is in one module, swapping
the provider is a one-module change.

With the `os-trust` feature, on Windows only, `windows-sys` (the Windows API
bindings, with only the API families `win` calls) is a direct dependency.
`palisade-policy` never enables the feature, so its graph is unchanged.

With `content-rules`, `aho-corasick` (std and its `memchr` fast path only)
for the tagger's multi-pattern search. It is already a dependency of
`palisade-policy` through `regex-automata`, so it adds no crate to the
workspace.

Dev-dependencies: `proptest` for the property tests, `criterion` for the
benchmarks, and `rsa` with `rand_core` for the fixture generator
(`tests/corpus/`): throwaway RSA test-CA keys from a seeded RNG, and their
signatures. They are never in a shipped build.

## Platform support

Portable parsing, hashing, signature verification and file-system context
logic on all platforms. OS-backed reads live in the `win` module, compiled
only on Windows with the `os-trust` feature
([ADR 0003](../../docs/adr/0003-crate-boundaries-and-dependency-direction.md)).
It holds the file-system context reads and the OS trust-verification
cross-check. It is the only part of the crate that may contain `unsafe` code
(ADR 0011): each submodule that calls the Windows API (through `windows-sys`)
is listed in `unsafe-allowlist.txt`, every `unsafe` block has a `// SAFETY:`
comment, and each wrapper is tested on the Windows runners.

## Feature flags

- `content-rules` (off by default): builds `palisade_fileid::tags`, the
  content tagger, and adds the `aho-corasick` dependency. The scan runs in
  the calling thread with a cooperative time limit that cannot interrupt a
  blocking read; running it in a worker off the identity hot path is the
  caller's job, and the agent's worker is still to come (#4, #59, #60).
- `os-trust` (off by default): builds `palisade_fileid::win` on Windows. It
  adds OS-backed reads and never changes what the portable code reports. It
  has no effect on other targets. The agent, and the CLI for local
  diagnostics, are its intended users; neither depends on this crate yet.

## Stability

Unstable and not published. Anything may change.

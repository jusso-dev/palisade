# palisade-fileid

File identity: PE parsing, hashing (SHA-256, Authenticode, page and flat hashes), signature and certificate chain extraction, and version-info metadata.

**Status:** early. PE header and version-resource parsing, flat hashing, the Authenticode image hash, Authenticode signature verification and certificate chains, signer trust and signer identity work; the rest of [#3](https://github.com/jusso-dev/palisade/issues/3) is still to come.

## What is here

- `pe`: a hardened PE32 / PE32+ parser ([#45](https://github.com/jusso-dev/palisade/issues/45)).
  `pe::parse(&bytes)` reads the DOS, COFF and optional headers, all 16 data
  directories, the section table, the debug directory (CodeView PDB path, GUID
  and age, `REPRO`, POGO), the certificate table location, overlay, PE checksum
  (stored and computed) and per-section entropy. It walks the resource tree and
  parses the version resource: `VS_FIXEDFILEINFO`, every `StringFileInfo`
  language block, language selection and the file-name fallback chain.
- `hash`: flat SHA-256, SHA-1, MD5, SHA-384 and SHA-512, computed together in
  one streaming pass ([#46](https://github.com/jusso-dev/palisade/issues/46)).
  SHA-256 is the primary identity. SHA-1 and MD5 are not collision resistant
  and are computed only for interop; they must never be the sole basis of an
  allow decision ([ADR 0008](../../docs/adr/0008-cryptographic-algorithms.md)).
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
  flat hash is the identity to use. Page hash checks are still to come (#47).
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
  signer attributes are #49, and timestamps, expiry and revocation are #50.

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
  - `win::fsctx` (Windows, `os-trust` feature): reads a file's final path
    (links resolved, short names expanded) and its `Zone.Identifier` stream.
    Owner and DACL reads, drive and bus type, volume GUIDs, DFS and the OS
    access check are still to come (#54).
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
    file; nothing is re-encoded. `CertSummary` serialises to JSON with
    stable field names (serde), and `pem()` exports it.
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
    path. Certificates added to a file cost at most one check per trusted
    key whose name they claim, and this phase has its own budget (512
    checks per chain), so nothing in a file can starve it. Verified results
    are cached per key, not per certificate.
  - The as-provided chain (and, when nothing is anchored, the full chain)
    is then searched upwards with whatever keys the file holds: every path
    is enumerated, loops are detected, paths stop at 10 certificates, and
    the 8 best are kept (anchored, then complete, then shortest), with
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
    and `file_publisher_os_rule` (plus file name and minimum version), with
    the reason for any that cannot be made. A file with no trusted signer
    gets a `VendorHint` from `CompanyName` instead, marked unverified. It is
    a separate type, so it can never satisfy a publisher rule.
  - Constraint checks for policy: `leaf_has_eku`, `chain_has_eku`,
    `permits_code_signing`, `meets_min_key_bits`, `cert_sig_algs_allowed`
    and `os_ci_compatible` (RSA keys of at most 4096 bits in the whole
    chain).

  `SignatureReport::primary` is still #48's choice by cryptographic
  validity alone. Anything that decides trust must use
  `TrustReport::primary`. Not checked yet: validity periods, timestamps
  (including `requires_countersignature`) and revocation, which are #50.
  The OS trust store is not consulted; that is the `os-trust` cross-check
  in #48. Catalog signing is #51.

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

Signature data gets the same treatment. Its ASN.1 is read by one small
DER-only module (`authenticode/asn1.rs`), which rejects BER indefinite
lengths, non-minimal and oversized lengths with a typed `Asn1Error`, and
borrows from the input instead of allocating, so no declared length sizes an
allocation. Fixed limits bound everything else: 16 `WIN_CERTIFICATE` entries,
a 16 MiB table, nesting 8 deep, 32 signatures in total, 64 certificates and 8
timestamps per signature, and 32 warnings per signature.

The same rules apply to the path normaliser, the security descriptor parser
and the `Zone.Identifier` parser, which are also fuzzed (`fsctx_parse`).

The parser has no `unsafe` code, and its modules say `#![forbid(unsafe_code)]`.

## Testing and fuzzing

Fixtures are synthetic PE images built byte by byte at test time
(`tests/common`); no PE binaries are checked in. The signature tests use
small PKCS#7 signatures in `tests/fixtures/authenticode`, made over that
synthetic image by osslsigncode with throwaway keys from a test-only CA, plus
one Ed25519 test certificate and one RSA-PSS signature value. The chain tests
use test certificates in `tests/fixtures/chain` (cross-signed, forged-issuer,
loop, depth, expired, ECC, self-signed and other chains, plus two
signatures), with reference thumbprints and TBS hashes computed by Python's
`hashlib`, independently of this crate. No private keys and no third-party
binaries are committed; the `generate.sh` scripts document how every file was
made and regenerate them.

```sh
cargo test -p palisade-fileid
```

The `properties` tests (proptest) feed random and mutated images to the parsers
on every run. Coverage-guided fuzz targets live in `fuzz/`, a separate cargo-fuzz
workspace that needs a nightly toolchain:

```sh
cd crates/palisade-fileid
# Seed the corpora from the synthetic fixtures.
for t in pe_parse version_info_parse authenticode_ranges; do
  PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/$t" \
    cargo test -p palisade-fileid --test properties -- --ignored write_fuzz_seeds
done
PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/authenticode_pkcs7" \
  cargo test -p palisade-fileid --test signature -- --ignored write_pkcs7_fuzz_seeds
cargo +nightly fuzz run pe_parse -- -dict=fuzz/pe.dict -max_total_time=60
cargo +nightly fuzz run version_info_parse -- -dict=fuzz/pe.dict -max_total_time=60
cargo +nightly fuzz run authenticode_ranges -- -dict=fuzz/pe.dict -max_total_time=60
cargo +nightly fuzz run authenticode_pkcs7 -- -dict=fuzz/pkcs7.dict -max_total_time=60
cargo +nightly fuzz run fsctx_parse -- -max_total_time=60
cargo +nightly fuzz run x509_chain -- -max_total_time=60
```

Running the fuzz targets in CI is part of [#25](https://github.com/jusso-dev/palisade/issues/25).

## Allowed dependencies

`palisade-core`, plus the RustCrypto `sha2`, `sha1` and `md-5` crates,
`ring` for signature verification (ADR 0008), used only inside
`authenticode/crypto.rs`, and `serde` (derive only, no format crate) so
certificate and chain reports serialise with stable field names. The workspace rules are enforced by
`cargo xtask check-deps`.

`ring` is not pure Rust (it has C and assembly), and on aarch64 Windows it
depends on `windows-sys` for CPU-feature detection. `check-deps` bans
`windows-sys` from `palisade-policy`'s graph, so a future `palisade-policy`
dependency on this crate would be rejected. Resolving that needs an ADR 0003
or 0008 amendment, either a narrowed carve-out or verification behind a
separate crate (#19). Because every `ring` call is in one module, swapping
the provider is a one-module change.

## Platform support

Portable parsing, hashing, signature verification and file-system context
logic on all platforms. OS-backed reads live in the `win` module, compiled
only on Windows with the `os-trust` feature
([ADR 0003](../../docs/adr/0003-crate-boundaries-and-dependency-direction.md)).
It holds the file-system context reads so far; the cross-check against the
OS trust-verification API that #48 describes will live there too.

## Feature flags

- `os-trust` (off by default): builds `palisade_fileid::win` on Windows. It
  adds OS-backed reads and never changes what the portable code reports. It
  has no effect on other targets. The agent, and the CLI for local
  diagnostics, are its intended users; neither depends on this crate yet.

## Stability

Unstable and not published. Anything may change.

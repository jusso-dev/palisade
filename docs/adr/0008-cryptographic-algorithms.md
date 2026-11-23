# 0008. Cryptographic algorithms and libraries

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Palisade uses cryptography in five places:

1. **File identity**: hashes that rules match on (#3, #46, #47).
2. **Palisade's own signatures**: policy bundles (#225), server commands (#62) and trust-set
   updates (#224).
3. **OS-defined signatures**: Authenticode on Palisade's releases (#24, #226) and signed OS-native
   code integrity policies (#85). Their formats are fixed by the OS.
4. **Transport**: mutual TLS between agent, relays and server (#223).
5. **At rest and short secrets**: the encrypted policy cache (#225), the driver boot cache MAC
   (#113) and offline override codes (#222).

The project aims to align with the Australian Government ISM cryptography guidance (ASD-approved
algorithms), which favours ECDSA with P-384, RSA of at least 3072 bits, SHA-2 and AES-GCM.
Issue #20's summary suggests Ed25519 for bundle signing, while #225 specifies ECDSA P-384 as the
default with Ed25519 as an option, and #61 mentions Ed25519 or P-256. This ADR settles that.

## Decision drivers

1. Collision-resistant identities: no allow decision may rest on a broken hash.
2. Alignment with ASD-approved algorithms, since Essential Eight and the ISM frame the project.
3. Exact compatibility with what the OS computes and requires (#3, #6).
4. Algorithm agility, so a key or algorithm can be rotated without a format break (#224).
5. A small number of well-reviewed libraries, with builds for x64 and ARM64 Windows and Linux.
6. A path to a FIPS-validated module later, without a rewrite.

## Considered options

Bundle and command signatures:

1. **Ed25519 only.** Fast, deterministic, small keys, hard to misuse. Not on the ASD-approved
   list, so an ISM-aligned deployment could not use it.
2. **ECDSA P-384 with SHA-384 only.** ASD-approved. Slower, and it needs a careful library
   because naive ECDSA nonce handling is dangerous.
3. **Algorithm-agile envelope supporting both, with ECDSA P-384 as the default.** Each signature
   names its key ID and algorithm. The agent accepts only algorithms in its trust set.

Libraries:

1. **`ring`** for signatures, AEAD and HMAC, and as the rustls crypto provider. Small API surface
   designed against misuse, with nonce generation handled inside the library. Builds with only a C
   compiler (no CMake or separate assembler). No FIPS-validated build.
2. **A FIPS-capable rustls provider.** Offers a validated mode, but needs a heavier native build
   (CMake, and extra build tools for the validated mode) on Windows runners. Validated mode is not needed yet.
3. **Pure-Rust RustCrypto crates for everything.** No C or assembly, but no single provider for
   rustls, and a wider set of crates to review.

## Decision

**Hashing (file identity)**

- **SHA-256 is the primary identity.** Every stored or exchanged file identity carries it.
- SHA-1 and MD5 are **compatibility-only**: they are computed so Palisade can match what the OS
  and imported policies use, and to join with OS events. They are never the sole basis of an
  allow. Policy validation (#40) rejects an *allow* rule whose only identity is SHA-1 or MD5.
  A *deny* rule may use them, because a collision there can only cause an extra block.
- The OS-native compiler emits whatever hash forms the target OS build requires (#81). That can
  include SHA-1 Authenticode values *alongside* SHA-256, never instead of it.
- SHA-384 and SHA-512 are optional extras (#46).
- Implementation: the RustCrypto `sha2` crate (with `sha1` and `md-5` for compatibility hashes),
  because they are pure Rust, `no_std` capable and support streaming. The single-pass multi-hash
  design is in #46.

**Palisade-native signatures** (bundles, commands, trust-set updates)

- Option 3: an algorithm-agile envelope (`{kid, alg, sig}` entries, #225).
- Algorithms: `ecdsa-p384-sha384` (**default**) and `ed25519` (opt-in per tenant). Nothing else.
  The agent accepts only algorithms listed in its trust set, and the trust set is itself signed
  (#224).
- Every signature covers a domain-separation prefix plus the canonical bytes (#43, #225), so a
  signature for one purpose cannot be replayed as another.

**OS-defined signatures**

- Authenticode on releases and signed OS-native policies use **RSA 3072-bit or larger with
  SHA-256**, and RFC 3161 timestamps for releases. The OS fixes these formats, and Palisade
  only chooses the key size and digest.

**Transport**

- **TLS through `rustls`**, TLS 1.3 preferred and TLS 1.2 allowed only with the restricted
  AEAD cipher suites in #223. Certificate verification is never disabled, in any build.

**Symmetric**

- AES-256-GCM for data at rest (#225). HMAC-SHA-256 for MACs (the driver boot cache, #113) and
  for one-time override codes (#222).

**Libraries**

- **`ring`** provides signatures, AES-GCM, HMAC and the rustls crypto provider. It replaces the
  wider candidate crate list in #225. Access goes through a thin `crypto` module, so call sites
  never use `ring` directly. This covers user-mode crates only. `ring` cannot link into the
  `no_std` kernel driver, so `palisade-driver` verifies the boot cache MAC with the kernel's own
  cryptography API or `no_std` RustCrypto crates (`hmac`, `sha2`). That choice is made in #113,
  using the same algorithm (HMAC-SHA-256) and the same test vectors.
- **FIPS (future work).** A FIPS-validated provider can be swapped in later through rustls's
  provider interface and the same `crypto` module. Adopting one needs a superseding ADR, which must
  also decide whether file-identity hashing (done by `sha2`, outside the provider) is in FIPS
  scope. Palisade makes no FIPS claim until then (#18 lists certification as out of scope).

## Consequences

### Positive

- No allow decision rests on SHA-1 or MD5.
- ISM-aligned defaults, with Ed25519 available where alignment is not needed.
- Algorithm agility means key and algorithm rotation are data changes, not format changes.
- One provider for TLS and signatures keeps the reviewed crypto surface small.

### Negative

- P-384 verification is slower than Ed25519. Bundles are verified on activation and every
  15 minutes (#225), not per decision, so the cost is acceptable.
- Two signature algorithms means two sets of known-answer test vectors on every platform (#225).
- Imported policies (#15) whose allow rules carry only a SHA-1 or MD5 hash cannot be imported
  as-is. The importer must resolve them to SHA-256 from inventory or a supplied file, or report
  them as rejected.
- `ring` has no FIPS-validated mode, so a FIPS deployment needs the future provider swap.

## Security impact

This ADR sets the strength of every trust decision Palisade makes. Banning weak hashes as the
sole basis of allow rules closes collision-based bypasses in Palisade's own evaluation, where an
attacker builds a malicious file with the same SHA-1 or MD5 as an allowed one. The native layer
is limited by what the target OS build checks: where an older build only matches SHA-1
Authenticode values, the compile report (#81) flags the rule so the weakness is visible. Algorithm lists in a signed trust set prevent
algorithm downgrade, and domain separation prevents cross-protocol signature reuse. Keeping
verification always on in TLS means a misconfigured proxy fails closed rather than silently
exposing traffic. A flaw in `ring` would affect TLS and signatures at once, so it is tracked
under the supply-chain advisory scan (#23).

## Links

- Issues #20, #3, #43, #46, #47, #62, #81, #85, #113, #222, #223, #224, #225, #226. Epic #18.

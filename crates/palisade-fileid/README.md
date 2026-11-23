# palisade-fileid

File identity: PE parsing, hashing (SHA-256, Authenticode, page and flat hashes), signature and certificate chain extraction, and version-info metadata.

**Status:** early. PE header and version-resource parsing and flat hashing work; the rest of [#3](https://github.com/jusso-dev/palisade/issues/3) is still to come.

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

## Handling untrusted input

Every file this crate reads may be hostile, so the parser:

- never panics: all reads are bounds-checked and all offset arithmetic is
  checked (`unwrap`, unchecked indexing and lossy casts are linted);
- never allocates from a size the file declares: every collection is bounded by
  the input length or a fixed `MAX_*` limit, and resource loops are not
  followed;
- reads what the OS loader reads: RVAs map through each section's aligned
  virtual size, so oversized raw data cannot shadow the next section; the
  version and manifest resources are found by direct lookup along the
  type → name → language path, so the rest of the tree cannot hide them; and
  the version resource reported is the one the OS loads (`VS_VERSION_INFO`,
  ID 1);
- fails with a typed `PeError` (with the file offset) only when the headers are
  unreadable, and otherwise returns everything it could read plus a list of
  `ParseWarning`s, each with an offset;
- records the file offset of every structure, so later stages such as the
  Authenticode hash work on exactly the bytes that were parsed.

The parser has no `unsafe` code, and its modules say `#![forbid(unsafe_code)]`.

## Testing and fuzzing

Fixtures are synthetic PE images built byte by byte at test time
(`tests/common`); no binaries are checked in.

```sh
cargo test -p palisade-fileid
```

The `properties` tests (proptest) feed random and mutated images to the parsers
on every run. Coverage-guided fuzz targets live in `fuzz/`, a separate cargo-fuzz
workspace that needs a nightly toolchain:

```sh
cd crates/palisade-fileid
# Seed the corpora from the synthetic fixtures.
for t in pe_parse version_info_parse; do
  PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/$t" \
    cargo test -p palisade-fileid --test properties -- --ignored write_fuzz_seeds
done
cargo +nightly fuzz run pe_parse -- -dict=fuzz/pe.dict -max_total_time=60
cargo +nightly fuzz run version_info_parse -- -dict=fuzz/pe.dict -max_total_time=60
```

Running the fuzz targets in CI is part of [#25](https://github.com/jusso-dev/palisade/issues/25).

## Allowed dependencies

`palisade-core`, plus the RustCrypto `sha2`, `sha1` and `md-5` crates. The
workspace rules are enforced by `cargo xtask check-deps`.

## Platform support

Portable parsing and hashing on all platforms. OS trust APIs will live in a `win` module compiled only on Windows with the `os-trust` feature ([ADR 0003](../../docs/adr/0003-crate-boundaries-and-dependency-direction.md)).

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.

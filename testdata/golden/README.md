# Golden hashes of the generated test fixtures

`fixtures.txt` lists the SHA-256 of every fixture in the generated corpus
(#25), one `<sha256> <name>` line each. It is checked by `cargo xtask golden`
(the `fixtures` CI job) and rewritten by `cargo xtask golden --update`.

## Provenance

Nothing here was downloaded or copied from anywhere. Every fixture is built
from Rust source in `crates/palisade-fileid/tests/corpus/` at test time:

- The PE images come from the synthetic builder in
  `crates/palisade-fileid/tests/common/` (a `ret` and filler bytes, no real
  code), with a version resource naming the fixture.
- The test PKI (a root, an intermediate, RSA-3072 leaves, an ECDSA P-256 leaf,
  and expired, revoked, wrong-EKU and self-signed leaves, plus a CRL) is made
  by `tests/corpus/pki.rs`. The RSA keys come from a seeded RNG, so they are
  the same on every run and anyone can recompute them. They are throwaway test
  keys, trusted by nothing outside these tests.
- The Authenticode signatures are made by `tests/corpus/sign.rs` in pure Rust,
  so the corpus builds on any OS without OS signing tools.
- The scripts only print or write the marker `PALISADE-FIXTURE`.

`signed-ecdsa-p256.exe` is listed as `nondeterministic`, because ECDSA
signatures are random; its properties are still checked by
`tests/fixture_corpus.rs` on every run.

## When the hashes change

A changed hash means a fixture is built differently, so its bytes, and every
test that relies on them, changed. Review the diff like code, then run:

```sh
cargo xtask golden --update
```

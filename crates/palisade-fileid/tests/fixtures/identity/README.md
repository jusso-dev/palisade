# File identity corpus

The shared corpus for the unified file identity record (#55). Every file
`palisade_fileid::identity::identify` is run over here has a manifest entry
with its source, licence, the command that made it, and the values it must
produce. `tests/identity_corpus.rs` runs the whole manifest and fails on any
difference.

It lives under `tests/fixtures/` with the crate's other fixture sets, but
commits no binary: only the manifest, the signer (`signed.rs`) and the
scripts that check it. It reuses the generated fixture corpus of
`cargo xtask fixtures` (`tests/corpus/`, the pure-Rust PKI and Authenticode
signer) to sign its files at test time.

**No binary is committed, and no third-party binary is ever used.** There
are three kinds of entry:

| `source` | Where the bytes come from |
|---|---|
| `synthetic` | built byte by byte at test time by `tests/identity_corpus.rs` (`corpus_files`) |
| `generated` | a synthetic file signed at test time by `signed.rs`, or a catalog or CRL it makes |
| `os` | an OS file, read by path on the Windows CI runners only, never copied |

`synthetic` and `generated` files are licensed like the rest of the
repository (Apache-2.0 OR MIT). `os` entries name the file by path and are
checked only for values every version of it has (that it is a signed PE, its
`OriginalFilename`), because the exact bytes change with OS updates.

`signed.rs` builds a corpus CA, its leaves (the corpus vendor, the corpus
"OS" signer, a signer valid only in 2020, a revoked one, and a self-signed
rogue), a CRL, and the signed files: signatures with SHA-256 and with SHA-1,
a file changed after signing, one signed by the revoked leaf, and two
catalogs (one signed by the expired leaf without a timestamp). Its RSA keys
come from a deterministic RNG, so every run makes the same bytes.

## Expected values

Every value in `expected` is checked. Digests are not this crate's word:
they come from tools independent of it, run by `generate.sh` over the files
the tests make:

- `sha256`, `sha1`, `md5`: `shasum` and `openssl dgst`;
- `authenticode_sha256`: osslsigncode's `extract-data`, which computes the
  Authenticode digest in its own code;
- signer thumbprints: `openssl x509 -fingerprint`.

`generate.sh` also has osslsigncode verify every signature the corpus calls
good against the corpus CA, and refuse the tampered, revoked (given the
CRL) and rogue ones. The rest of `expected` (`signing_state`,
`masquerade_reasons`, `original_file_name` and so on) are the values a
reviewer decided are right for the file.

```sh
sh crates/palisade-fileid/tests/fixtures/identity/generate.sh
```

It needs openssl (3.x or later), osslsigncode (2.7 or later) and cargo. The
bytes are deterministic, so a rerun prints the same digests; a change to
the signer or the image builders that changes a byte fails
`corpus_matches_the_manifest` until the script is rerun and the manifest
updated from its output.

## Manifest format

`manifest.yaml` is a list of entries:

```yaml
- id: unsigned-exe           # unique
  file: unsigned.exe         # the name it is identified under
  source: synthetic          # synthetic | generated | os
  licence: Apache-2.0 OR MIT
  generator: corpus_files    # the function, script or path that makes it
  description: ...
  context: default           # default | trusted | trusted_crl (see `Contexts::get`)
  path_as: "C:\\Temp\\y.exe"  # optional: the path it is identified under
  requires: os-trust         # optional: a crate feature the entry needs
  expected:
    signing_state: unsigned
    ...
```

The keys under `expected` are listed in `tests/identity_corpus.rs`
(`check_expected`). An unknown key fails the test, so a typo cannot pass
silently.

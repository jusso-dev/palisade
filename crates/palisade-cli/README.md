# palisade-cli

The `pal` command-line tool for policy-as-code and administration.

**Status:** early. `pal fileid` (alias `pal file`) inspects file identities
([#55](https://github.com/jusso-dev/palisade/issues/55)). The policy-as-code
and administration commands are tracked in
[#15](https://github.com/jusso-dev/palisade/issues/15).

## Commands

```text
pal fileid inspect <path|dir> [--tiers all|t0..t5] [--json|--yaml|--table] [--recursive]
                              [--anchor <cert>]... [--well-known-root ID=HASH]... [--catroot <dir>]
pal fileid hash    <path> --alg sha256,authenticode-sha256,page-sha256,... [--json]
pal fileid certs   <path|dir|catalog> [--which all|leaf|root | --leaf | --root] --out <dir> [--pem]
pal fileid compare <a> <b> [--json] [--anchor <cert>]...
pal fileid explain <path> [--json] [--anchor <cert>]...
```

- `inspect` prints the full `palisade_fileid::identity::FileIdentity`
  record (schema `fileid.v1`): one line per attribute by default, pretty
  JSON with `--json`, or YAML. For a directory it prints one record per
  file, and with `--json` one compact JSON object per line. `--recursive`
  walks subdirectories without following symbolic links.
- `--tiers` picks the computation tiers: `t0` stat, `t1` PE headers and
  version information, `t2` hashes, `t3` signatures, chains and catalogs,
  `t4` file system context, `t5` deep content. A range (`t0..t3`) or a list
  (`t0,t2`) works too.
- Trust comes only from the command line. With no `--anchor`, signatures
  are checked but no signer is trusted. `--anchor` adds a trust anchor
  certificate (DER or PEM) for code signers, catalog signers and
  timestamping authorities. `--well-known-root` names an OS root by its
  TBS hash; protected binaries such as interpreters are expected to chain
  to one. `--catroot` loads every `*.cat` under a directory (such as the OS
  catalog root) and looks files up in it. Revocation is not fetched
  (offline).
- `inspect --include-ads` also identifies each alternate data stream that
  is not a well-known benign one, as its own record (`file:stream`). The
  streams are listed from the Windows file system; where they cannot be,
  the run fails rather than report none.
- `hash` prints only the selected digests. `msi-normalised` (an
  installer's timestamp-free hash) and `script-normalised` (a script's text
  without its signature block, byte order mark and line-ending
  differences) parse the file; for any other file they are not available
  and exit 1.
- `certs` writes each certificate of a signed PE file, cabinet, catalog or
  other PKCS#7 file (nested signatures included) to
  `<out>/<sha256 thumbprint>.der` (or `.pem`), once each, through
  `palisade_fileid::authenticode::extract_certificates`.
- `compare` lists the rule-relevant attributes in which two files differ,
  for example to check that an update keeps its publisher and product.
- `explain` lists every attribute with its identity strength and
  recommends a rule level, with the reasons and the levels it refused.

Every string from a file, in every format and in error messages, is
printed with control and bidirectional characters escaped (`\uXXXX` in JSON
and YAML, which parse back to the same string; `\u{...}` elsewhere), so a
crafted name cannot rewrite the terminal.

Exit codes: `0` success, `1` a file could not be read or a requested value
is not available, `2` a bad argument.

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. The rules are enforced by `cargo xtask check-deps`.
Third-party: `clap` (command line), `serde_json` (JSON output) and, on
Unix, `libc` (for `O_NONBLOCK`), all already in the workspace. YAML is written by a small emitter here, so every
string is a double-quoted, escaped scalar; `yaml-rust2` is a dev-dependency
that parses it back in the tests.

## Platform support

All platforms. On Windows, `pal fileid` reads the known folders from the
environment for the path variables and the protected binaries' expected
locations. Commands that talk to a local agent will be Windows only.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change. The JSON form of
`inspect` follows the `fileid.v1` evolution rules: fields are only added.

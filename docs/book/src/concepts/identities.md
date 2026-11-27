# Identities

A rule says which objects it means through **identity criteria**: facts about the file itself.
Specified in [#31](https://github.com/jusso-dev/palisade/issues/31) (identity criteria) and
[#3](https://github.com/jusso-dev/palisade/issues/3) (how `palisade-fileid` computes them).

| Family | Fields | Strength |
|---|---|---|
| Hash | `hash.sha256`, `hash.sha384`, `hash.sha512`, `hash.authenticode_sha256` | strong: names exactly one file |
| Hash (compatibility) | `hash.sha1`, `hash.md5`, `hash.authenticode_sha1`, page hashes | weak alone ([ADR 0008](../../../adr/0008-cryptographic-algorithms.md)) |
| Publisher | `signer.publisher` (CN, O or full DN) | medium |
| Certificate | `signer.leaf_thumbprint`, `signer.tbs_hash` | strong: names one certificate |
| Certificate authority | `signer.issuer`, `signer.pca`, `signer.root_thumbprint`, `signer.eku`, SHA-1 thumbprints | weak alone: a CA vouches for every file it signs |
| Path | `path.full`, `path.directory`, `path.file_name`, `path.extension` | medium, and only where users cannot write |
| Metadata | `meta.original_filename`, `meta.product_name`, `meta.file_version`, ... | weak: easy to copy into another file |

The strength matters. Validation warns about an allow rule whose only identity is weak, and an
allow rule must have a positive identity on every branch of its match tree, so a rule cannot
allow "anything not named X". A path rule only allows a file in a location that ordinary users
cannot write (ISM-1392); the engine checks the path's ACL safety at evaluation time.

**Hash rules** are the most precise and the most work: every update needs a new rule.
**Publisher rules** trust what a signer signs, optionally narrowed by product name and minimum
version (ISM-1471: use publisher *and* product names). By default a signer
criterion only trusts signatures that are valid, valid with an expired but timestamped
certificate, or catalog-signed; a criterion's `signer` options can accept other statuses, require
a timestamp after a date or a minimum key size, reject algorithms, or pick the signature's source
and index. To block a stolen certificate, deny its `signer.tbs_hash`. That blocks one
certificate only: the hashed data includes the serial number and the validity period, so a
certificate reissued with the same key has a new TBS hash and needs its own rule. No criterion
yet names a key across all the certificates that carry it. **Path rules** are the easiest to write and
the easiest to get wrong.

A workstation baseline with hash, publisher and path rules (ISM-0955), validated in CI:

```yaml
{{#include ../../../examples/policies/workstation-baseline.yaml}}
```

A publisher rule narrowed by product name and minimum version (ISM-1471):

```yaml
{{#include ../../../examples/policies/finance-workstations.yaml}}
```

See also: the full field list in the [policy reference](../reference/generated/policy/types.md#field),
and the [file identity crate](../../../../crates/palisade-fileid/README.md).

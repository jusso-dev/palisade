# Identities

A rule says which objects it means through **identity criteria**: facts about the file itself.
Specified in [#31](https://github.com/jusso-dev/palisade/issues/31) (identity criteria) and
[#3](https://github.com/jusso-dev/palisade/issues/3) (how `palisade-fileid` computes them).

| Family | Fields | Strength |
|---|---|---|
| Hash | `hash.sha256`, `hash.sha384`, `hash.sha512`, `hash.authenticode_sha256` | strong: names exactly one file |
| Hash (compatibility) | `hash.sha1`, `hash.md5`, `hash.authenticode_sha1`, page hashes | weak alone ([ADR 0008](../../../adr/0008-cryptographic-algorithms.md)) |
| Publisher | `signer.publisher` (CN, O or full DN) | medium |
| Certificate | `signer.leaf_thumbprint`, `signer.tbs_hash` | strong: names one certificate (a TBS hash above the leaf names a CA, so it is weak in an allow) |
| Key | `signer.spki_sha256` | strong at `position: leaf`: names the signing key, in every certificate issued for it (a key above the leaf is a CA's, so it is weak in an allow) |
| Certificate authority | `signer.issuer`, `signer.pca`, `signer.root_thumbprint`, `signer.eku`, SHA-1 thumbprints | weak alone: a CA vouches for every file it signs |
| Path | `path.full`, `path.directory`, `path.file_name`, `path.extension` | medium, and only where users cannot write |
| Path location | `path.drive_type`, `path.bus`, `path.is_unc`, `path.is_ads`, `path.share`, `path.user_can_change_acl`; the `%REMOVABLE%` and `%HOT%` variables (the roots of mounted removable and hot-pluggable volumes) | weak: say where a file is, never which file; for denies and scoping, such as "block anything on a USB disk" |
| Metadata | `meta.original_filename`, `meta.product_name`, `meta.file_version`, `meta.legal_copyright`, `meta.language`, `meta.file_name_fallback`, ... | weak: easy to copy into another file |
| File and image | `meta.file_size` (a number), `meta.pe_machine`, `meta.pe_subsystem`, `meta.is_dotnet` (yes or no), `meta.detected_type` (from the content) and `meta.extension_type` (from the name), so a rule can block a PE renamed to `.pdf` | weak: describe a file, never name one |
| Windows Installer | `msi.product_code`, `msi.upgrade_code`, `msi.package_code` (GUIDs, compared with or without braces, in either case), `msi.product_name`, `msi.manufacturer`, `msi.product_version` | weak: the package's author writes them all |

The strength matters. Validation warns about an allow rule whose only identity is weak, and an
allow rule must have a positive identity on every branch of its match tree, so a rule cannot
allow "anything not named X". A path rule only allows a file in a location that ordinary users
cannot write (ISM-1392); the engine checks the path's ACL safety at evaluation time. The ACL
counts only on a fixed local disk: on a removable, optical or network volume, or one whose kind
the agent could not tell, a path allow does not match, because whoever holds the disk, or the
server, decides what its folders hold whatever their permissions say. A path deny matches
everywhere.

**Hash rules** are the most precise and the most work: every update needs a new rule.
**Publisher rules** trust what a signer signs, optionally narrowed by product name and minimum
version (ISM-1471: use publisher *and* product names). The `publisher_product` preset
(`palisade_policy::model::preset::PublisherProduct`) builds that form. By default a signer
criterion only trusts signatures that are valid, valid with an expired but timestamped
certificate, or catalog-signed; a criterion's `signer` options can accept other statuses, require
a timestamp after a date or a minimum key size, reject algorithms, or pick the signature's source
and index. To block one stolen certificate, deny its `signer.tbs_hash`. That blocks that
certificate only: the hashed data includes the serial number and the validity period, so a
certificate reissued with the same key has a new TBS hash. To block a stolen **key**, deny its
`signer.spki_sha256` (the SHA-256 of the certificate's DER `SubjectPublicKeyInfo`) with
`position: leaf`: it is the same in every certificate issued for the key, so the deny still
applies after a reissue. Use the TBS hash when one certificate is the problem (a mis-issued
certificate, say, whose key is still trusted elsewhere), and the key hash when the private key
is. As an allow, a leaf key hash trusts whoever holds the key whatever certificate they present
next, as long as the chain is still valid; a key above the leaf belongs to a certificate
authority, which vouches for everything it signs, so validation warns about it as weak. As
with every signer criterion, a revoked or otherwise untrusted signature does not take part by
default, and an unknown key hash never makes a rule match. **Path rules** are the easiest to write and
the easiest to get wrong.

Path criteria match the **final** path, after symbolic links and junctions are resolved. A
**hard link** is another name for the same file, with no final path to resolve to: a file
hard-linked into an allowed folder from somewhere else is the same content under both names, and
a path rule sees only the name it was started by. Only a hash or signer criterion follows the
content across its names. Write those rules for files that must never run, and do not rely on a
path deny alone to stop a file that users can hard-link elsewhere.

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

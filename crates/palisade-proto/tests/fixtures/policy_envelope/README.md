# Signed policy envelope known-answer vectors (#325)

Made with the OpenSSL command-line tool, independently of `ring`, and read by
`policy_bundle::envelope::tests` in `palisade-proto`.

- `minimal.cbor`: a copy of `palisade-policy`'s golden bundle
  `tests/golden/bundles/minimal.cbor` (bundle hash
  `a624aa7585a0d12980d89669d8cec784402631420c145f939d6979f7c591d958`).
- `minimal.envelope`: that bundle in an envelope (format 1, kind 1) with two
  signatures over `"palisade-policy-v1\0" ‖ minimal.cbor`, ascending by key ID:
  - Ed25519 (`pkeyutl -sign -rawin`) by the key of RFC 8032 section 7.1,
    test 1. The key is published in the RFC, and Ed25519 is deterministic,
    so the test also signs again and expects the same bytes.
  - ECDSA P-384 SHA-384 (`dgst -sha384 -sign`) by a key generated for this
    file with `genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384`,
    converted from DER to `r ‖ s`. Its private key was not kept; the tests
    hold only its `SubjectPublicKeyInfo`.

Regenerated for bundle format 2 (#368), when the golden bundle's bytes
changed: the same Ed25519 key, and a new P-384 key made the same way,
whose key ID sorts after the Ed25519 one.

The key IDs and public keys are constants in the tests. Any byte that
changes here is a changed envelope format or a changed golden bundle.

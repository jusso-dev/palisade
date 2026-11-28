# Signed policy envelope known-answer vectors (#325)

Made with the OpenSSL command-line tool, independently of `ring`, and read by
`policy_bundle::envelope::tests` in `palisade-proto`.

- `minimal.cbor`: a copy of `palisade-policy`'s golden bundle
  `tests/golden/bundles/minimal.cbor` (bundle hash
  `3b5fe5f805e1a0871ca716d61648879a7b9e5bab1364a9426711705a64347052`).
- `minimal.envelope`: that bundle in an envelope (format 1, kind 1) with two
  signatures over `"palisade-policy-v1\0" ‖ minimal.cbor`, ascending by key ID:
  - Ed25519 (`pkeyutl -sign -rawin`) by the key of RFC 8032 section 7.1,
    test 1. The key is published in the RFC, and Ed25519 is deterministic,
    so the test also signs again and expects the same bytes.
  - ECDSA P-384 SHA-384 (`dgst -sha384 -sign`) by a key generated for this
    file with `genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384`,
    converted from DER to `r ‖ s`. Its private key was not kept; the tests
    hold only its `SubjectPublicKeyInfo`.

The key IDs and public keys are constants in the tests. Any byte that
changes here is a changed envelope format or a changed golden bundle.

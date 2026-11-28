# Key compromise and emergency re-key runbook

| | |
|---|---|
| Document version | 0.1.0 |
| Last reviewed | 2026-11-28 |
| Status | Draft. Not yet rehearsed: the lab rehearsal and its notes are still to come (#224). |
| Tracking issue | [#224](https://github.com/jusso-dev/palisade/issues/224), under epic [#18](https://github.com/jusso-dev/palisade/issues/18) |

Palisade is an educational, personal-development project (see the [README](../../README.md)).
This runbook says what to do when one of Palisade's own keys is, or may be, compromised. It
covers every key in the inventory of #224, plus device keys. It is written for the operator of
a Palisade server and the holder of the offline root.

The PKI building blocks exist in `palisade_proto::pki`: the key inventory and lifecycle, the
signed trust set and the agent's acceptance rule, the `Signer` interface, renewal and rotation
schedules, and certificate and revocation-list issuance. The tools that drive them do not exist
yet: the `pal pki` ceremony commands and `pal pki emergency-rotate` (#15), the admin audit log
(#132), the agent's use of the trust set (#220, #223), policy bundles (#225), update metadata
(#226) and unlock tokens (#222). Each step below says which issue provides it. A step whose tool
does not exist yet cannot be carried out today; that is stated, not hidden.

## Contents

1. [Principles](#principles)
2. [First hour: any suspected compromise](#first-hour-any-suspected-compromise)
3. [Detection signals](#detection-signals)
4. [Per-key procedures](#per-key-procedures)
5. [Emergency rotation of everything except the root](#emergency-rotation-of-everything-except-the-root)
6. [What agents do](#what-agents-do)
7. [Communication template](#communication-template)
8. [After the incident](#after-the-incident)
9. [Rehearsal](#rehearsal)

## Principles

- **Suspected is compromised.** Treat a key as compromised when its exposure cannot be ruled
  out. Rotating a good key costs a rotation; trusting a stolen one costs the fleet.
- **`compromised` is final.** In the key inventory, `compromised` has no way out
  (`KeyStatus::can_become`). A compromised key is never reactivated, even if the suspicion turns
  out to be wrong. Generate a new key instead.
- **Contain by removal.** A trust set lists only `active` and `retiring` keys. A compromised key
  is revoked by publishing a trust set that leaves it out. Agents stop trusting it when they
  accept that set.
- **Keys are separate by purpose.** No key signs for two purposes (ADR 0008, ADR 0017), and every
  Palisade signature carries a domain prefix. A stolen key therefore reaches one purpose only.
  Use this to scope the response: rotate the key that leaked, not everything.
- **The root has no clean recovery.** If the offline root is compromised, every device must be
  re-enrolled with a new pin. There is no other way (R-11 in the
  [threat model](threat-model.md)).
- **Record everything.** Every key event, signing ceremony and trust-set publication goes in the
  admin audit log with the actor (#132). Until #132 exists, keep a written incident log with
  times, actors and the key IDs (`kid`) involved.

## First hour: any suspected compromise

1. **Open an incident** and start the incident log. Name one incident lead.
2. **Identify the key** by its `kid` (32 hex digits: the first 16 bytes of the SHA-256 of its
   `SubjectPublicKeyInfo`) and its purpose. If you do not know which key leaked, assume every key
   held where the leak happened: for example, a server host compromise means `issuing-ca`,
   `server-tls`, `trust-set`, `policy-signing`, `unlock-token`, `escrow` and `audit-chain` if they
   are file keys on that host.
3. **Preserve evidence** before changing anything: copies of logs, the audit log, the key store
   metadata (not key material), and the signing history.
4. **Mark the key `compromised`** in the inventory (`KeyRecord::transition`), so the server's
   signer refuses to use it (`KeyRecord::can_sign`). Through the console or `pal pki` once #15
   exists.
5. **Follow the per-key procedure** below.
6. **Tell people** using the [communication template](#communication-template).

## Detection signals

| Signal | Points to |
|---|---|
| A signature by a `kid` with no matching entry in the audit log (#132, T-signer-03) | The key that made it |
| Signing volume for a key well above its normal rate | Oracle use of the signer (T-signer-01) |
| A policy bundle or unlock token reported by an agent that the server never issued | `policy-signing` or `unlock-token` |
| A trust set with a `trust_version` the server never published, seen on any agent | `trust-set` or `root-ca` |
| A device or relay certificate whose serial and key fingerprint do not match an enrolment record (`CertificateBinding`, T-ca-02) | `issuing-ca` |
| A certificate for the server's name that the server did not request (CT logs, inspection, agents reporting `transport.pin_mismatch`, #223) | `server-tls`, `issuing-ca` or the external CA |
| Release metadata signed outside the release pipeline (#226) | `update-signing` |
| A break in the admin audit hash chain (#229) | `audit-chain`, or tampering with the log |
| Escrowed secrets used without a recorded escrow request | `escrow` |
| Host compromise, lost backup, lost or stolen HSM token, departed operator with key access | Every key held there |

## Per-key procedures

Each procedure lists containment (stop the damage now) and recovery (return to a trusted
state). Overlap periods come from `pki::lifecycle::RotationPlan`; in an emergency they are cut
to zero: the old key is dropped at once, not retired gradually.

### root-ca (offline root)

Signs issuing-CA certificates and trust sets. Never on the server.

- **Containment:** none that agents can enforce. The root is the anchor every agent pins; an
  attacker with it can sign any trust set and any issuing CA. Take the server's agent endpoints
  to an allowlist of known networks if possible, and watch for unexpected trust sets.
- **Recovery:**
  1. Run a new root ceremony on an offline machine (`pal pki root init`, #15) and generate a
     new root key.
  2. Issue a new issuing CA from the new root.
  3. **Re-enrol every device** with the new root pin (#223). Agents cannot be moved to the new
     root by a trust set, because any trust set the old root could sign, the attacker can sign
     too. A cross-certificate from the old root (`CaCertificate::cross_signed`) does not help
     here: it is for planned rotations, when the old root is still trusted.
  4. Destroy the old root key and every backup of it, and record that.
- **Honest limits:** until every device is re-enrolled, the attacker can push trust sets to
  devices that still pin the old root. Plan re-enrolment as a fleet-wide project.

### issuing-ca (online issuing CA)

Issues device, relay and server certificates.

- **Containment:**
  1. Mark it `compromised`; stop issuing with it.
  2. The server keeps rejecting any device or relay certificate whose serial **and** key
     fingerprint do not match its enrolment record (`CertificateBinding`, #223), so certificates
     the attacker mints for new keys are refused at the server at once.
  3. Revoke the issuing CA: the root signs a revocation list naming its serial
     (`issue::revocation_list` with reason `CaCompromise`), published to relays and other
     verifiers. Every certificate under it then fails verification (tested by
     `pki::issue::tests::revoked_intermediate_is_refused`).
  4. If `server-tls` was issued by this CA, its pin path must change too: see
     [server-tls](#server-tls).
- **Recovery:**
  1. Offline root ceremony: issue a new issuing CA (`pal pki root sign-intermediate`, #15).
  2. Start a forced device-certificate renewal campaign: every device renews against the new
     CA at its next check-in, without waiting for 2/3 of its lifetime (#223).
  3. Re-issue relay and server certificates from the new CA.
  4. When every active device reports a certificate from the new CA, drop the old CA from the
     server's client CA bundle.
- **Agent behaviour:** devices keep their old certificate until they renew; the server accepts
  it only while it matches the enrolment record.

### server-tls

The server's TLS key, issued by `issuing-ca` or by an external CA.

- **Containment:**
  1. Generate a new key and certificate.
  2. Publish a trust set with the new SPKI pin added and the old pin **removed**, signed by the
     current trust-set key. Agents then refuse the old key at the next handshake (T-ca-01).
  3. Switch the server to the new certificate.
- **Recovery:** if the certificate came from an external CA, also revoke it there.
- **Agent behaviour:** an agent that has not yet received the new trust set will refuse the new
  certificate, because its pin is not yet known. Publish the trust set **before** switching, and
  give agents one check-in interval to fetch it if the risk allows. In a confirmed interception,
  switch at once and accept that some agents reconnect only after their next successful trust-set
  fetch.

### trust-set (online trust-set key)

Signs trust sets, endorsed by the root.

- **Containment:**
  1. Mark it `compromised`.
  2. Offline root ceremony: the root signs a trust set without the compromised key and with a
     new trust-set key (`pal pki root sign-trustset`, #15).
  3. The new set's `trust_version` must be greater than any version the attacker may have
     published. An agent accepts a step of at most 1,000,000 (`MAX_VERSION_STEP`, T-ca-08), so
     if the attacker fast-forwarded some agents, publish intermediate root-signed sets to bring
     them back in line.
- **Recovery:** resume normal trust-set publication with the new key.
- **Honest limits:** until agents accept the root-signed set, the attacker can publish trust
  sets within one version step to agents that reach them.

### policy-signing

Signs policy bundles (#225).

- **Containment:**
  1. Mark it `compromised`.
  2. Generate a new policy-signing key.
  3. Publish a trust set that adds the new key and removes the compromised one. No dual-signing
     period: in an emergency the old key is not retired gradually.
  4. Re-sign and publish the current policy with the new key only.
- **Recovery:** check every agent's reported active bundle hash and `kid` against the server's
  history (T-signer-03); investigate any bundle the server did not issue.
- **Agent behaviour:** once an agent accepts the new trust set, bundles signed by the old key are
  refused as unsigned, and the agent keeps running its current policy (ADR 0018: a missing or
  bad signature never relaxes a decision). Bundles the attacker managed to install before then
  stay active until replaced, so push the re-signed policy at once.

### update-signing

Signs release metadata. Held in the release pipeline, not on the server (#226).

- **Containment:** stop releases. Rotate the key under the update metadata's own root (#226) and
  update the update-root pointer in the next trust set.
- **Recovery:** re-sign the current release metadata; audit every release signed since the
  suspected exposure.
- **Honest limits:** if the update metadata **root** is compromised, devices must be
  re-provisioned (R-11).

### unlock-token

Signs break-glass unlock tokens (#222).

- **Containment:** publish a trust set without the key. Unlike a planned rotation, its tokens are
  **not** honoured for the rest of their lifetime: they stop working when an agent accepts the
  set.
- **Recovery:** issue a new unlock-token key; check which devices redeemed tokens since the
  exposure (the redemption events, #222).
- **Agent behaviour:** an offline agent keeps accepting tokens from the old key until it next
  checks in and accepts the new trust set. That is the accepted risk of offline override (R-10).

### escrow

Encrypts escrowed device secrets.

- **Containment:** stop escrow writes with the key. Treat every secret escrowed under it as
  exposed.
- **Recovery:** generate a new escrow key; rotate every escrowed device secret (each device
  generates a new one and escrows it under the new key, #227). Envelope-encrypted columns are
  re-wrapped by the background re-wrap job (#227).

### audit-chain

Anchors the admin audit hash chain (#229).

- **Containment:** anchor a new chain segment with a new key, recording the break and why.
- **Recovery:** verify the chain up to the last anchor you trust; treat entries after it as
  unverified and compare them with independent records (server logs, agent check-ins).

### Device keys

A device's own key (non-exportable through the OS key store where available, #223).

- **Containment:** revoke the device in the console (#223). The server refuses its connections at
  once, without waiting for a revocation list.
- **Recovery:** re-enrol the device; it generates a new key.

## Emergency rotation of everything except the root

`pal pki emergency-rotate --scope issuing,policy,unlock` (#15, not built yet) will run the
containment steps above for the issuing CA, the policy-signing key and the unlock-token key in
one operation: mark the keys `compromised`, generate new ones, publish one trust set without the
old keys, and start the device-certificate renewal campaign. The new issuing CA still needs the
offline root, so the command prepares the signing request and stops for the root ceremony.

Until it exists, run the per-key procedures in this order: `trust-set` (if in scope), then
`issuing-ca`, then `server-tls`, `policy-signing` and `unlock-token` in one trust set, then
`escrow` and `audit-chain`.

## What agents do

Agents act only on what a trust set tells them; they never learn of a compromise any other way.
The rules, from `TrustAnchor::accept` (tested in `palisade-proto`):

- A key that is not in the current trust set is not trusted, whatever signed it. Removal from
  the set is the revocation.
- A new trust set must be signed by the pinned root or by a trust-set key in the **current** set.
  A set cannot endorse itself.
- `trust_version` must increase, by at most 1,000,000 per step. Older and replayed sets are
  refused.
- A bad or mislabelled signature from a known key rejects the whole set (tampering, not noise).
- When signature checks fail, the agent keeps its current policy and trust set. It never relaxes
  enforcement because something could not be verified (ADR 0018).

The agent does not use the trust set yet (#220, #223). Until it does, none of the containment
steps that depend on agents accepting a trust set take effect on endpoints.

## Communication template

Send one notice when the incident is opened and one when it is closed. Do not include key
material, passwords or internal host names.

```text
Subject: [Palisade] Key compromise: <key purpose> (<kid>), <opened | resolved>

What happened:
  On <date, time, time zone> we found that the Palisade <key purpose> key
  (kid <kid>) <was | may have been> exposed through <short cause>.

What it could be used for:
  <one line from the key's procedure: for example "signing policy bundles
  that agents would accept until <time>">

What we have done:
  - <time>: marked the key compromised; it can no longer sign.
  - <time>: published trust set version <n> without the key.
  - <other containment steps>

What you need to do:
  <nothing | re-enrol devices | update the pinned root | rotate a secret>

What we are watching for:
  <detection signals for this key>

Next update: <time>, or sooner if anything changes.
Contact: <incident lead>
```

## After the incident

- Close the incident only when every containment and recovery step is done and the detection
  signals have been quiet for one full renewal cycle of the affected certificates.
- Write a short review: cause, timeline, what worked, what did not, and changes to this runbook.
- Update the [threat model](threat-model.md) if the incident showed a threat it does not list.

## Rehearsal

Not yet done. #224 requires this runbook to be rehearsed once in the lab, with notes committed
here. That needs the `pal pki` commands (#15) and an agent that uses the trust set (#220, #223).
Until then, the parts that exist can be exercised through the `palisade-proto` tests named
above.

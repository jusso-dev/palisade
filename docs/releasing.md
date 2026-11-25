# Releasing

How a Palisade release is cut, signed, checked and published (#24). Everything runs on
GitHub-hosted runners, from `.github/workflows/release.yml`, with the steps in
`cargo xtask release` and `cargo xtask sign`. Building the artefacts themselves is described in
[packaging.md](packaging.md).

**Until the maintainer has done the one-time setup in [Code signing](#code-signing), pushing a
release tag fails at its first job.** A release never produces unsigned packages. Pull requests
and `main` produce unsigned builds only, clearly marked as such: the `package` job's packages and
the [`main-snapshot`](ci.md#main-snapshot) pre-release.

## Versioning

- SemVer for the whole workspace, one version for every binary: `workspace.package.version` in
  the root `Cargo.toml`.
- Pre-releases are `-alpha.N`, `-beta.N` and `-rc.N`, and are published as GitHub pre-releases.
- Tags are `vX.Y.Z` or `vX.Y.Z-rc.N` (and so on), **annotated and signed** with SSH or GPG
  (`git tag -s`). `cargo xtask release check-tag` refuses a lightweight or unsigned tag, a name
  that is not a release version, and a tag whose commit's `Cargo.toml` has another version. It
  checks that a signature is there; whose key made it is enforced by protecting `v*` tags
  (below), because a runner has no trusted keyring to check it against.

## The pipeline

A pushed `v*` tag runs these jobs. Files move between jobs through a **draft** GitHub Release,
because only three actions are allowed and none of them carries artefacts between jobs
([ci.md](ci.md#runner-and-action-policy)). Nobody sees a draft but maintainers, and it is
published only after `verify` passes.

| Job | Runner | Secrets | What it does |
|---|---|---|---|
| `check-tag` | ubuntu-latest | none | Checks the tag (above) and that `CHANGELOG.md` has its section, fails unless signing is configured, creates the draft |
| `build` | windows-latest (x64), windows-11-arm (ARM64) | none | `cargo xtask dist --locked` release builds, natively; uploads the unsigned executables, the symbols archive and the size report, warning about binaries more than 10% larger than in the previous release |
| `server` | ubuntu-latest | none | The Linux server binary |
| `sign` | windows-latest | `release-signing` environment | After a reviewer approves: signs every executable, builds each architecture's package from the **signed** executables (`dist --from`, which first checks they are this version's), signs each package, writes `SHA256SUMS` over the final files and signs it; replaces the unsigned files in the draft |
| `verify` | windows-latest (x64), windows-11-arm (ARM64) | none | Checks `SHA256SUMS`, then each architecture's package, on its own architecture's runner, and every executable **inside** it (unpacked with an administrative install) with the OS signing tool's default policy, every signature, SHA-256, and an RFC 3161 timestamp. Any unsigned, invalid or untimestamped file fails the release |
| `provenance` | ubuntu-latest | none | The hook for the SBOM, build provenance and signed update manifest (#18, #226); see [Provenance](#provenance) |
| `publish` | ubuntu-latest | none | The `CHANGELOG.md` section as release notes, the pre-release flag for `-alpha`, `-beta` and `-rc`, and publishes the draft |

Only `check-tag`, `build`, `server`, `sign` and `publish` can write to releases
(`contents: write`), only `sign` sees a secret, and nothing in this workflow uses a cache. A
test in `xtask/src/release/mod.rs` keeps these rules: secrets only in the environment job,
pull requests run only the dry run, releases are always timestamped, and publishing needs
`verify`.

A release contains:

- `Palisade-<version>-x64.msi` and `Palisade-<version>-arm64.msi`, signed, with signed
  executables inside;
- `palisade-<version>-x64-symbols.zip` and `palisade-<version>-arm64-symbols.zip`;
- `palisade-server-<version>-linux-x64`;
- `sizes-x64.json`, `sizes-arm64.json` and `sizes-linux-x64.json`, for the next release's size
  comparison;
- `SHA256SUMS` and `SHA256SUMS.sig`.

### Dry run on pull requests

A pull request that changes `release.yml`, `xtask/src/dist/`, `xtask/src/release/` or
`packaging/` runs the `dry-run` job instead: the same build, signed with a throwaway test CA
created on the runner, packaged, signed again, every signature verified (timestamps aside, as
there is no timestamp server in a test), and the checksums written and checked. It has no
secrets, no environment, no write access and uploads nothing.

In addition, CI's `sign-test` job ([ci.md](ci.md)) runs on every pull request: the test-CA build
and verification, the `pfx` signer with a throwaway PFX whose password is a canary that must not
appear in the output, and a signed package of unsigned executables, which `release verify` must
reject.

## Code signing

Signing is pluggable (`cargo xtask sign --signer <kind>`, `xtask/src/release/sign.rs`). Every
signer signs PE files and packages in place with a SHA-256 file digest and an RFC 3161 timestamp,
and verifies them.

| Signer | Used by | Key material |
|---|---|---|
| `none` | Pull request and `main` builds | None: logs what it would sign |
| `test-ca` | CI tests and the release dry run | A throwaway root CA and leaf made on the runner and deleted; its signatures are trusted only where its root was installed |
| `pfx` | Releases | A PKCS#12 file with its password, from the `release-signing` environment |
| `cloud-hsm` | Releases | A remote signing service, through a command template; the key never leaves the service |

There is no publicly trusted code-signing certificate yet. That is the one step only the
maintainer can do; everything else is in place.

### What the maintainer sets up

1. **A code-signing certificate.** Either:
   - an **Authenticode code-signing certificate** (the "code signing" extended key usage,
     1.3.6.1.5.5.7.3.3) from a publicly trusted certificate authority, with its private key, as
     a password-protected PKCS#12 (`.pfx`) file, for the `pfx` signer. Current CA rules require
     such keys to be generated and kept on hardware, so a PFX export is often only possible
     for an internal enterprise CA; or
   - a **remote signing service or HSM** that signs files through a command-line client, for
     the `cloud-hsm` signer.

   An educational project may not have either. Without a publicly trusted certificate, the OS
   download-reputation check warns when the package is downloaded. That is an accepted
   limitation; it does not change what `verify` checks.

2. **The `release-signing` environment** (Settings → Environments → New environment):
   - **Required reviewers**: the maintainer (and any co-maintainer). Prevent self-review if
     there is more than one.
   - **Wait timer**: for example 5 minutes, so a mistaken tag can be cancelled.
   - **Deployment branches and tags**: *Selected branches and tags*, with the tag rule `v*`
     only. No branch can deploy to it.

   With `gh`:

   ```sh
   gh api -X PUT repos/jusso-dev/palisade/environments/release-signing --input - <<'EOF'
   {
     "wait_timer": 5,
     "prevent_self_review": false,
     "reviewers": [{ "type": "User", "id": <maintainer user id> }],
     "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
   }
   EOF
   gh api -X POST repos/jusso-dev/palisade/environments/release-signing/deployment-branch-policies \
     -f name='v*' -f type=tag
   ```

3. **Environment secrets** (in `release-signing`, never repository secrets):

   | Secret | Signer | Value |
   |---|---|---|
   | `PALISADE_SIGN_PFX_BASE64` | `pfx` | The `.pfx` file, base64-encoded (`base64 -w0 signing.pfx`) |
   | `PALISADE_SIGN_PFX_PASSWORD` | `pfx` | Its password |
   | `PALISADE_SIGN_COMMAND` | `cloud-hsm` | The client command that signs one file in place, with `{file}` where the path goes, for example `remote-sign --profile palisade --digest sha256 --timestamp {file}`. It is split on spaces and run without a shell. The client reads its own credentials from further environment secrets, which the maintainer adds to the `sign` job's `env` |
   | `RELEASE_CHECKSUM_KEY` | all | The Ed25519 SSH private key that signs `SHA256SUMS` ([below](#checksum-signing-key)) |

4. **Repository variables** (Settings → Variables; not secret):

   | Variable | Value |
   |---|---|
   | `RELEASE_SIGNER` | `pfx` or `cloud-hsm`. Until it is set, `check-tag` fails every release tag with "Signing not configured" |
   | `RELEASE_TSA_URLS` | One or more RFC 3161 timestamp server URLs, separated by spaces, tried in order. Use the certificate authority's own server first |
   | `RELEASE_PROVENANCE` | Leave unset until #226 lands ([Provenance](#provenance)) |

5. **Protect `v*` tags** with a tag ruleset, so only the maintainer can create, move or delete
   release tags:

   ```sh
   gh api -X POST repos/jusso-dev/palisade/rulesets --input - <<'EOF'
   {
     "name": "release tags",
     "target": "tag",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
     "rules": [{ "type": "creation" }, { "type": "update" }, { "type": "deletion" }, { "type": "required_signatures" }],
     "bypass_actors": [{ "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }]
   }
   EOF
   ```

   `required_signatures` makes GitHub refuse tags whose signature it cannot verify against the
   tagger's registered keys.

### How secrets are handled

- They exist only in the `release-signing` environment, which only `v*` tags can use and a
  reviewer must approve. Pull request workflows never see them (`pull_request` runs get no
  secrets from environments they cannot deploy to, and this one has a tag-only policy).
- They are passed to `cargo xtask sign` in the environment, never on a command line. The PFX is
  written to a temporary folder only the job's user can read, imported into that user's
  certificate store for one signature, then removed from the store and deleted in a `finally`
  block, whatever happens. The signing tool only ever gets the certificate thumbprint.
- `cargo xtask sign` replaces any secret value in the signing tool's output with `***` before
  printing it, on top of GitHub's own masking of secrets. No signing step uses `set -x`.
- The checksum key is written to a mode-600 file under the runner's temporary folder and
  removed by a `trap` on exit. A final `always()` step removes the signing work folders.
- The `sign-test` job proves this with a canary: it signs with a throwaway PFX whose password is
  a random value, and fails if that value, or the PFX, appears in the output.

### Key rotation

1. Obtain the new certificate (or service key) before the old one expires.
2. Replace the environment secrets. Releases signed with the old certificate stay valid: every
   signature is timestamped, so it outlives the certificate.
3. If a key may have been exposed, revoke the certificate with the CA first, then rotate, then
   follow [Yanking](#yanking) for any release signed after the possible exposure.
4. Rotate `RELEASE_CHECKSUM_KEY` the same way and publish the new public key in this file.
   Pinning the publisher certificate in the agent, and dual-signing during rollover, are #226;
   key management as a whole is #18.

### Checksum signing key

`SHA256SUMS.sig` is an SSH signature (`ssh-keygen -Y sign`, namespace `palisade-release`) made
with an Ed25519 key held as `RELEASE_CHECKSUM_KEY`. Create it once:

```sh
ssh-keygen -t ed25519 -N '' -C 'palisade-release' -f palisade-release
# Secret: the contents of palisade-release. Public key: palisade-release.pub, published here.
```

To check a download:

```sh
echo "palisade-release $(cat palisade-release.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I palisade-release -n palisade-release \
  -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

The public key is published here once the maintainer has created it.

## Release checklist

### Pre-flight

1. `main` is green, and nothing is waiting that must be in the release.
2. Check open security advisories (Security → Advisories). A fix under embargo is released as
   in [Security fixes](#security-fixes), not as an ordinary release.
3. Prepare the release on a branch:

   ```sh
   git switch -c release/v0.2.0 origin/main
   RELEASE_DATE=2026-12-01 cargo xtask release prepare 0.2.0
   ```

   This sets `workspace.package.version`, updates `Cargo.lock` to match (the release builds
   with `--locked`), and adds a `CHANGELOG.md` section generated from the
   Conventional Commit titles merged since the last release tag, under Breaking, Security,
   Features, Fixes, Docs and Internal. Edit the wording if needed, commit all three files, then
   open a pull request
   titled `chore(release): 0.2.0` and merge it once CI passes.
4. Tag the merge commit and push the tag:

   ```sh
   git switch main && git pull
   git tag -s v0.2.0 -m "Palisade 0.2.0"
   git push origin v0.2.0
   ```

5. Approve the `sign` job when it asks (Actions → the run → Review deployments), after checking
   the run is for the tag you pushed.

### Security fixes

Under the [coordinated disclosure](../SECURITY.md#coordinated-disclosure) process, a fix is
prepared in the advisory's private fork, merged and released at the agreed time. Keep the
changelog entry vague (`security: fix a policy bypass`) until the advisory is published, then
publish the advisory, which links the release, the same day. Do not tag before the fix is ready
to ship: tags are public.

### Post-release verification

1. Download the release files and check the checksums and their signature as in
   [Checksum signing key](#checksum-signing-key).
2. On a Windows machine, check a package: `Get-AuthenticodeSignature Palisade-0.2.0-x64.msi`.
   It should be valid and timestamped.
3. Install it on a test machine or VM, silently, and check the service runs
   ([packaging.md](packaging.md#properties)). The VM harness automates this (#26).
4. Check the release is marked as a pre-release exactly when its version has `-alpha`, `-beta`
   or `-rc`.

## Yanking

A published release is never deleted or replaced: someone may already have it, and a deleted
release cannot be audited. To withdraw one:

1. Edit the release: put **Withdrawn: <reason>. Use <version> instead.** at the top of its
   notes, and mark it as a pre-release so it is no longer *latest*.
2. Publish a security advisory if the reason is a vulnerability.
3. Release the fixed version as usual.
4. The update channel's signed metadata (#18, #226) stops offering the withdrawn version.
   Until that exists, the release notes are the notice.

The tag stays. A tag that was pushed but whose release failed before publishing leaves only a
draft. Delete the draft, fix the problem, and tag a new patch version rather than moving the
tag.

## Provenance

The `provenance` job is the slot for the SBOM, build provenance attestation and signed update
manifest (#18, #226). It runs `cargo xtask release provenance`, which does nothing while the
`RELEASE_PROVENANCE` variable is unset. Once #226 adds `cargo xtask sbom`, set the variable to
`on`: from then on the job runs it and fails the release if it is missing or fails, so a release
can never silently ship without provenance again.

## Not covered here

- Publishing the SBOM, provenance and the signed update manifest: #226 (hook above).
- Signing the server's container image: #18.
- Installing a release on clean VMs as part of the release: #26.
- Driver catalog signing: #8.

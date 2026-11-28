# palisade-agent

The Windows endpoint agent: a Windows service that collects execution events, caches policy locally and drives enforcement.

**Status:** service host only. The process, component model, supervisor, lifecycle states and configuration loading are in place ([#56](https://github.com/jusso-dev/palisade/issues/56)). The subsystems so far are `config`, `clock`, `inventory`, `policy_cache` (#61) and, on Windows, `process-monitor` (#59); see below. Server comms (#62), the installer (#57) and tamper protection (#220) come later. Parent epic: [#4](https://github.com/jusso-dev/palisade/issues/4).

## Running

```sh
palisade-agent --console [--config <path>]   # foreground, any OS, stop with Ctrl-C
palisade-agent --service [--config <path>]   # Windows only, started by the service control manager
palisade-agent --simulate [--scenario <path>] # development builds only: the fake agent, see below
```

Without `--config`, the agent reads `%ProgramData%\Palisade\agent.toml` on Windows if it exists, and uses built-in defaults otherwise. If the file exists but is invalid, the agent does not start. The OS-native policy keeps enforcing while it is down ([ADR 0012](../../docs/adr/0012-fail-open-vs-fail-closed-defaults.md)).

## Configuration

Strict TOML. Unknown keys, wrong types and out-of-range values are errors. The file is limited to 64 KiB.

```toml
fail_mode = "fail_open"               # or "fail_closed"; see below
safe_mode_behaviour = "audit_only"    # "enforce_cached" | "audit_only" | "disabled"

[runtime]
worker_threads = 4                    # 1..=64; default min(4, cores)
max_blocking_threads = 8              # 1..=256; file I/O and hashing pool

[log]
level = "info"                        # "error" | "warn" | "info" | "debug" | "trace"
files = 10                            # 1..=100; log files kept, the current one included
file_size_mib = 10                    # 1..=1024; size limit of one log file
```

On Windows the agent logs to standard error and to `%ProgramData%\Palisade\logs\agent.log`, which rotates by size to `agent.log.1` and onwards; with the defaults the log takes at most 100 MiB. The installer creates the directory with its ACL. If it is missing, the agent logs to standard error only. The level can change while the agent runs (on `PARAMCHANGE`); a change of rotation applies at the next start.

`fail_mode` defaults to `fail_open` for M1. That is a security trade-off: while the agent's decision engine is unavailable, agent-side decisions allow, and the kernel-enforced OS-native policy stays the baseline ([ADR 0002](../../docs/adr/0002-enforcement-strategy.md)). Enforcement components (#113) consume the setting.

The effective configuration has four layers, lowest priority first: built-in defaults, this file, the agent settings delivered with policy (#61), and local overrides in `%ProgramData%\Palisade\overrides.toml`. `settings::resolve` merges them and records where each value came from; `Effective::render` is the text `palctl config show` prints, with secret settings redacted. Overrides apply only while the policy sets `allow_local_overrides = true` and only if the file and every folder above it can be written by SYSTEM, Administrators and `TrustedInstaller` alone; otherwise they are ignored and reported. A policy layer or overrides file that would make the configuration invalid is dropped and reported, never fatal.

Advanced settings (`agent.advanced.*`, delivered with policy) are checked against `settings::ADVANCED_SCHEMA` (name, type, range, default, whether secret). Unknown keys are logged and ignored; a wrong type or out-of-range value is logged and replaced by the default. The policy cache (#61) supplies the policy layer when it lands; until then the agent runs on the first two layers.

## Design

- `subsystem`: the `Subsystem` trait (`name`, `criticality`, `dependencies`, `run`, `health`, `start_timeout`, `stop_timeout`). A run calls `set_ready` once initialised, works until `stopped()` resolves, and returns by the given deadline.
- `supervisor`: starts subsystems in dependency order, which must be acyclic. A subsystem's dependents wait until it is ready. A run that fails is restarted with exponential backoff from 1 s to 5 min. Failure means an error, an early exit, a panic or a start timeout. A panic is contained in that subsystem's task. Three panics within 10 minutes mark the subsystem `Failed`. Shutdown runs in reverse order within a budget, and subsystems that miss their deadline are aborted.
- `lifecycle`: the agent states (`Starting`, `Running`, `Degraded`, `SafeMode`, `Updating`, `Stopping`, `Stopped`, `FailSafe`) and the legal transitions between them. A permanently failed critical subsystem forces `FailSafe`, and only stopping leaves it.
- `host`: the tokio runtime (ADR 0009), logging to standard error with a level that can change at run time, the panic hook, the `config` subsystem and the console run loop.
- `clock`: the `clock` subsystem. It compares the wall clock with the monotonic clock every 30 s and on `TIMECHANGE`, and reports a disagreement of more than 5 minutes as a clock jump (ISM-0988). A suspend and resume starts a new baseline instead.
- `boot`: safe-mode detection, from `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option`. In a safe-mode boot the agent reports `SafeMode` instead of `Running` or `Degraded`, and enforcement applies `safe_mode_behaviour`. A registry read that fails counts as a normal boot, since safe mode can only relax enforcement.
- `facts`: the bridge from a file's `palisade_fileid` identity to the facts policy evaluates (#318, #328). `from_identity` maps hashes, every signature (embedded and catalog) with its chain's names, thumbprints, TBS and key hashes, EKUs, keys and digests, the version resource, PE and installer facts, and the final path with its volume and ACL facts, and reports which fact classes the record covered so the engine asks for the rest. It fails closed: a fact fileid did not compute is absent, a partial signature list is unknown rather than short, only a signer fileid counts usable is trusted (never one resting on SHA-1, revoked, or expired without a trusted timestamp), and a path is trusted only on a fixed local volume with proven ACLs. It lives here, not in `palisade-policy`, because fileid's graph reaches `windows-sys`, which policy may not depend on. The execution path that calls it comes with #58, #59 and #113.
- `inventory`: the file inventory model (#60). `InvEntry` records a file by volume serial and file ID, with its path and last 10 paths, an identity summary, first-seen, last-modified and last-executed times, how it was found, and its state. `InventoryStore` is the storage trait ADR 0007 asks for until its store spike, with `MemoryStore` behind it. `track` gathers changes per file for 2 s and until the file is closed (at most 60 s), applies them (new files, content changes, renames with history, deletes kept for the retention period, security changes) and says what each needs next. A change marks the entry stale, or its location unassessed, as soon as it is seen, so an old identity is never used while a file is rewritten. A location not assessed counts as user-writable. `changes_from_journal` maps change-journal records to changes. `engine` runs one volume: the initial scan in batches, keeping candidates (phase 1 drops content that cannot run code), saving a checkpoint every 10,000 files or 30 s so a restart resumes, and asking a `Throttle` before each batch (the #65 budgets plug in there); then journal polling from the saved cursor. A replaced or wrapped journal, or a lost cursor, reconciles the volume: a full rescan that marks files no longer listed as deleted and identifies known files again. The `inventory` subsystem (non-critical, after `config`) runs it on a blocking thread over every fixed NTFS or ReFS volume on Windows, reading each file by its ID and keeping an identity only if it describes that ID (T-agent-13). Its health is `Degraded("Baseline: scanning …")` until every volume's first scan is complete. Volumes without a journal are rescanned daily. Off Windows it has no volumes.
- `control`: OS notifications as `HostEvent`s (session, power, parameter and time changes), which every subsystem can follow through `SubsystemContext::host_events`, and the `TamperGuard` trait that decides whether `STOP` is offered (#220 implements it; until then `STOP` is always allowed).
- `service` (Windows): the service control manager integration. It handles `STOP` (20 s budget, offered only while the tamper guard allows it), `PRESHUTDOWN`/`SHUTDOWN` (10 s budget), and turns `POWEREVENT`, `SESSIONCHANGE`, `PARAMCHANGE` and `TIMECHANGE` into host events. `PARAMCHANGE` makes the `config` subsystem read the configuration again; a reload that fails keeps the current configuration.

### Policy cache

`policy_cache` (#61) decides which policy the agent enforces and activates new bundles, following ADR 0007 and ADR 0018. The decisions themselves (what loads at startup, whether a bundle is accepted, the anti-rollback record and staleness) are `palisade_proto::policy_bundle` (#304); this module does the file I/O in the required order and swaps the evaluator.

- Files: `active`, `previous` (last known good) and `pending` in the SYSTEM-only store directory, each written to a temporary file, flushed, then renamed over its target with write-through (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` on Windows), and the anti-rollback record copies (`RecordStore`).
- At rest (#326): `PolicyStore::sealed` seals every cache file with AES-256-GCM (`palisade_proto::policy_bundle::at_rest`, through `ring`) under a data key. Its keyring is protected by a `Protector` (machine-scope DPAPI on Windows through `ffi`, `MemoryProtector` elsewhere) and persisted with its seal count before every seal. Nonces are random and drawn inside the seal call; each key seals at most 2^32 times, then rotates (ADR 0017). The opened bytes are still the signed envelope and are verified as before; a file that does not open is unreadable. A keyring that is lost or does not unprotect is replaced, so old files count as unreadable and the cache falls back without trusting them. `ProtectedRecordStore` keeps the record copies DPAPI-protected in separate `RecordSlot`s (a file and an `HKLM` registry value on Windows); a copy that does not unprotect reads as corrupt and is reported.
- Startup: deletes a leftover `pending`, loads `active` if it verifies and is at or above the floor, else `previous` under the one-step exception, else the built-in emergency policy once a policy was ever accepted (it allows only OS-publisher binaries in the protected OS locations, through the agent's `system_baseline`, and Palisade's own images pinned by hash and publisher, and blocks the rest; enforce mode, or audit mode with `PolicyEmergencyUnenforced` health under `native_only`; it never touches the installed native policies), else the first-install policy (audit mode). A bundle that does not decode, validate or compile is refused like an unsupported schema, and the next candidate is tried.
- Activation (`PolicyCache::activate`): verify and compile in memory, write `pending` and read it back, copy the verified bytes of the running `active` to `previous`, clear the record's fallback, rename `pending` over `active`, raise the floor, then swap. A failure before the rename leaves the running policy in force, on disk and in memory. A rollback is a new, higher version from the server (#225); there is no rollback flag.
- Evaluation: `PolicyCache::current()` returns the running `Active` from an `ArcSwap`. A decision holds it to the end, so a swap never mixes two policies, and the `Verdict` names the `policy_version` and bundle hash that decided.
- Offline: staleness (no bundle within `policy.stale_after`, 7 days by default, or past `expires_at`) is reported as `PolicyStale` health and never relaxes anything. `PolicyCache::mark_current` restarts the window on a check-in. Deltas are rebuilt into a full bundle envelope (`rebuild_from_delta`, through `envelope::rebuild`), which carries the delta's signatures and is verified as a whole before activation.
- Verification: each cache file is a signed bundle envelope (#325). `SignedEnvelopes` runs `palisade_proto::policy_bundle::envelope::verify` against the device's trust set (shared in an `ArcSwap`, so a trust-set update swaps it whole) at trusted time, before anything past the bundle header is decoded. An accepted bundle loads in one step (`palisade_policy::bundle::load`, then `Engine::from_loaded`) with its inlined library sets and, when the agent reports them, its `system_baseline` facts.
- Re-verification (`PolicyCache::reverify`, every 15 minutes by default): the running bundle's bytes in memory are checked against the hash they were loaded with, the envelope against the trust set at trusted time, and the cache file on disk against the bytes in memory. A bundle that no longer matches or passes is reloaded as at startup (failing closed onto `previous` or the emergency policy); a changed file is rewritten from the verified copy. Both raise `agent.tamper`.
- Events: activation, rejection, startup findings, the emergency policy (with whether it is enforced), staleness and tamper go to a `PolicyEventSink`. `BoundedSink` queues them in memory, bounded, dropping and counting what overflows, until the event pipeline (#63) implements the trait.
- Seams: enrolment (`comms`, #223) supplies the target and trust set, and #220's protected store the record key; until both are wired the host registers an unenrolled cache that runs the first-install policy. Encryption at rest, the emergency policy content and periodic re-verification are #326.

### Server communication

`comms` (#223 enrolment, #62 check-in) talks to the server with the messages in `palisade_proto::comms`, in the JSON encoding ADR 0015 names for the fallback. gRPC is still to come.

- TLS (`comms::tls`): the restricted `ring` provider, the same as the server's `default` profile (TLS 1.3 and 1.2, AES-GCM, X25519/P-256/P-384). The server is authenticated against pinned root keys, never the OS store. Before enrolment the pin is the installed `PALISADE_CA_PIN`. Afterwards the pins are the trust set's server pins and the root. A chain must verify to a root whose SPKI SHA-256 is pinned, with the hostname always checked. Anything else fails as `transport.pin_mismatch` and is not retried on a weaker setting. The client certificate is signed by `LeafKey::sign_tls`, so the device key stays inside its type. #220's TPM-backed key replaces that behind the same call.
- Transport (`comms::transport`): one HTTP/1.1 request per connection, direct or through an explicit `http://` proxy over a `CONNECT` tunnel, with optional `Proxy-Authorization`. `NO_PROXY` is honoured. Every request has a 30 s deadline, and responses are bounded and framed by `Content-Length` only, so a general HTTP client stack stays out of the service. TLS runs end to end inside the tunnel.
- Enrolment (`comms::enrol`): generates a P-384 device key and posts the signed request. Before storing anything it checks three things: the issued certificate certifies this key, the root key hashes to the installed pin, and the trust set verifies under that root. A rejected code, a source outside the restrictions or a hardware-key requirement stops enrolment until an administrator acts. Rate limits and network failures are retried with backoff.
- Identity (`comms::identity`): the device and tenant IDs, the chain, the pinned root, the last accepted trust set, the check-in URL and the device key's PKCS#8, sealed in one file by a `Protector` (machine-scope DPAPI on Windows). A missing file means not enrolled. A corrupt or foreign one is an error, never a silent re-enrolment.
- Check-in (`comms::checkin`): posts versions and health over mTLS at the server's interval with ±20% jitter. Failures back off from 1 s up to four intervals, and `Retry-After` is honoured. It fetches a newer trust set and accepts it only through `TrustAnchor::accept`, then swaps it into the policy cache's `SharedTrust`. It fetches a newer or different bundle and hands it to `PolicyCache::activate`. A `device_rejected` reply stops check-in and reports unhealthy.
- Subsystem (`comms::subsystem::CommsSubsystem`, non-critical): registered only when `PALISADE_SERVER` is set. Its inputs are `PALISADE_SERVER`, `PALISADE_CA_PIN`, `PALISADE_REGCODE`, and optionally `PALISADE_PROXY`, `NO_PROXY` and `PALISADE_DATA_DIR`, until the installer writes them into `agent.toml` (#57).
- Not yet: handing the enrolled target and record key to a policy cache built for this device, which needs #220's protected store (`CommsSubsystem::with_cache` takes them once it exists); the fake agent posting its events (#334, after the event pipeline #63); gRPC and the fallback triggers, push, relays, commands, PAC/WPAD, NTLM/Negotiate proxies, metered networks and network-change check-ins (#62); certificate renewal (#223).

### Adding a subsystem

Implement `Subsystem`, give it a stable `name`, choose its `criticality` and list the names it depends on in `dependencies` (usually at least `config`). Construct it in `host::builtin_subsystems` with what it needs, such as a `ConfigSubsystem::subscribe` receiver, after the subsystems it depends on. In `run`, subscribe to `ctx.host_events()` if it needs OS notifications, call `ctx.set_ready()` once initialised, and return by the deadline `ctx.stopped()` gives.

## Process monitor (#59)

`telemetry` watches process starts and stops and image loads (executables, libraries and drivers) through a real-time ETW session, `Palisade-Agent-Trace`, with the kernel process provider bound by GUID. Console and service runs register it (`host::agent_supervisor`); `host::supervisor`, which tests use, does not, so tests never touch the machine-wide session.

- `telemetry::kernel` decodes the provider's records: process start versions 0 to 4, stop 0 to 2, image load and unload 0. It is portable and fuzzed (`crates/palisade-agent/fuzz`, target `kernel_records`). An unknown version, a short record, trailing bytes, a string without its terminator or text that is not valid UTF-16 is an error, never a guess.
- `telemetry::tree` is the process tree, keyed by process ID **and** creation time. A parent is linked only if its sequence number matches, or if it has the recorded parent ID, was created no later than the child and was still running then. A reused process ID is never read as the parent. Exited processes are kept for 10 minutes so late events can be correlated, and the tree holds at most 200,000 processes. When it is full, the process that exited first is evicted; a new process that still finds no room is counted, not recorded.
- `telemetry::cmdline` captures command lines (`capture_cmdline`, on by default). It redacts them with the decision-trace redactor, with default patterns for `password=`, `-p <x>` and similar that policy can add to but not remove, and then cuts them to 32,767 characters with a `truncated` flag.
- `telemetry::monitor` is the state machine. It runs a startup snapshot (`observed_start = false`), finds parents, reads command lines and tokens, and emits `ProcessStart`, `ProcessStop`, `ImageLoad` (drivers always; libraries per `dll_events`, where `untrusted_only` emits every library until identity results arrive) and an advisory `ParentSpoof` when the creator is not the recorded parent. A `PostStartAction` hook is off by default.
- `telemetry::output` is the seam to the event pipeline (#63): a non-blocking `TelemetrySink`, a bounded `ChannelSink`, and `process_fields`, which builds the canonical `process` field set with its parent and grandparent. Until #63 lands, the host wires a `DiscardSink`.
- On Windows, the ETW callback (`ffi::etw`) only copies records into a bounded queue (50,000). A worker thread decodes them. The subsystem's health reports events the OS lost, records dropped from the queue or not decoded, and events the sink refused, so no loss is silent. A stale session left by a crash is stopped and started again.

Still to come, tracked on #59: identity resolution and audit evaluation of each image (they need the hash cache and policy cache, #61), image-hijack detection, masquerade signals (#55), directory group resolution, the file provider, the NT kernel logger fallback, and the Windows integration and stress tests.

## Event-log ingestion (#58)

`eventlog` turns the OS code integrity, legacy rule-collection and PowerShell logs into canonical events. Every step that reads record text is portable and fuzzed (target `eventlog_records`):

- `eventlog::decode` reads rendered event XML (`EvtRenderEventXml`) with the bounded XML reader from `palisade_fileid::package::xml`, which refuses DTDs, undefined entities and oversized input. It produces a `palisade_proto::mapping::Record`, with field names normalised to the mapping files' form (`SHA256 Flat Hash` becomes `SHA256FlatHash`). A record without a parseable event ID or time, or with a repeated field, is an error.
- `eventlog::correlate` holds each 3076/3077 (and each script host's 8028/8029) until its `TotalSignatureCount` signature records (3089, 8038) with the same activity ID arrive, or for 2 s. It then releases the group, marked incomplete if signatures are missing. Before correlation, a token bucket (2,000 records/s) bounds audit storms. Every drop is counted: rate-limited records, orphan and excess signatures, and groups evicted early.
- `eventlog::ingest` maps groups through the shipped mapping files and adds the process key, parent, grandparent and command line from the #59 process tree when the tree knew that process at the record's time. It keeps every value the OS log supplied, and emits into an `EventSink`, with an `EnvelopeSource` standing in for the event pipeline (#63).
- `eventlog::inventory` keeps the latest 3099 activation of each OS-native policy (ID, name, GUID, hash, option bits with names) for health (#67).
- `eventlog::CHANNEL_SUFFIXES` lists the channels by name suffix, marking which ones are optional (MSI and Script is absent on Server Core).

Still to come, tracked on #58: the `EvtSubscribe` subscription with bookmarks persisted in the agent local store (ADR 0007), the first-start backfill, channel name resolution, the verbose channel and channel-size management, and the periodic policy store query.

## Platform layer

The agent reads the OS only through the `palisade_core::platform` traits (#29), so its logic can be
tested on any OS against the mocks in `palisade_core::test_util`. `palisade_agent::platform` holds
the real implementations:

| Trait | Implementation | Status |
|---|---|---|
| `Clock` | `SystemClock` | Done. The one place that reads the wall clock (`clippy.toml` bans `SystemTime::now` elsewhere) |
| `FileSystem` | `StdFileSystem`; `windows::WindowsFileSystem` | Reads, size and times on every OS, opened so other processes can keep writing and deleting. On Windows, `WindowsFileSystem` adds the file ID, volume serial and USN (from the open handle), the owner SID, the security descriptor and the alternate data streams, through `palisade_fileid::win`; `StdFileSystem` reports those `Unsupported` |
| `Environment` | `StdEnvironment` | Variables, architecture and interface addresses everywhere; host name, domain and OS version from the OS on Windows. On Windows, the connection type is that of the interfaces the OS routes internet-bound IPv4 and IPv6 traffic through (`GetBestRoute2`, then `GetIfEntry2` by LUID), read on each call: wired, wireless or cellular only for an up, connected hardware interface that is not a tunnel and whose type and physical medium agree; VPN only for a virtual tunnel interface (it means some tunnel, not a trusted network, which is #38's question); offline only when neither family has a route; and `Unknown` otherwise and on other OSes |
| `Registry` | `windows::WindowsRegistry` | Done, on Windows |
| `IdentityProvider` | `windows::WindowsIdentity` | On Windows: a process's token (user, groups with deny-only flags, session ID and kind, integrity level, elevation type and state), account names, local group members by SID, and the directory group cache (filled by the directory sync, #38) |
| `ProcessInfo` | `windows::WindowsProcesses` | On Windows: process records keyed by process ID and creation time, with parent ID, image path and command line, read through one handle |
| `SignatureVerifier` | `FileidSignatures` | Every OS: embedded Authenticode signatures, chains, timestamps, expiry and revocation, and catalog lookups, all judged by `palisade_fileid`, against the trust, validity and revocation settings and the catalog store policy supplies |

The Windows identity and process backends fail closed
([ADR 0018](../../docs/adr/0018-fail-open-vs-fail-closed-defaults-revised.md)). A token is read
in full or not at all: if the OS refuses its user, groups, integrity level or elevation type, the
query fails instead of returning a token with a part guessed, so a failed elevation query never
reads as "not elevated". Only the session kind falls back: session 0 is always `Services`, whatever the protocol query says, and a non-zero session whose protocol cannot be read is `Unknown`, never `Console`. A
group that is in a token but not enabled is reported as deny-only, like a group UAC filtered,
since the OS does not use it to grant access. A process that has exited is `NotFound`, even
while a handle keeps its object alive, and a process key whose creation time does not match the
process now using its ID is `NotFound` too, so a reused process ID is never read as the process
it replaced. A local group's members are listed only if the SID names a local group whose name
resolves back to the same SID: the bare name the OS enumerates by must itself be a local group with that SID, so a local group that only shares a domain group's name is never listed in its place. The name is checked again after the members are read, and a group renamed meanwhile is an error, not another group's members (#60). A rename and restore inside that window still passes; only an administrator can rename a local group. An account name lookup that fails for any reason other than "no such account" is an error, not `None`.

The signature and file-system backends fail closed too. A file that cannot be read, or is larger
than the size limit (256 MiB by default), is an error, never "unsigned"; so is a file that
starts like a PE image but does not parse, or whose certificate table cannot be read
(`MalformedSignature`). A file whose hash is revoked (its flat or Authenticode SHA-256 or SHA-1)
is `RevokedByHash` on the embedded and the catalog path alike. A signature or catalog match that
relies on SHA-1 is `WeakHashAlgorithm` (ADR 0008). With no catalog store, or an incomplete one (a
load error or limit, an unreadable catalog, a truncated index), a catalog miss is an error, not
"no catalog signature", and a catalog whose expiry and revocation were never judged is not `Ok`.
Embedded signatures are judged on every call against the current settings and clock; a
catalog's own signature is judged when the store is built, so the store is rebuilt to re-judge
it, while the file's own revocation is checked on every call. The OS trust-verification API is
never consulted: it is a diagnostic cross-check (`palisade_fileid::win::trust`) and must not
decide. Owners and security descriptors are reported only on volumes where they can be relied on
(a local NTFS or ReFS physical disk), and `None` elsewhere, which writability checks read as
possibly writable; a descriptor is checked by `palisade_fileid`'s parser before it is returned; a
named stream has no file ID, volume serial or USN of its own; and a stream list the OS cut short
is `TooLarge`, never a complete list.

Each implementation passes the same contract checks as the mocks
(`palisade_core::test_util::contract`), in `tests/platform.rs`, on every CI runner. The Windows
registry, environment, identity, process and file-system tests run on the Windows runners,
against the test process itself, its token and files it creates. `tests/signatures.rs` runs the
signature backend on every OS against `palisade_fileid`'s fixtures, including the shared
`contract::signatures` check that `MockSignatures` also passes.

## The fake agent

`palisade-agent --simulate`, in a build with the `test-util` feature, replays a scripted scenario
on the mock platform and writes the agent's events to standard output, one canonical JSON event
per line. It runs on any OS, so server and console work needs no Windows machine
([docs/dev/unix.md](../../docs/dev/unix.md#the-fake-agent)).

```sh
cargo run -p palisade-agent --features test-util -- --simulate [--scenario <path>]
```

It emits `agent.started`, one `exec.decision` per step, then `agent.stopped`. The events are built
only through the platform traits: process, parent and grandparent (from the process-ID-reuse-safe
ancestry), user and session, image hash and signer, and the host. Every event passes
`Event::validate`, is numbered (`seq`) and linked to the previous one (`prev_hash`; a plain
SHA-256 placeholder until the keyed chain in #220 and #202), and the same scenario always gives the
same events. Decisions are scripted, not evaluated (evaluation comes with the policy cache, #61).
Sending the events to a server needs the agent endpoints and enrolment (#62, #126, #223).

A scenario is strict TOML (unknown keys are errors, at most 1 MiB and 10,000 steps). The built-in
one is [`scenarios/default.toml`](scenarios/default.toml).

```toml
start = "2026-01-05T09:00:00.000000Z"   # the simulated wall clock at start
mode = "audit"                          # audit | monitor | learning | enforce

[device]
hostname = "SIM-0001"
domain = "example.test"                 # optional
os_version = "10.0.26100.2314"          # major.minor.build.revision
architecture = "x64"                    # x64 | arm64 | x86
tenant_id = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61"   # UUIDv7
host_id = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60"     # UUIDv7

[[user]]                                # every SID a process runs as
sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
name = "alice"
domain = "EXAMPLE"                      # optional
session = "console"                     # console | remote_desktop | services
elevated = false                        # optional; elevated users hold Administrators

[[running]]                             # processes running before the first step
pid = 5120
parent = 744                            # optional
image = 'C:\Windows\explorer.exe'
user = "S-1-5-21-1111111111-2222222222-3333333333-1001"

[[step]]                                # one process start each
after_ms = 1500                         # time since the previous step, at most a day
exited = []                             # process IDs that exit first (to reuse an ID)
pid = 6200
parent = 5120
image = 'C:\Windows\System32\cmd.exe'
command_line = "cmd.exe /c ver"         # optional
user = "S-1-5-21-1111111111-2222222222-3333333333-1001"
outcome = "allowed"                     # allowed | blocked | audited
signer = "Example OS Publisher"         # optional: the image's signature publisher
```

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. Must never depend on `palisade-server` or any HTTP server or database stack. The rules are enforced by `cargo xtask check-deps`.

Workspace: `palisade-fileid`, for SIDs, signature verification and catalog lookups, and on Windows with its `os-trust` feature, for account names and the file-system context (ADR 0003: the agent is the crate that enables it). `palisade-policy` (the bundle format and the engine) and `palisade-proto` (the event schema, and the anti-rollback, last-known-good and staleness decisions of #304), for the policy cache.

Third-party: `tokio` (the only async runtime, ADR 0009), `tracing` and `tracing-subscriber` (logging), `serde` and `toml` (configuration), `if-addrs` (interface addresses, as in the server), `rustls` and `tokio-rustls` (the TLS client for server communication, with the same `ring` provider as the server; no HTTP client crate), `serde_json` (the agent-server messages), `zeroize` (wiping the sealed identity's plaintext), `arc-swap` (the lock-free swap of the running policy, already in the tree through `palisade-policy`), and, on Windows only, `windows-service` (the safe service control manager API), `windows-registry` (safe registry reads), `windows-version` (the running OS version) and `windows-sys` (the process, token, session and local-group calls, and the policy cache's durable rename, in `ffi`). With `test-util` only: `sha2` (the simulator's placeholder chain).

## Unsafe code

Only in `ffi` (Windows only), the one file listed in [`unsafe-allowlist.txt`](../../unsafe-allowlist.txt) ([ADR 0011](../../docs/adr/0011-msrv-and-unsafe-code-policy.md)). It wraps the process, token, session, account and local-group calls, and `MoveFileExW` for the policy cache, once, each `unsafe` block with a `// SAFETY:` comment, owns every buffer it hands to the OS, closes every handle on drop, and returns raw bytes for variable-length records. The portable `platform::nt` decodes those records without `unsafe` code, checking every pointer inside a record against the record's bounds, and its tests run on every OS.

The library root cannot say `#![forbid(unsafe_code)]`, because `forbid` cannot be relaxed by `ffi`, so it keeps the workspace's `deny`, and every other module, and the binary root, forbids unsafe code itself. The service entry point is written by hand, not with the wrapper crate's macro, which expands to `unsafe`. The registry and OS version are read through safe wrapper crates.

## Platform support

The service host is platform-independent and builds and tests on Linux, other desktop OS and Windows. `--console` and `--simulate` work everywhere. `--service` and the registry, identity, process and file-system context backends are Windows only; elsewhere `--service` exits with an error.

## Feature flags

- `test-util`: the fake agent (`--simulate`) and the `simulate` module, built on `palisade-core`'s platform mocks. For development builds only, never a release build ([docs/workspace.md](../../docs/workspace.md#feature-flags)). Without it, `--simulate` exits with a message saying how to build it.

## Stability

Unstable and not published. Anything may change.

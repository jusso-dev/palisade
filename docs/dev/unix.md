# Developing on Linux and other desktop OS

Most of Palisade does not need Windows. The policy engine, file identity parsers, event schema,
server and CLI build and test on any OS, and so does the agent's service host. This guide covers
working on those from Linux or another desktop OS. For Windows, see [windows.md](windows.md).

## What builds where

The whole workspace builds and tests everywhere: `cargo test --workspace` works on Linux and
other desktop OS. Code that only means something on Windows is behind `#[cfg(windows)]`, so
elsewhere it is left out or replaced by a stub:

| Crate | On Linux and other desktop OS |
|---|---|
| `palisade-core`, `-fileid`, `-policy`, `-proto` | Everything. The file identity crate parses Windows files from bytes; only its optional `os-trust` backend (OS trust and file-system APIs) is Windows only |
| `palisade-server`, `-cli`, `-console` | Everything |
| `palisade-agent` | The service host, configuration, supervisor and `--console` mode; the platform backends that the standard library covers; and the fake agent (`--simulate`). `--service` and the Windows registry backend are Windows only |
| `palisade-tray`, `-driver` | Placeholders that build anywhere |

To check the Windows-only code without Windows:

```sh
rustup target add x86_64-pc-windows-gnu
cargo clippy --workspace --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings
```

That needs a MinGW-w64 C cross-compiler on `PATH` for the build scripts (`gcc-mingw-w64-x86-64`
on Debian and Ubuntu). The dev container has it. CI checks the real MSVC targets on Windows
runners, so this is a quick local check, not a replacement.

## The dev container

[`.devcontainer/`](../../.devcontainer) defines a Linux image with:

- the toolchain pinned in `rust-toolchain.toml`, its components and targets, plus the Windows GNU
  target, the MSRV toolchain and the pinned nightly for fuzzing;
- the tools CI uses, at the versions CI installs: cargo-nextest, cargo-deny, cargo-audit,
  cargo-vet, cargo-hack, cargo-llvm-cov, cargo-insta, cargo-fuzz, zizmor and actionlint (the
  release archive, checked against its SHA-256, as the CI job does);
- the documentation tools: mdBook, mdbook-mermaid-ssr, lychee and typos (not the headless browser
  that mdbook-mermaid-ssr renders diagrams with, so `cargo xtask docs build` names it as missing);
- a Postgres 17 service (the image and digest the CI `postgres` job uses), with
  `PALISADE_TEST_DATABASE_ADMIN_URL` set, so the server's database tests run instead of skipping.

Open the repository in any editor that supports dev containers, or run it with the dev container
CLI. The cargo tools are built from source with `cargo install --locked`, so the first build takes
a while; actionlint is the one prebuilt binary, checked against its published SHA-256. xtask tests check that the image's toolchain and tool versions match
`rust-toolchain.toml` and CI.

`cargo xtask ci` runs every CI check inside the container, and `--fast` skips the slow ones. The
image has every tool it checks for, and an xtask test fails if a CI step needs one the image
lacks. Two exceptions: the Windows-only package and signing steps never run on Linux, and the
`server-image` steps need podman, a container runtime the image does not nest; run those on the
host, or use `--fast`, which skips them. The Postgres step runs because the container sets `PALISADE_TEST_DATABASE_ADMIN_URL`.

**Proven in CI.** The [`devcontainer.yml`](../ci.md#devcontaineryml-weekly-on-tuesday-at-0417-utc-on-demand-and-on-prs-that-change-devcontainer)
workflow builds this image and its Postgres service from scratch on a GitHub-hosted runner and
runs `cargo xtask ci --fast` inside it, weekly and on every PR that changes `.devcontainer/`.
Its first green run is the evidence for #29 that `cargo xtask ci` passes in a clean
environment. To run it yourself, start the workflow from the Actions tab (**Run workflow**), or
do what it does:

```sh
docker compose --file .devcontainer/compose.yaml --project-name palisade-dev up --detach --build --wait
docker compose --file .devcontainer/compose.yaml --project-name palisade-dev exec dev cargo xtask ci --fast
docker compose --file .devcontainer/compose.yaml --project-name palisade-dev down --volumes
```

Behind a TLS-inspecting proxy the image build cannot pull or download anything until the proxy's
CA is trusted by the container engine; never disable TLS verification to get round it.

Optional: building the image with `--build-arg WITH_XWIN=1` adds `cargo-xwin`, which can check the
`x86_64-pc-windows-msvc` target from Linux (`cargo xwin check --target x86_64-pc-windows-msvc`).
On first use it downloads the Windows SDK and C runtime headers, under their own licence terms,
which you have to accept; that is why it is off by default.

The container never turns on the Git hooks. See [Git hooks](#git-hooks).

## Running the server

The server needs a TLS certificate and an agent CA even for local work: it has no plaintext
listener ([its README](../../crates/palisade-server/README.md#tls)). For a throwaway local setup,
make a development CA and a certificate for `localhost` with OpenSSL. These are for your machine
only; never use them anywhere else.

```sh
mkdir -p dev/tls && cd dev
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
  -subj /CN=palisade-dev-ca -keyout tls/ca.key -out tls/agent-ca.crt
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost \
  -keyout tls/server.key -out tls/server.csr
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > tls/ext.cnf
openssl x509 -req -in tls/server.csr -CA tls/agent-ca.crt -CAkey tls/ca.key \
  -CAcreateserial -days 30 -extfile tls/ext.cnf -out tls/server.crt
chmod 600 tls/*.key
cat > server.toml <<'EOF'
[tls]
cert_file = "tls/server.crt"
key_file = "tls/server.key"

[listen.admin]
bind = "127.0.0.1"
port = 8443
public_url = "https://localhost:8443"

[listen.agent]
bind = "127.0.0.1"
port = 8444
public_url = "https://localhost:8444"
client_ca_file = "tls/agent-ca.crt"
EOF
cd ..
cargo run -p palisade-server -- check-config --config dev/server.toml
cargo run -p palisade-server -- serve --config dev/server.toml
```

In another terminal:

```sh
curl --cacert dev/tls/agent-ca.crt https://localhost:8443/healthz   # {"status":"alive"}
curl --cacert dev/tls/agent-ca.crt https://localhost:8443/readyz    # {"status":"ready"}
```

`dev/` is not ignored by Git; keep it outside the repository, or never `git add` it. Keys must not
be committed (`.gitignore` already drops `*.pem` and `*.pfx`).

To run the server with Postgres, add a `[database]` section
([server README](../../crates/palisade-server/README.md#database)). In the dev container the
database is at host `postgres`, port 5432. Outside it, any disposable Postgres 16 or later works;
`docs/ci.md` describes how the tests use one.

The web console is still a skeleton
([#136](https://github.com/jusso-dev/palisade/issues/136)); there is nothing to run yet.

## The fake agent

Server, console and event-pipeline work needs agent events, and the real agent's sources (ETW,
the OS event logs) only exist on Windows. The fake agent produces the same events on any OS:

```sh
cargo run -p palisade-agent --features test-util -- --simulate
cargo run -p palisade-agent --features test-util -- --simulate --scenario my-scenario.toml
```

It replays a scripted scenario on the mock platform (`palisade_core::test_util`) and writes one
canonical event per line to standard output: `agent.started`, an `exec.decision` per process start,
then `agent.stopped`. Every event passes the schema's validation, carries a sequence number and a
chain link, and is the same on every run. The built-in scenario is
[`crates/palisade-agent/scenarios/default.toml`](../../crates/palisade-agent/scenarios/default.toml),
and the [agent README](../../crates/palisade-agent/README.md#the-fake-agent) documents the format.

```sh
cargo run -q -p palisade-agent --features test-util -- --simulate | jq -c '{seq, event_type, outcome}'
```

The fake agent cannot send its events to a server yet: the server has no agent endpoints, and
devices cannot enrol. Both come with server communication
([#62](https://github.com/jusso-dev/palisade/issues/62)), enrolment
([#223](https://github.com/jusso-dev/palisade/issues/223)) and the server's agent endpoints
([#126](https://github.com/jusso-dev/palisade/issues/126)). The simulator will then post the
same events. Until then, pipe its output into whatever you are building.

`--simulate` only exists in builds with the `test-util` feature, which release builds never turn
on ([workspace.md](../workspace.md#feature-flags)). A normal build rejects it.

## Testing against the platform mocks

Agent logic reads the OS only through the traits in `palisade_core::platform`: the clock, files,
signatures, identity, processes, the environment, the registry and the event sink.
`palisade_core::test_util` (feature `test-util`) has an in-memory mock of each, and `MockPlatform`
bundles them:

```rust,ignore
use palisade_core::platform::{Clock, UtcTime};
use palisade_core::test_util::{MockFile, MockPlatform};

let mut p = MockPlatform::new();
p.clock.set_utc(UtcTime(1_764_000_000_000_000));
p.fs.insert(r"C:\Tools\tool.exe", MockFile::new(b"MZ...".to_vec()).owner("S-1-5-32-544"));
p.clock.advance(30 * 60 * 1_000_000); // let 30 minutes pass
```

Add it as a dev-dependency: `palisade-core = { workspace = true, features = ["test-util"] }`.

`palisade_core::test_util::contract` holds the behaviour every implementation must have. The mocks
pass it in `palisade-core`'s tests, and the agent's real implementations pass it in
`crates/palisade-agent/tests/platform.rs`, on every CI runner, Windows included. If you change a
mock, change the contract with it, so mocks and real behaviour cannot drift apart.

## The VM test harness

End-to-end tests on real Windows run in VMs. The harness, and how to drive it from a Linux host,
is [#26](https://github.com/jusso-dev/palisade/issues/26) (milestone M1). It is not built yet; this
section will describe it when it lands.

## Git hooks

Opt-in hooks run the quick checks before each commit: formatting, spelling and the banned-terms
check, and the Conventional Commit format of the message. Nothing turns them on for you:

```sh
git config core.hooksPath .githooks      # on
git config --unset core.hooksPath        # off
```

See [`.githooks/README.md`](../../.githooks/README.md).

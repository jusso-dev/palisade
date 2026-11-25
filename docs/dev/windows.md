# Developing on Windows

The agent, the tray and the driver are Windows programs, and this guide sets up a Windows machine
to build and run them. Most other work does not need Windows; see [unix.md](unix.md).

> **Never enforce a policy on the machine you develop on.** Palisade is application control: a
> wrong policy in enforce mode can stop a machine from running its own tools. Run the agent in
> audit mode on a development machine. Test enforcement, drivers and test signing only in a
> virtual machine with a snapshot to roll back to.

## Tools

1. **The C++ build tools for Windows** (the MSVC toolchain and a Windows SDK). The Rust
   `*-pc-windows-msvc` targets link with them. In the build tools installer, select the C++ build
   tools workload, and add the **ARM64 build tools** component as well as x64, so you can build
   `aarch64-pc-windows-msvc` too. When rustup's installer offers to install the build tools for
   you, it installs only the x64 components; add ARM64 afterwards from the same installer.
2. **Rust**, through [rustup](https://rustup.rs). The first `cargo` command in the repository
   installs the toolchain pinned in `rust-toolchain.toml`, with its components and the
   `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` targets.
3. **Git**, which also provides the Bash the opt-in Git hooks use.
4. **WiX Toolset v4 or later**, only to build the MSI. The packaging work
   ([#22](https://github.com/jusso-dev/palisade/issues/22)) pins the version and its install
   command; `cargo xtask dist --msi` will say what is missing.
5. **The Windows Driver Kit** (optional), only for the kernel driver
   ([#8](https://github.com/jusso-dev/palisade/issues/8),
   [#110](https://github.com/jusso-dev/palisade/issues/110)). Today the driver crate is a
   placeholder that builds anywhere, and `cargo build` leaves it out. Install the Driver Kit that
   matches your SDK version when driver work starts.

Then, from the repository root:

```powershell
cargo build
cargo test --workspace
cargo xtask ci --fast        # the CI checks; see docs/ci.md for the extra tools
```

Build for ARM64 from an x64 machine with `cargo build --target aarch64-pc-windows-msvc`. Tests for
that target only run on an ARM64 machine; CI runs them natively on an ARM64 runner.

## Running the agent without installing it

The agent runs as a console program, in the foreground, without being installed as a service:

```powershell
cargo run -p palisade-agent -- --console --config dev.toml
```

(#29 calls this `palisade-agent run --foreground`; the flag is `--console`, as the
[agent README](../../crates/palisade-agent/README.md#running) describes.) It runs until Ctrl-C and
logs to standard error. A minimal `dev.toml` for a development machine:

```toml
# dev.toml: never enforce on a development machine.
fail_mode = "fail_open"
safe_mode_behaviour = "audit_only"

[log]
level = "debug"
```

The agent reads `%ProgramData%\Palisade\agent.toml` only when `--config` is not given, so an
explicit `--config` keeps your development settings separate from any installed agent.

Run the terminal as a standard user unless the code you are testing needs administrator rights.
Code that reads process tokens or other users' files will need them (#59), and the console
reports what it could not read.

The service mode, `--service`, only works when the service control manager starts the agent. The
installer registers it ([#57](https://github.com/jusso-dev/palisade/issues/57)); until then, test
the service code in a VM.

## Tracing

The agent writes structured logs to standard error in console mode. Raise the level with
`[log] level = "trace"` in the configuration file.

The agent will observe process starts through Event Tracing for Windows (ETW,
[#59](https://github.com/jusso-dev/palisade/issues/59)). To see the events it will consume, record
the kernel process provider yourself, from an elevated terminal:

```powershell
# Start a session for the kernel process provider (keyword 0x10: process start and stop).
logman create trace palisade-dev -p "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}" 0x10 -o "$env:TEMP\palisade-dev.etl" -ets
# ... start some programs ...
logman stop palisade-dev -ets
tracerpt "$env:TEMP\palisade-dev.etl" -o "$env:TEMP\palisade-dev.xml" -of XML
```

Always stop the session when you are done: an ETW session keeps running, and writing, until it is
stopped or the machine restarts. `logman query -ets` lists the sessions that are running.

The OS's own application control logs (code integrity and the legacy rule collections) are read by
the agent in [#58](https://github.com/jusso-dev/palisade/issues/58), which lists their exact channel
names. Event Viewer shows them under the OS application logs.

## Test signing in a VM

Loading a driver you built yourself needs test signing. Turn it on **only in a VM**, never on
your main machine: test signing lets any test-signed driver load, which weakens the machine.

1. Make a VM with Secure Boot off (test signing cannot be turned on while it is on), and take a
   snapshot.
2. In the VM, from an elevated terminal: `bcdedit /set testsigning on`, then restart. The desktop
   shows a "Test Mode" watermark.
3. Sign the driver with a test certificate that only the VM trusts. The driver build
   ([#22](https://github.com/jusso-dev/palisade/issues/22)) and signing
   ([#24](https://github.com/jusso-dev/palisade/issues/24)) work describes this when the driver
   exists.
4. When you are done, `bcdedit /set testsigning off` and restart, or roll back to the snapshot.

The VM test harness ([#26](https://github.com/jusso-dev/palisade/issues/26)) automates VMs for
end-to-end tests.

## If you lock yourself out

Today nothing in Palisade blocks a program: the agent is audit-only (milestone M1), and
enforcement arrives in M2. These rules keep it that way on a development machine as enforcement
lands:

- **Audit mode only on a development machine.** Every policy you deploy there uses mode `audit`
  (or `monitor`), never `enforce` ([#36](https://github.com/jusso-dev/palisade/issues/36)). An
  audit policy reports what it would block and blocks nothing.
- **Enforce only in a VM with a snapshot.** If an enforce test goes wrong, roll back the snapshot.

If a policy does block what you need, the emergency procedure, from least to most drastic:

1. **Stop the agent.** In console mode, press Ctrl-C; nothing it did persists. An installed agent
   is stopped with `sc stop PalisadeAgent` from an elevated terminal. (Stop protection and its
   break-glass unlock come later, in [#222](https://github.com/jusso-dev/palisade/issues/222), and
   offline override codes in [#120](https://github.com/jusso-dev/palisade/issues/120).)
2. **Remove an OS-native policy.** A policy that Palisade compiled for the OS's own code
   integrity enforcement ([#6](https://github.com/jusso-dev/palisade/issues/6)) keeps enforcing
   when the agent is stopped ([ADR 0012](../adr/0012-fail-open-vs-fail-closed-defaults.md)). Remove
   it with the OS's code integrity policy command-line tool, from an elevated terminal: list the
   active policies, remove the one with Palisade's policy ID, and restart. The OS documentation for
   the tool gives the exact options for your build.
3. **If no terminal will start**, restart into the Windows Recovery Environment (hold Shift while
   choosing Restart), open a command prompt, delete the policy file named after the policy ID from
   the code integrity policies folder under `\Windows\System32\CodeIntegrity`, and restart.
4. **Roll back the VM**, if this happened in one.

## Git hooks

Opt-in hooks check formatting, spelling, banned terms and the commit message before each commit.
They run under Git's Bash. Turn them on with `git config core.hooksPath .githooks`; see
[`.githooks/README.md`](../../.githooks/README.md).

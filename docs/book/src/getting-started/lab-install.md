# Lab install

> **Only on machines you own and can throw away.** Palisade is educational software
> ([ADR 0014](../../../adr/0014-educational-scope-statement.md)).

## Build from source

You need [rustup](https://rustup.rs) and Git; the toolchain is pinned in `rust-toolchain.toml`.

```sh
git clone https://github.com/jusso-dev/palisade.git
cd palisade
cargo build --workspace --exclude palisade-driver
cargo test --workspace --exclude palisade-driver
```

The full build instructions, for Windows and other platforms, are in the
[README](../../../../README.md#building).

## The VM lab

> **Planned.** The Windows VM integration test harness is
> [#26](https://github.com/jusso-dev/palisade/issues/26) (milestone M1).

The harness will create a disposable Windows virtual machine from a local hypervisor, install the
agent from the MSI ([#22](https://github.com/jusso-dev/palisade/issues/22)), enrol it with a local
server, run benign test executables and scripts, and reset the VM afterwards. Until it lands
there is no supported way to install the agent: the agent binary runs in the foreground with
`palisade-agent --console` (see the [CLI reference](../reference/generated/cli.md)), but does not
enforce anything yet.

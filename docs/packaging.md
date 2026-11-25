# Packaging

How Palisade's release binaries, Windows Installer packages, symbols and server image are built
(#22). Everything here runs on GitHub-hosted runners or on a developer machine with the same
command: `cargo xtask dist`. Signing and publishing releases is the release pipeline (#24).

## Artefacts

| Artefact | Built on | Contents |
|---|---|---|
| `Palisade-<version>-x64.msi` | `windows-latest` | `palisade-agent.exe`, `palisade-tray.exe`, `pal.exe` for x64 |
| `Palisade-<version>-arm64.msi` | `windows-11-arm` | The same, built natively for ARM64 |
| `Palisade-<version>-<arch>.msi.sha256` | with each package | Its SHA-256, in `sha256sum` format |
| `palisade-<version>-<arch>-symbols.zip` | with each package | The PDBs, in symbol-server layout |
| `palisade-server` | `ubuntu-latest` | The server for `x86_64-unknown-linux-gnu` |
| `palisade-server` OCI image | `ubuntu-latest` | That binary on a minimal base ([Server image](#server-image)) |
| `sizes-<arch>.json` | with each build | The size of every file above, for size tracking |

The ARM64 package is built and tested natively on the ARM64 runner, with an ARM64 notifier, so
it never relies on x64 emulation.

## Building locally

```sh
# On Windows x64 or ARM64: binaries, symbols, and with --msi the package.
cargo xtask dist --msi
# On Linux x64: the server binary.
cargo xtask dist
# Then the image (podman or any OCI builder):
podman build -f packaging/server/Containerfile -t palisade-server:dev target/dist/linux-x64-0.1.0
```

`--target <triple>` picks the target explicitly (`x86_64-pc-windows-msvc`,
`aarch64-pc-windows-msvc` or `x86_64-unknown-linux-gnu`). Windows targets build on Windows and
the server on Linux, each with the platform's own linker. Output goes to
`target/dist/<arch>-<version>/`, or to `--out <dir>`. `--sign <signer>` signs every executable
before it is packaged, then the package, with any `cargo xtask sign` signer (`none` only logs);
see [releasing.md](releasing.md#code-signing). `--from <dir>` packages executables built and
signed elsewhere, after checking they are this version's; the release pipeline uses it. `--bump-patch` builds as the next patch version, which CI uses to test upgrades.
`--compare-sizes <sizes.json>` warns about every binary that grew by more than 10% against an
earlier build's size report. Everything `dist` builds and downloads goes under Cargo's target
directory, wherever `CARGO_TARGET_DIR` or `build.target-dir` puts it.

A Windows build needs the MSVC build tools and, for `--msi`, the .NET runtime. `dist` downloads
the WiX toolset itself (see [WiX](#wix)). Nothing else is installed.

## What `dist` does

For each Windows executable it:

1. writes the version resource and the application manifest straight to a compiled resource
   file (`.res`), with no resource compiler and no build script (`xtask/src/dist/res.rs`);
2. builds it with `cargo rustc --release --locked`, adding the static C runtime
   (`+crt-static`), `--remap-path-prefix` for the workspace and Cargo home, and the linker
   options `/Brepro` (reproducible timestamps), `/PDBALTPATH:%_PDB%` (only the PDB's file name is
   recorded), `/MANIFEST:NO` and the `.res` file;
3. checks the result and fails the build if anything is off: the PE machine type matches the
   target (`0x8664` or `0xAA64`), there is a PDB record holding a file name and no path, a
   reproducible-build marker, no C runtime DLL is imported, and the version resource and manifest are byte for byte the ones
   step 1 wrote;
4. copies the PDB into the symbols archive.

Then, with `--msi`, it builds the package from those executables and validates it.

### Version stamping

| Field | Value |
|---|---|
| `FileVersion` | `MAJOR.MINOR.PATCH.0` from `workspace.package.version` |
| `ProductVersion` | The SemVer and the commit: `0.1.0+g1a2b3c4d5e6f` (`.dirty` for uncommitted changes) |
| `CompanyName` | `Palisade Project` |
| `ProductName` | `Palisade` |
| `OriginalFilename`, `InternalName` | The file name, with and without `.exe` |
| `FileDescription` | Per binary |
| `LegalCopyright` | The dual licence |
| Pre-release flag | Set for `-alpha`, `-beta` and `-rc` versions |

The package's `ProductVersion` is `MAJOR.MINOR.PATCH`: Windows Installer compares only three
numeric parts, and the first two must be at most 255.

### Application manifest

Every executable has the same embedded manifest: `requestedExecutionLevel` `asInvoker`,
`longPathAware`, and `supportedOS` for Windows 10 and 11. The service gets its rights from its
service account, not from elevation, and the notifier and CLI never ask for elevation.

The manifest schema only works with the operating system's fixed XML namespaces, which contain
the OS vendor's name. They, and the autostart registry path, are kept in one file,
`xtask/src/dist/os_ids.rs`, as [NAMING.md](NAMING.md) allows for identifiers the OS requires.

### C runtime

The Windows executables link the C runtime statically, so no VC++ redistributable is needed. The
choice is documented per target in `.cargo/config.toml`. That file may only define aliases
(ADR 0011), so `dist` passes the flags with `--config` for the one target it builds; a plain
`cargo build` is unaffected. The server uses the default dynamic glibc, which its image provides.

### Symbols

The release profile writes split debug info (PDBs). The PDBs are never packaged. They go to
`palisade-<version>-<arch>-symbols.zip` in the symbol-server layout,
`<name>.pdb/<GUID><age>/<name>.pdb`, where `<GUID>` is the 32 hex digits of the CodeView
signature and `<age>` its age in hex, read from each executable. Unzipped into a symbol store
directory, it serves debuggers as is.

### Reproducibility

The linker runs with `/Brepro`, so the COFF timestamp is a hash of the output rather than a
time, and `--remap-path-prefix` keeps local paths out of the binaries and PDBs. The symbols
archive uses one fixed timestamp, `SOURCE_DATE_EPOCH` or the commit time of `HEAD`.

To compare two builds of one commit:

```sh
cargo xtask dist --msi --out a
cargo clean
cargo xtask dist --msi --out b
fc /b a\palisade-0.1.0-x64\pal.exe b\palisade-0.1.0-x64\pal.exe
```

The executables are expected to match; CI does not compare two builds yet. The packages are not: each build gets a new product code
(see below), and the package database records its build time. Exact reproducibility of the
package is a stretch goal.

## Installer package

The package is built from `packaging/wix/` with WiX and uses only standard Windows Installer 5
tables: no WiX extension and no custom action code. The custom actions set properties, and one
runs the operating system's service-control tool, `sc.exe`, to set the service's recovery
actions: the installer's own failure-actions table opens the service without the right a restart
action needs and fails with access denied. It runs deferred, as SYSTEM, right after the service
is installed.

- **Per machine only.** Files go to `%ProgramFiles%\Palisade\`.
- **Upgrades.** One upgrade code per architecture (`xtask/src/dist/msi.rs`) and a new product
  code every build. Installing a newer package replaces the older one in place, inside the same
  transaction, so a failed upgrade rolls back to the old version; installing an older one is
  refused with a message. Packages of the same version replace each other, so
  snapshot builds of `main` can be installed in turn. The service is stopped before files change
  and started again afterwards.
- **Service.** `PalisadeAgent` ("Palisade Agent"), started automatically with a delayed start,
  as LocalSystem, with the command line `palisade-agent.exe --service`. Recovery restarts it
  after 0, 5 and 30 seconds, and the failure count resets after a day. Its service SID type is
  unrestricted. Splitting privileges is evaluated in #18.
- **Data.** `%ProgramData%\Palisade\` with `policy`, `queue` and `logs` below it. Each of the
  four folders gets the same protected DACL and SYSTEM as owner, not only by inheritance: SYSTEM
  and Administrators have full control and nobody else has access, even if a user created one of
  the folders before the install (CI tests that case).
  Hardening is extended in #18. The agent's own files there are not the package's, so upgrades,
  repairs and removal leave them alone.
- **Settings.** The properties below, except the two hidden ones, are written to
  `HKLM\SOFTWARE\Palisade\Agent`, readable by SYSTEM and Administrators only, for the agent's
  enrolment bootstrap (#57). An upgrade or repair keeps their earlier values unless they are given
  again. The earlier values are read in the elevated part of the install only: the user-interface
  part of an interactive install runs unelevated and cannot read the key.
- **Notifier.** `palisade-tray.exe` is started in every user's session at sign-in, from the
  per-machine Run key, unless `NO_TRAY=1`. The conditional parts (this entry, `ADD_TO_PATH` and
  each stored setting) are re-evaluated on a repair or reinstall, so
  `msiexec /i <package> REINSTALL=ALL REINSTALLMODE=amus NO_TRAY=1` removes the entry, and
  `NO_TRAY=0` puts it back.
- **CLI.** `pal.exe` is installed next to the agent. `ADD_TO_PATH=1` adds the folder to the
  system `PATH`.
- **Logging.** Windows Installer records every install, upgrade and removal in the Windows
  Application log (source `MsiInstaller`). `msiexec /l*v <file>` writes a full log.
- **Licence dialog.** An interactive first install shows the educational-project notice and the
  licence; a silent install (`/qn`) shows nothing. The dialogs are written out in
  `packaging/wix/UI.wxs` instead of using a WiX UI extension, whose print button needs a native
  custom action.

### Properties

All are optional. `SERVER_URL` must start with `https://`, and `MODE` must be one of the values
below; otherwise the install, or a repair or reinstall that passes them, is refused before
anything changes. Removal never checks them, so a damaged stored value cannot block it.

| Property | Meaning |
|---|---|
| `SERVER_URL` | HTTPS base URL of the management server |
| `ENROLL_TOKEN` | Enrolment token. Hidden: never written to installer logs or the registry; taken over by enrolment (#57) |
| `GROUP_KEY` | Policy group to join at enrolment |
| `PROXY` | Proxy for agent traffic |
| `MODE` | Initial mode: `audit` (default), `monitor`, `learning`, `enforce` or `disabled` |
| `NO_TRAY` | `1`: do not start the notifier at sign-in |
| `SKIP_ENROLL` | `1`: offline install, no server |
| `ALLOW_UNINSTALL` | Uninstall authorisation, for uninstall protection (#18). Hidden like the token |
| `ADD_TO_PATH` | `1`: add the install folder (and `pal.exe`) to the system `PATH` |

```bat
msiexec /i Palisade-0.1.0-arm64.msi /qn SERVER_URL=https://palisade.example ENROLL_TOKEN=... GROUP_KEY=lab
msiexec /i Palisade-0.1.0-x64.msi /qn SKIP_ENROLL=1 MODE=audit
msiexec /x Palisade-0.1.0-x64.msi /qn
```

`ENROLL_TOKEN` and `ALLOW_UNINSTALL` are hidden properties (`MsiHiddenProperties`), so the
installer does not log their values. The package also never writes either one anywhere: a
verbose log records every registry value and command line the installer writes, hidden property
or not. Taking the token over into the agent's protected store at install (machine-scoped data
protection) is part of enrolment, #57; until then the property is accepted and validated for
logging only, and `SKIP_ENROLL=1` installs are unaffected. CI checks that a random token is in
none of the verbose logs. One exception is outside the package's control: when the machine's
installer logging policy is set to its most verbose debug level, Windows Installer writes
command-line properties to the log regardless.

## Tests in CI

The `package` job in `ci.yml` runs on `windows-latest` and `windows-11-arm`. It builds the
package twice, the second time with `--bump-patch`, and runs `packaging/wix/smoke-test.ps1` on
the runner, which:

- checks the package tables: shared upgrade code, distinct product codes, both hidden
  properties, no PDBs, three files, no custom action code, that the only custom actions set
  properties, stop with an error, or run the `sc.exe` recovery command, that the unelevated
  user-interface sequence never reads the settings key or defaults `MODE`, and that the old
  version is removed inside the install transaction;
- refuses an unknown `MODE` and a plain-HTTP `SERVER_URL`;
- installs silently with every property set, then checks the service (state, start type,
  delayed start, account, command line, recovery actions, SID type), every binary's version
  resource and machine type, that the agent runs natively, the `%ProgramData%\Palisade` and
  settings-key ACLs, the stored settings (and that the token is not among them), the notifier
  entry, and the verbose log for the token;
- upgrades and checks that agent state in `%ProgramData%\Palisade` and the settings survive and
  the service runs the new binaries;
- tries a downgrade and checks it is refused and changes nothing;
- deletes a binary, repairs, and checks it is back;
- uninstalls and checks the service, files, settings and autostart entry are gone;
- plants a data folder with a permissive, non-inheriting ACL, as a standard user could, then
  installs offline with `SKIP_ENROLL`, `NO_TRAY`, `ADD_TO_PATH` and `MODE=enforce` and checks the
  planted folder's ACL was replaced; upgrades it; repairs it with the basic user interface and
  checks the settings and `MODE` are kept; damages the stored `MODE` and checks it can still be
  removed. Windows Installer runs the user-interface sequence only with reduced or full UI, which
  need a person, so that sequence is checked through the package tables above;
- checks the Application log has the install and removal events.

`wix msi validate` runs the standard ICE suite on every package; any ICE error fails the build.
Three warnings are expected and left in place: ICE61, because same-version packages replace each
other on purpose (snapshot builds); WiX's note that the installer's service configuration table
is documented as unreliable, which the smoke test checks directly on every run; and WiX's note
that the property search is suppressed in the user-interface sequence, which is intended (see
Settings above).
`cargo xtask ci` on Windows builds both packages but does not run the smoke test, which installs
a service on the machine.

### Snapshot builds

Every push to `main` whose CI passed publishes its unsigned packages and their checksums to the
rolling `main-snapshot` pre-release. See [ci.md](ci.md#main-snapshot).

## Binary size

Each build writes `sizes-<arch>.json`. `dist --compare-sizes <file>` prints a warning annotation
for every executable or server binary more than 10% larger than in that file. The release
pipeline (#24) compares each release with the previous one.

## Server image

`packaging/server/Containerfile` copies the server binary onto a minimal base image that has
glibc, the C++ runtime and CA certificates and no shell or package manager, pinned by digest.
It runs as an unprivileged user and starts `palisade-server serve --config
/etc/palisade/server.toml`; the configuration and TLS files are mounted in (see
[the server README](../crates/palisade-server/README.md)). The `server-image` job builds it with
the runner's preinstalled podman and runs `palisade-server version` in it. Image signing is #18.

## WiX

WiX 5.0.2 is pinned in `xtask/src/dist/msi.rs`. `dist` downloads the package from the NuGet
registry into `target/wix/`, checks its SHA-256 before anything in it runs, and runs it with the
.NET runtime preinstalled on the hosted Windows images. No WiX installation and no
`dotnet tool install` is needed.

WiX 5 is the last major version under its plain open-source licence (MS-RL). Version 6 and
later require each user to accept an additional maintenance-fee licence agreement before use,
and CI must not accept a licence agreement on the maintainer's behalf. Moving to a later
version is the maintainer's decision.

## Kernel driver

The optional kernel driver (#8) is not implemented yet. When it is, its package will be built
on a developer machine with the Windows Driver Kit, with `cargo xtask dist driver`, and its
files signed with a test certificate. It is **local-only**: the Driver Kit is not part of every
hosted image and installing it exceeds job limits, and no other runner type is ever used
([ci.md](ci.md)). Until then, `cargo xtask dist driver` explains this and fails.

## Not covered here

- Signing binaries and packages, and publishing releases: [releasing.md](releasing.md).
- Testing on clean x64 and ARM64 virtual machines, including the notifier in a real user
  session: the VM harness (#26).
- Image signing, uninstall protection and further ACL hardening: #18.
- Enrolment itself, including storing `ENROLL_TOKEN` protected for the agent, `CONFIGFILE`, tags,
  relays and the other installer properties of the full installer: #57.

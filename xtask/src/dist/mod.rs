//! `cargo xtask dist`: release builds, Windows Installer packages, symbols
//! and the Linux server binary, exactly as CI builds them (#22).
//!
//! ```text
//! cargo xtask dist [--target <triple>] [--msi] [--sign <signer>] [--out <dir>]
//!                  [--bump-patch] [--compare-sizes <sizes.json>] [--from <dir>]
//! cargo xtask dist driver
//! ```
//!
//! The target defaults to the machine's own: Windows x64 or ARM64, or the
//! Linux server. For a Windows target it:
//!
//! 1. writes each executable's resources (version and manifest, [`res`]) to
//!    a `.res` file named after its own hash, so a changed version relinks;
//! 2. builds `palisade-agent`, `palisade-tray` and `pal` with the release
//!    profile, the static CRT ([`windows_rustflags`]), local paths remapped,
//!    `/Brepro` and no linker manifest;
//! 3. checks every executable ([`verify_windows`]): the machine type, the
//!    PDB record, the reproducible-build marker, no CRT DLL imports, and
//!    resources identical to what step 1 wrote;
//! 4. writes the PDBs to `palisade-<version>-<arch>-symbols.zip` in the
//!    symbol-server layout, and `sizes-<arch>.json`;
//! 5. with `--sign`, signs every executable before it is packaged;
//! 6. with `--msi`, builds
//!    `Palisade-<version>-<arch>.msi` with the pinned WiX version and
//!    validates it (ICE), then signs it with the same signer. PDBs are never
//!    packaged. `--from <dir>` packages executables built (and signed)
//!    elsewhere instead, after checking they match this version.
//!
//! For `x86_64-unknown-linux-gnu` it builds `palisade-server`, checks it is
//! an x86-64 ELF executable and writes it with `sizes-linux-x64.json`.

pub mod msi;
pub mod os_ids;
pub mod pe;
pub mod res;
pub mod version;
pub mod zip;

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};
use version::Version;

/// A target `dist` builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    WindowsX64,
    WindowsArm64,
    LinuxX64,
}

impl Target {
    pub const ALL: [Self; 3] = [Self::WindowsX64, Self::WindowsArm64, Self::LinuxX64];

    pub const fn triple(self) -> &'static str {
        match self {
            Self::WindowsX64 => "x86_64-pc-windows-msvc",
            Self::WindowsArm64 => "aarch64-pc-windows-msvc",
            Self::LinuxX64 => "x86_64-unknown-linux-gnu",
        }
    }

    /// The architecture in artefact names.
    pub const fn arch(self) -> &'static str {
        match self {
            Self::WindowsX64 => "x64",
            Self::WindowsArm64 => "arm64",
            Self::LinuxX64 => "linux-x64",
        }
    }

    pub const fn is_windows(self) -> bool {
        !matches!(self, Self::LinuxX64)
    }

    const fn machine(self) -> u16 {
        match self {
            Self::WindowsArm64 => pe::MACHINE_ARM64,
            _ => pe::MACHINE_AMD64,
        }
    }

    /// The target of the machine running this, if `dist` supports it.
    pub const fn host() -> Option<Self> {
        if cfg!(all(windows, target_arch = "x86_64")) {
            Some(Self::WindowsX64)
        } else if cfg!(all(windows, target_arch = "aarch64")) {
            Some(Self::WindowsArm64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Self::LinuxX64)
        } else {
            None
        }
    }

    pub fn parse(triple: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|t| t.triple() == triple)
            .ok_or_else(|| {
                let all: Vec<&str> = Self::ALL.iter().map(|t| t.triple()).collect();
                format!(
                    "unsupported target `{triple}`; use one of: {}",
                    all.join(", ")
                )
            })
    }
}

/// One shipped executable.
#[derive(Debug, Clone, Copy)]
pub struct Binary {
    pub package: &'static str,
    pub bin: &'static str,
    pub description: &'static str,
}

/// The Windows executables, in the order the MSI lists them.
pub const WINDOWS_BINARIES: &[Binary] = &[
    Binary {
        package: "palisade-agent",
        bin: "palisade-agent",
        description: "Palisade endpoint agent service",
    },
    Binary {
        package: "palisade-tray",
        bin: "palisade-tray",
        description: "Palisade user notifier",
    },
    Binary {
        package: "palisade-cli",
        bin: "pal",
        description: "Palisade command-line tool",
    },
];

/// The Linux server binary.
pub const SERVER: Binary = Binary {
    package: "palisade-server",
    bin: "palisade-server",
    description: "Palisade management server",
};

/// DLLs that only a dynamically linked C runtime imports. A static CRT
/// build imports none of them.
/// Matched as prefixes, so `vcruntime140_1.dll`, `msvcp140_atomic_wait.dll`
/// and the debug variants count too.
const CRT_DLLS: &[&str] = &["vcruntime", "msvcp", "ucrtbase", "concrt", "vccorlib"];
const CRT_API_SET_PREFIX: &str = "api-ms-win-crt-";

/// The signer `--sign` selects: any kind `cargo xtask sign` has
/// (`crate::release::sign`).
pub use crate::release::sign::Kind as Signer;

/// Signs `files` in place with `kind`, reading its secrets from the
/// environment. Verification is a separate step (`cargo xtask release
/// verify`), because a test CA must be trusted first.
fn sign_files(
    root: &Path,
    kind: Signer,
    no_timestamp: bool,
    files: &[PathBuf],
) -> Result<(), String> {
    use crate::release::sign;
    let mut config = sign::Config::from_process(kind, root);
    if no_timestamp {
        config.timestamp = sign::Timestamp::Skip;
    }
    let mut runner = sign::ProcessRunner::new(&config);
    let mut signer = sign::signer(&config, &mut runner)?;
    sign::sign_all(signer.as_mut(), files, false).map(|_| ())
}

/// Parsed `cargo xtask dist` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub target: Target,
    pub msi: bool,
    pub sign: Option<Signer>,
    pub out: Option<PathBuf>,
    pub bump_patch: bool,
    pub compare_sizes: Option<PathBuf>,
    /// `--from <dir>`: package these already-built (and signed)
    /// executables instead of building them. The release pipeline builds
    /// and signs in separate jobs, then packages.
    pub from: Option<PathBuf>,
    /// `--no-timestamp`: sign without a timestamp server. For the CI test
    /// of the signing path only; `release.yml` never passes it.
    pub no_timestamp: bool,
}

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Build(Args),
    Driver,
}

pub fn parse_args(args: &[String]) -> Result<Request, String> {
    if let [only] = args {
        if only == "driver" {
            return Ok(Request::Driver);
        }
    }
    let mut target = None;
    let mut msi = false;
    let mut sign = None;
    let mut out = None;
    let mut bump_patch = false;
    let mut compare_sizes = None;
    let mut from = None;
    let mut no_timestamp = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--target" => target = Some(Target::parse(&value("--target")?)?),
            "--msi" => msi = true,
            "--sign" => sign = Some(Signer::parse(&value("--sign")?)?),
            "--out" => out = Some(PathBuf::from(value("--out")?)),
            "--bump-patch" => bump_patch = true,
            "--compare-sizes" => compare_sizes = Some(PathBuf::from(value("--compare-sizes")?)),
            "--from" => from = Some(PathBuf::from(value("--from")?)),
            "--no-timestamp" => no_timestamp = true,
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    let target = match target {
        Some(target) => target,
        None => Target::host().ok_or(
            "this machine has no default target; pass --target (Windows targets build on Windows, the server on Linux)",
        )?,
    };
    if msi && !target.is_windows() {
        return Err("--msi needs a Windows target".to_owned());
    }
    if sign.is_some() && !target.is_windows() {
        return Err("--sign needs a Windows target (Authenticode)".to_owned());
    }
    if from.is_some() && !msi {
        return Err("--from packages prebuilt executables; it needs --msi".to_owned());
    }
    if from.is_some() && bump_patch {
        return Err(
            "--from packages the executables as built; --bump-patch cannot change them".to_owned(),
        );
    }
    Ok(Request::Build(Args {
        target,
        msi,
        sign,
        out,
        bump_patch,
        compare_sizes,
        from,
        no_timestamp,
    }))
}

/// Why `cargo xtask dist driver` does nothing yet.
pub const DRIVER_NOTE: &str = "\
dist driver: the optional kernel driver is not implemented yet (#8). When it is, its package is
built on a developer machine with the Windows Driver Kit, never in CI and never on another
runner type: the kit is not part of every hosted image and installing it exceeds job limits.
See docs/packaging.md#kernel-driver.";

/// The build inputs that are the same for every file.
struct Build<'a> {
    root: &'a Path,
    target: Target,
    version: Version,
    product_version: String,
    source_date_epoch: i64,
    out: PathBuf,
    /// Cargo's target directory, as `cargo metadata` reports it (it honours
    /// `CARGO_TARGET_DIR` and `build.target-dir`). Builds are passed it
    /// explicitly, and every path read back is under it.
    target_dir: PathBuf,
}

/// `true` when this machine can link `target` with its own linker.
pub const fn can_link(target: Target) -> bool {
    match target {
        Target::WindowsX64 | Target::WindowsArm64 => cfg!(windows),
        Target::LinuxX64 => cfg!(all(target_os = "linux", target_arch = "x86_64")),
    }
}

/// Cargo's target directory for the workspace at `root`.
pub fn target_dir(root: &Path) -> Result<PathBuf, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("cannot parse cargo metadata: {e}"))?;
    metadata["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| "cargo metadata has no target_directory".to_owned())
}

/// Runs `cargo xtask dist`. Returns the files written.
pub fn run(root: &Path, args: &Args) -> Result<Vec<PathBuf>, String> {
    // Packaging prebuilt executables links nothing, so any Windows
    // machine can package for either architecture.
    if !(can_link(args.target) || (args.from.is_some() && cfg!(windows))) {
        return Err(format!(
            "{} builds only on {}: it links with the platform's own linker",
            args.target.triple(),
            if args.target.is_windows() {
                "Windows"
            } else {
                "Linux x64"
            }
        ));
    }
    let target_dir = target_dir(root)?;
    let manifest: toml::Table = read(&root.join("Cargo.toml"))?
        .parse()
        .map_err(|e| format!("Cargo.toml: {e}"))?;
    let text = manifest
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or("Cargo.toml: no workspace.package.version")?;
    let mut version = Version::parse(text)?;
    if args.bump_patch {
        version.patch = version
            .patch
            .checked_add(1)
            .ok_or("--bump-patch: the patch number is already at its maximum")?;
        version.pre = None;
    }
    let commit = git_commit(root);
    let build = Build {
        root,
        target: args.target,
        product_version: version.product_string(commit.as_deref()),
        source_date_epoch: source_date_epoch(root),
        out: args.out.clone().unwrap_or_else(|| {
            target_dir
                .join("dist")
                .join(format!("{}-{version}", args.target.arch()))
        }),
        version,
        target_dir,
    };
    std::fs::create_dir_all(&build.out)
        .map_err(|e| format!("cannot create {}: {e}", build.out.display()))?;
    println!(
        "dist: {} {} ({}) into {}",
        build.target.triple(),
        build.version,
        build.product_version,
        build.out.display()
    );
    let mut written = if build.target.is_windows() {
        windows(&build, args)?
    } else {
        linux(&build)?
    };
    let sizes = sizes_json(&build, &written)?;
    let sizes_path = build
        .out
        .join(format!("sizes-{}.json", build.target.arch()));
    write(&sizes_path, sizes.as_bytes())?;
    if let Some(baseline) = &args.compare_sizes {
        compare_sizes(baseline, &sizes)?;
    }
    written.push(sizes_path);
    for path in &written {
        println!("dist: wrote {}", path.display());
    }
    Ok(written)
}

fn windows(build: &Build<'_>, args: &Args) -> Result<Vec<PathBuf>, String> {
    let triple = build.target.triple();
    let res_dir = build.target_dir.join(triple).join("dist-res");
    std::fs::create_dir_all(&res_dir)
        .map_err(|e| format!("cannot create {}: {e}", res_dir.display()))?;
    let bin_dir = build.out.join(format!(
        "palisade-{}-{}",
        build.version,
        build.target.arch()
    ));
    std::fs::create_dir_all(&bin_dir)
        .map_err(|e| format!("cannot create {}: {e}", bin_dir.display()))?;

    if let Some(from) = &args.from {
        return package_prebuilt(build, args, from, &bin_dir);
    }
    let mut exes = Vec::new();
    let mut symbols = Vec::new();
    for binary in WINDOWS_BINARIES {
        let file_name = format!("{}.exe", binary.bin);
        let stamp = res::Stamp {
            file_name: &file_name,
            description: binary.description,
            version: &build.version,
            product_version: &build.product_version,
        };
        let res_bytes = res::res_file(&stamp);
        let res_path = res_dir.join(format!("{}-{}.res", binary.bin, short_hash(&res_bytes)));
        write(&res_path, &res_bytes)?;
        cargo_build(
            build,
            binary,
            &[
                "-C".to_owned(),
                "link-arg=/Brepro".to_owned(),
                "-C".to_owned(),
                "link-arg=/MANIFEST:NO".to_owned(),
                // rustc already passes this; it is repeated so the PDB path
                // recorded in the executable is the file name only, which
                // `verify_windows` checks, whatever rustc's default.
                "-C".to_owned(),
                "link-arg=/PDBALTPATH:%_PDB%".to_owned(),
                "-C".to_owned(),
                format!("link-arg={}", res_path.display()),
            ],
        )?;
        let built = build
            .target_dir
            .join(triple)
            .join("release")
            .join(&file_name);
        let data =
            std::fs::read(&built).map_err(|e| format!("cannot read {}: {e}", built.display()))?;
        let image = verify_windows(&file_name, &data, build.target, &stamp)?;
        let codeview = image
            .codeview
            .ok_or_else(|| format!("{file_name}: no PDB record"))?;
        let pdb = built.with_file_name(codeview.file_name());
        let pdb_data =
            std::fs::read(&pdb).map_err(|e| format!("cannot read {}: {e}", pdb.display()))?;
        symbols.push(zip::Entry {
            name: format!(
                "{name}/{key}/{name}",
                name = codeview.file_name(),
                key = codeview.symbol_key()
            ),
            data: pdb_data,
        });
        let shipped = bin_dir.join(&file_name);
        write(&shipped, &data)?;
        exes.push(shipped);
    }
    // Every executable is signed before it is packaged, so the package
    // never holds an unsigned payload.
    if let Some(signer) = args.sign {
        sign_files(build.root, signer, args.no_timestamp, &exes)?;
    }

    let symbols_path = build.out.join(format!(
        "palisade-{}-{}-symbols.zip",
        build.version,
        build.target.arch()
    ));
    write(
        &symbols_path,
        &zip::write(&symbols, build.source_date_epoch)?,
    )?;

    let mut written = exes;
    written.push(symbols_path);
    if args.msi {
        written.extend(package(build, args, &bin_dir)?);
    }
    Ok(written)
}

/// Builds the package from the executables in `bin_dir`, signs it with
/// the selected signer, and writes its checksum file.
fn package(build: &Build<'_>, args: &Args, bin_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let msi_path = msi::build(
        build.root,
        &msi::Inputs {
            target: build.target,
            version: &build.version,
            bin_dir,
            out_dir: &build.out,
            target_dir: &build.target_dir,
        },
    )?;
    if let Some(signer) = args.sign {
        sign_files(
            build.root,
            signer,
            args.no_timestamp,
            std::slice::from_ref(&msi_path),
        )?;
    }
    let digest =
        hex(&Sha256::digest(std::fs::read(&msi_path).map_err(|e| {
            format!("cannot read {}: {e}", msi_path.display())
        })?));
    let name = file_name(&msi_path);
    let sum_path = msi_path.with_file_name(format!("{name}.sha256"));
    write(&sum_path, format!("{digest}  {name}\n").as_bytes())?;
    Ok(vec![msi_path, sum_path])
}

/// `--from <dir>`: checks the executables in `from` are the ones this
/// version and target produce (machine type, version resource and
/// manifest), copies them, and packages them. The release pipeline uses it
/// to package executables another job built and signed. A signature only
/// changes the certificate table, which the checks do not read.
fn package_prebuilt(
    build: &Build<'_>,
    args: &Args,
    from: &Path,
    bin_dir: &Path,
) -> Result<Vec<PathBuf>, String> {
    let mut written = Vec::new();
    for binary in WINDOWS_BINARIES {
        let file_name = format!("{}.exe", binary.bin);
        let source = from.join(&file_name);
        let data =
            std::fs::read(&source).map_err(|e| format!("cannot read {}: {e}", source.display()))?;
        let stamp = res::Stamp {
            file_name: &file_name,
            description: binary.description,
            version: &build.version,
            product_version: &build.product_version,
        };
        verify_windows(&file_name, &data, build.target, &stamp)?;
        let shipped = bin_dir.join(&file_name);
        write(&shipped, &data)?;
        written.push(shipped);
    }
    written.extend(package(build, args, bin_dir)?);
    Ok(written)
}

fn linux(build: &Build<'_>) -> Result<Vec<PathBuf>, String> {
    cargo_build(build, &SERVER, &[])?;
    let built = build
        .target_dir
        .join(build.target.triple())
        .join("release")
        .join(SERVER.bin);
    let data =
        std::fs::read(&built).map_err(|e| format!("cannot read {}: {e}", built.display()))?;
    verify_elf_x64(&data)?;
    let shipped = build.out.join(SERVER.bin);
    write(&shipped, &data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&shipped, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot mark {} executable: {e}", shipped.display()))?;
    }
    Ok(vec![shipped])
}

/// The `rustflags` every Windows release build gets, besides the remapped
/// paths: the static C runtime, so the VC++ redistributable is not needed.
/// `.cargo/config.toml` documents this per target.
pub const WINDOWS_RUSTFLAGS: &[&str] = &["-C", "target-feature=+crt-static"];

/// The rustflags for `target`: [`WINDOWS_RUSTFLAGS`] on Windows, then the
/// workspace and Cargo home directories remapped, so no local path is left
/// in the binaries or their PDBs.
pub fn windows_rustflags(target: Target, root: &Path, cargo_home: Option<&Path>) -> Vec<String> {
    let mut flags: Vec<String> = if target.is_windows() {
        WINDOWS_RUSTFLAGS.iter().map(|s| (*s).to_owned()).collect()
    } else {
        Vec::new()
    };
    flags.push(format!("--remap-path-prefix={}=palisade", root.display()));
    if let Some(home) = cargo_home {
        flags.push(format!("--remap-path-prefix={}=cargo", home.display()));
    }
    flags
}

/// The `--config` value that sets `rustflags` for one target.
pub fn rustflags_config(target: Target, flags: &[String]) -> String {
    let items: Vec<String> = flags.iter().map(|f| toml_string(f)).collect();
    format!(
        "target.{}.rustflags=[{}]",
        target.triple(),
        items.join(", ")
    )
}

/// A TOML basic string.
pub fn toml_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn cargo_build(build: &Build<'_>, binary: &Binary, link_args: &[String]) -> Result<(), String> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(|h| PathBuf::from(h).join(".cargo"))
        });
    let flags = windows_rustflags(build.target, build.root, cargo_home.as_deref());
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    // Rustflags from the environment would replace the configured ones
    // instead of adding to them, so they are cleared.
    command
        .current_dir(build.root)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env("SOURCE_DATE_EPOCH", build.source_date_epoch.to_string())
        .args(["rustc", "--locked", "--release", "--target"])
        .arg(build.target.triple())
        .arg("--target-dir")
        .arg(&build.target_dir)
        .args(["--package", binary.package, "--bin", binary.bin, "--config"])
        .arg(rustflags_config(build.target, &flags));
    if !link_args.is_empty() {
        command.arg("--").args(link_args);
    }
    println!(
        "dist: building {} for {}",
        binary.bin,
        build.target.triple()
    );
    let status = command
        .status()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("building {} failed", binary.bin))
    }
}

/// Checks one built Windows executable against what this build asked for.
pub fn verify_windows(
    name: &str,
    data: &[u8],
    target: Target,
    stamp: &res::Stamp<'_>,
) -> Result<pe::Image, String> {
    let image = pe::parse(data).map_err(|e| format!("{name}: {e}"))?;
    let mut problems = Vec::new();
    if image.machine != target.machine() {
        problems.push(format!(
            "machine type 0x{:04x}, expected 0x{:04x} for {}",
            image.machine,
            target.machine(),
            target.triple()
        ));
    }
    match &image.codeview {
        None => problems.push("no PDB (CodeView) record".to_owned()),
        Some(cv) if cv.path != cv.file_name() => problems.push(format!(
            "the PDB record holds a build path ({}); only the file name may be recorded",
            cv.path
        )),
        Some(_) => {}
    }
    if !image.reproducible {
        problems
            .push("no reproducible-build (REPRO) debug entry; /Brepro was not applied".to_owned());
    }
    for import in &image.imports {
        if CRT_DLLS.iter().any(|p| import.starts_with(p)) || import.starts_with(CRT_API_SET_PREFIX)
        {
            problems.push(format!(
                "imports {import}: the C runtime must be linked statically"
            ));
        }
    }
    let version = image
        .resource(data, 16, 1)
        .map_err(|e| format!("{name}: {e}"))?;
    if version != Some(res::version_info(stamp).as_slice()) {
        problems.push("the version resource is missing or not the one this build wrote".to_owned());
    }
    let manifest = image
        .resource(data, 24, 1)
        .map_err(|e| format!("{name}: {e}"))?;
    if manifest != Some(res::manifest().as_bytes()) {
        problems
            .push("the application manifest is missing or not the one this build wrote".to_owned());
    }
    if problems.is_empty() {
        Ok(image)
    } else {
        Err(format!("{name}: {}", problems.join("; ")))
    }
}

/// Checks that `data` is a little-endian 64-bit x86-64 ELF executable.
pub fn verify_elf_x64(data: &[u8]) -> Result<(), String> {
    const EM_X86_64: u16 = 62;
    let ok = data.len() > 20
        && data[..4] == *b"\x7fELF"
        && data[4] == 2 // ELFCLASS64
        && data[5] == 1 // little-endian
        && u16::from_le_bytes([data[18], data[19]]) == EM_X86_64;
    if ok {
        Ok(())
    } else {
        Err(format!("{}: not an x86-64 ELF executable", SERVER.bin))
    }
}

/// `sizes-<arch>.json`: the size of every shipped file, to compare between
/// builds.
fn sizes_json(build: &Build<'_>, files: &[PathBuf]) -> Result<String, String> {
    let mut sizes = serde_json::Map::new();
    for path in files {
        let len = std::fs::metadata(path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
            .len();
        sizes.insert(file_name(path), len.into());
    }
    let json = serde_json::json!({
        "target": build.target.triple(),
        "version": build.version.to_string(),
        "sizes": sizes,
    });
    serde_json::to_string_pretty(&json).map_err(|e| format!("cannot write sizes: {e}"))
}

/// The binaries whose size is tracked, without version numbers so they
/// compare across releases.
fn tracked(name: &str) -> Option<&str> {
    let tracked = name.ends_with(".exe") || name == SERVER.bin;
    tracked.then_some(name)
}

/// Warns (a GitHub `::warning` annotation) for every tracked binary that
/// grew by more than 10% against `baseline`. A missing baseline is a note:
/// the first build has nothing to compare with.
pub fn compare_sizes(baseline: &Path, current: &str) -> Result<(), String> {
    let old = match std::fs::read_to_string(baseline) {
        Ok(old) => old,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "dist: no size baseline at {}; nothing to compare",
                baseline.display()
            );
            return Ok(());
        }
        Err(e) => return Err(format!("cannot read {}: {e}", baseline.display())),
    };
    for warning in size_warnings(&old, current)? {
        println!("{warning}");
    }
    Ok(())
}

/// The warnings [`compare_sizes`] prints.
pub fn size_warnings(old: &str, new: &str) -> Result<Vec<String>, String> {
    let parse = |text: &str| -> Result<serde_json::Map<String, serde_json::Value>, String> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("sizes file: {e}"))?;
        value["sizes"]
            .as_object()
            .cloned()
            .ok_or_else(|| "sizes file: no `sizes` object".to_owned())
    };
    let (old, new) = (parse(old)?, parse(new)?);
    let mut warnings = Vec::new();
    for (name, size) in &new {
        let Some(name) = tracked(name) else { continue };
        let (Some(before), Some(after)) = (
            old.get(name).and_then(serde_json::Value::as_u64),
            size.as_u64(),
        ) else {
            continue;
        };
        // after > before * 1.1, in integers.
        if before > 0 && after.saturating_mul(10) > before.saturating_mul(11) {
            let tenths = (after - before).saturating_mul(1000) / before;
            let message = format!(
                "{name} grew {}.{}% ({before} to {after} bytes) since the previous build",
                tenths / 10,
                tenths % 10
            );
            warnings.push(format!(
                "::warning title=Binary size::{}",
                crate::fuzz::escape_data(&message)
            ));
        }
    }
    Ok(warnings)
}

fn git_commit(root: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    let commit = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if !out.status.success() || !version::is_commit(&commit) {
        return None;
    }
    // A failed `git status` counts as dirty: a clean build must prove it.
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(root)
        .output()
        .ok()
        .is_none_or(|o| !o.status.success() || !o.stdout.is_empty());
    Some(if dirty {
        format!("{commit}.dirty")
    } else {
        commit
    })
}

/// `SOURCE_DATE_EPOCH` if set, otherwise the commit time of `HEAD`, so a
/// rebuild of the same commit gets the same timestamps.
fn source_date_epoch(root: &Path) -> i64 {
    if let Some(epoch) = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse().ok())
    {
        return epoch;
    }
    Command::new("git")
        .args(["log", "-1", "--format=%ct", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn short_hash(data: &[u8]) -> String {
    hex(&Sha256::digest(data)[..8])
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn write(path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Request, String> {
        parse_args(&list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_the_command_line() {
        assert_eq!(args(&["driver"]), Ok(Request::Driver));
        assert_eq!(
            args(&[
                "--target",
                "aarch64-pc-windows-msvc",
                "--msi",
                "--sign",
                "none",
                "--out",
                "o"
            ]),
            Ok(Request::Build(Args {
                target: Target::WindowsArm64,
                msi: true,
                sign: Some(Signer::None),
                out: Some(PathBuf::from("o")),
                bump_patch: false,
                compare_sizes: None,
                from: None,
                no_timestamp: false,
            }))
        );
        let Ok(Request::Build(a)) = args(&[
            "--target",
            "aarch64-pc-windows-msvc",
            "--msi",
            "--from",
            "signed",
            "--sign",
            "pfx",
        ]) else {
            panic!()
        };
        assert_eq!(
            (a.from, a.sign),
            (Some(PathBuf::from("signed")), Some(Signer::Pfx))
        );
        let Ok(Request::Build(a)) = args(&[
            "--target",
            "x86_64-unknown-linux-gnu",
            "--bump-patch",
            "--compare-sizes",
            "old.json",
        ]) else {
            panic!()
        };
        assert!(a.bump_patch);
        assert_eq!(a.compare_sizes, Some(PathBuf::from("old.json")));
        match Target::host() {
            Some(host) => {
                let Ok(Request::Build(a)) = args(&[]) else {
                    panic!()
                };
                assert_eq!(a.target, host);
            }
            None => assert!(args(&[]).is_err()),
        }
        for bad in [
            &["--target"][..],
            &["--target", "i686-pc-windows-msvc"],
            &["--target", "x86_64-unknown-linux-gnu", "--msi"],
            &["--target", "x86_64-pc-windows-msvc", "--sign", "hsm"],
            &["--target", "x86_64-pc-windows-msvc", "--from", "x"],
            &[
                "--target",
                "x86_64-pc-windows-msvc",
                "--msi",
                "--from",
                "x",
                "--bump-patch",
            ],
            &["--target", "x86_64-pc-windows-msvc", "--bogus"],
            &["driver", "--msi"],
            &["--target", "x86_64-unknown-linux-gnu", "--msi"],
            &["--target", "x86_64-unknown-linux-gnu", "--sign", "none"],
        ] {
            assert!(args(bad).is_err(), "{bad:?}");
        }
        let error = args(&["--target", "x86_64-pc-windows-msvc", "--sign", "x"]).unwrap_err();
        assert!(error.contains("test-ca"), "{error}");
    }

    #[test]
    fn targets_match_the_pinned_toolchain() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let toolchain: toml::Table = std::fs::read_to_string(root.join("rust-toolchain.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let listed: Vec<&str> = toolchain["toolchain"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        for target in Target::ALL {
            assert!(listed.contains(&target.triple()), "{}", target.triple());
        }
    }

    #[test]
    fn rustflags_are_static_crt_and_remapped_paths() {
        let root = Path::new(r"C:\a\pal isade");
        let flags = windows_rustflags(
            Target::WindowsX64,
            root,
            Some(Path::new(r"C:\Users\r\.cargo")),
        );
        assert_eq!(
            flags,
            [
                "-C",
                "target-feature=+crt-static",
                r"--remap-path-prefix=C:\a\pal isade=palisade",
                r"--remap-path-prefix=C:\Users\r\.cargo=cargo",
            ]
        );
        let config = rustflags_config(Target::WindowsX64, &flags);
        assert!(config.starts_with("target.x86_64-pc-windows-msvc.rustflags=[\"-C\", "));
        // The value is valid TOML and round-trips the paths.
        let parsed: toml::Table = format!("v = {}", config.split_once('=').unwrap().1)
            .parse()
            .unwrap();
        let back: Vec<&str> = parsed["v"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(back, flags);
        let linux = windows_rustflags(Target::LinuxX64, Path::new("/w"), None);
        assert_eq!(linux, ["--remap-path-prefix=/w=palisade"]);
        assert_eq!(toml_string("a\"b\\c\n"), r#""a\"b\\c\u000A""#);
    }

    #[test]
    fn the_cargo_config_documents_the_crt_choice_per_target() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let config = std::fs::read_to_string(root.join(".cargo/config.toml")).unwrap();
        for target in Target::ALL {
            assert!(config.contains(target.triple()), "{}", target.triple());
        }
        assert!(config.contains("+crt-static"));
    }

    #[test]
    fn verify_windows_checks_machine_crt_and_resources() {
        let version = Version::parse("0.1.0").unwrap();
        let stamp = res::Stamp {
            file_name: "pal.exe",
            description: "d",
            version: &version,
            product_version: "0.1.0",
        };
        let good = res::version_info(&stamp);
        let data = pe::tests::sample(pe::MACHINE_ARM64, (16, 1, &good));
        // The sample has a version resource but no manifest, and imports
        // only system DLLs.
        let error = verify_windows("pal.exe", &data, Target::WindowsArm64, &stamp).unwrap_err();
        assert_eq!(
            error,
            "pal.exe: the application manifest is missing or not the one this build wrote"
        );
        let error = verify_windows("pal.exe", &data, Target::WindowsX64, &stamp).unwrap_err();
        assert!(
            error.contains("machine type 0xaa64, expected 0x8664"),
            "{error}"
        );
        let other = res::Stamp {
            product_version: "9.9.9",
            ..stamp.clone()
        };
        let error = verify_windows("pal.exe", &data, Target::WindowsArm64, &other).unwrap_err();
        assert!(error.contains("version resource"), "{error}");

        // A dynamic CRT import, by DLL name (same length as the sample's
        // `KERNEL32.dll`, so the table stays valid).
        let at = data.windows(12).position(|w| w == b"KERNEL32.dll").unwrap();
        let mut crt = data.clone();
        crt[at..at + 12].copy_from_slice(b"UCRTBASE.dll");
        let error = verify_windows("pal.exe", &crt, Target::WindowsArm64, &stamp).unwrap_err();
        assert!(error.contains("imports ucrtbase.dll"), "{error}");

        // A PDB record that holds a build path instead of the file name.
        let at = data.windows(7).position(|w| w == b"a_b.pdb").unwrap();
        let mut path = data.clone();
        path[at..at + 7].copy_from_slice(b"c\\b.pdb");
        let error = verify_windows("pal.exe", &path, Target::WindowsArm64, &stamp).unwrap_err();
        assert!(error.contains("holds a build path (c\\b.pdb)"), "{error}");
    }

    #[test]
    fn each_target_links_only_on_its_own_platform() {
        assert_eq!(can_link(Target::WindowsX64), cfg!(windows));
        assert_eq!(can_link(Target::WindowsArm64), cfg!(windows));
        assert_eq!(
            can_link(Target::LinuxX64),
            cfg!(all(target_os = "linux", target_arch = "x86_64"))
        );
        if let Some(host) = Target::host() {
            assert!(can_link(host));
        }
    }

    #[test]
    fn target_dir_comes_from_cargo() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let dir = target_dir(&root).unwrap();
        assert!(dir.is_absolute(), "{}", dir.display());
    }

    #[test]
    fn elf_check() {
        let mut elf = vec![0_u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18] = 62;
        assert!(verify_elf_x64(&elf).is_ok());
        elf[18] = 183; // aarch64
        assert!(verify_elf_x64(&elf).is_err());
        assert!(verify_elf_x64(b"MZ").is_err());
    }

    #[test]
    fn size_growth_over_ten_percent_warns() {
        let old = r#"{"sizes": {"pal.exe": 1000, "palisade-agent.exe": 1000, "palisade-server": 0, "x.msi": 10}}"#;
        let new = r#"{"sizes": {"pal.exe": 1100, "palisade-agent.exe": 1101, "palisade-server": 5, "x.msi": 99, "new.exe": 1}}"#;
        let warnings = size_warnings(old, new).unwrap();
        assert_eq!(
            warnings,
            [
                "::warning title=Binary size::palisade-agent.exe grew 10.1%25 (1000 to 1101 bytes) since the previous build"
            ]
        );
        assert!(size_warnings("{}", new).is_err());
        assert!(compare_sizes(Path::new("/nonexistent/sizes.json"), new).is_ok());
        assert!(compare_sizes(Path::new(env!("CARGO_MANIFEST_DIR")), new).is_err());
        assert!(size_warnings("nope", new).is_err());
    }
}

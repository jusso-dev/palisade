//! `cargo xtask sign`: the pluggable Authenticode signer (#24).
//!
//! Every signer implements [`Signer`]: `sign(path)` signs one PE or
//! Windows Installer file in place, with a SHA-256 file digest and an
//! RFC 3161 timestamp, and `verify(path)` checks it. The kinds:
//!
//! - `none`: a dry run that logs every file it would sign and verifies
//!   nothing. Used by pull request builds, which never see a secret.
//! - `test-ca`: an ephemeral self-signed code-signing CA and leaf created on
//!   this machine, used once and deleted. For CI tests of the signing path
//!   only; its signatures are trusted only where its root was installed.
//! - `pfx`: a PKCS#12 file and its password, both from the environment
//!   (secrets of the `release-signing` environment).
//! - `cloud-hsm`: a command template the maintainer configures for a remote
//!   signing service, so the key never leaves it.
//!
//! The certificate store work and the calls to the OS signing tool are
//! done by `packaging/sign/sign.ps1` on Windows; this module decides what
//! to run, keeps secrets out of command lines and logs, and is unit-tested
//! with a recording [`Runner`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The signing script, relative to the repository root.
pub const SCRIPT: &str = "packaging/sign/sign.ps1";

/// Environment variables the signers read. Their values are secrets except
/// where noted, and are never put on a command line or printed.
pub mod env {
    /// `pfx`: the PKCS#12 file, base64-encoded.
    pub const PFX_BASE64: &str = "PALISADE_SIGN_PFX_BASE64";
    /// `pfx`: its password.
    pub const PFX_PASSWORD: &str = "PALISADE_SIGN_PFX_PASSWORD";
    /// `cloud-hsm`: the command to sign one file, with `{file}` where the
    /// path goes. Not secret; it reads its own credentials from the
    /// environment.
    pub const HSM_COMMAND: &str = "PALISADE_SIGN_COMMAND";
    /// Space-separated RFC 3161 timestamp server URLs, tried in order. Not
    /// secret.
    pub const TSA_URLS: &str = "PALISADE_TSA_URLS";
}

/// A signer kind, as `--signer` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    None,
    TestCa,
    Pfx,
    CloudHsm,
}

impl Kind {
    pub const ALL: [Self; 4] = [Self::None, Self::TestCa, Self::Pfx, Self::CloudHsm];

    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TestCa => "test-ca",
            Self::Pfx => "pfx",
            Self::CloudHsm => "cloud-hsm",
        }
    }

    pub fn parse(name: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == name)
            .ok_or_else(|| {
                let all: Vec<&str> = Self::ALL.iter().map(|k| k.name()).collect();
                format!("unknown signer `{name}`; use one of: {}", all.join(", "))
            })
    }

    /// The secrets this kind needs from the environment.
    pub const fn required_env(self) -> &'static [&'static str] {
        match self {
            Self::None | Self::TestCa => &[],
            Self::Pfx => &[env::PFX_BASE64, env::PFX_PASSWORD],
            Self::CloudHsm => &[env::HSM_COMMAND],
        }
    }

    /// Whether files signed by this kind are a real release.
    pub const fn is_release_signer(self) -> bool {
        matches!(self, Self::Pfx | Self::CloudHsm)
    }
}

/// One command to run: the program, its arguments, and extra environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

/// Runs commands. The real one spawns processes; tests record them.
pub trait Runner {
    fn run(&mut self, invocation: &Invocation) -> Result<(), String>;
}

/// Spawns each command, waits for it, and prints its output with every
/// secret value replaced by `***`, so a tool that echoes a secret cannot
/// put it in a log.
pub struct ProcessRunner {
    /// The values to scrub.
    pub secrets: Vec<String>,
}

impl ProcessRunner {
    pub fn new(config: &Config) -> Self {
        Self {
            secrets: config.secret_values(),
        }
    }
}

/// `text` with every non-empty secret replaced by `***`.
pub fn scrub(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_owned();
    // Longest first, so a secret that contains another is replaced whole.
    let mut sorted: Vec<&String> = secrets.iter().filter(|s| !s.is_empty()).collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in sorted {
        out = out.replace(secret.as_str(), "***");
    }
    out
}

impl Runner for ProcessRunner {
    fn run(&mut self, invocation: &Invocation) -> Result<(), String> {
        let output = std::process::Command::new(&invocation.program)
            .args(&invocation.args)
            .envs(&invocation.env)
            .output()
            .map_err(|e| format!("cannot run {}: {e}", invocation.program))?;
        print!(
            "{}",
            scrub(&String::from_utf8_lossy(&output.stdout), &self.secrets)
        );
        eprint!(
            "{}",
            scrub(&String::from_utf8_lossy(&output.stderr), &self.secrets)
        );
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("{} failed ({})", invocation.program, output.status))
        }
    }
}

/// What every signer does.
pub trait Signer {
    /// Signs `path` in place.
    fn sign(&mut self, path: &Path) -> Result<(), String>;
    /// Checks `path` has a valid, timestamped signature.
    fn verify(&mut self, path: &Path) -> Result<(), String>;
    /// Whether this signer only logs (`none`), so having nothing to sign is
    /// not an error.
    fn is_dry_run(&self) -> bool {
        false
    }
}

/// Whether signatures get an RFC 3161 timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timestamp {
    /// Required: a release signer needs at least one server in
    /// [`env::TSA_URLS`], and verification fails without a timestamp.
    Required,
    /// Used when [`env::TSA_URLS`] is set (the default for `test-ca`).
    IfConfigured,
    /// Never, for the CI test of the `pfx` path, which has no server.
    /// `release.yml` never passes it (a test checks).
    Skip,
}

/// The values a signer is built from.
pub struct Config {
    pub kind: Kind,
    pub root: PathBuf,
    /// The environment the secrets are read from.
    pub env: BTreeMap<String, String>,
    pub timestamp: Timestamp,
}

impl Config {
    /// Reads the signer's variables from the process environment.
    pub fn from_process(kind: Kind, root: &Path) -> Self {
        let names = [
            env::PFX_BASE64,
            env::PFX_PASSWORD,
            env::HSM_COMMAND,
            env::TSA_URLS,
        ];
        let env = names
            .iter()
            .filter_map(|n| std::env::var(n).ok().map(|v| ((*n).to_owned(), v)))
            .filter(|(_, v)| !v.trim().is_empty())
            .collect();
        let timestamp = if kind.is_release_signer() {
            Timestamp::Required
        } else {
            Timestamp::IfConfigured
        };
        Self {
            kind,
            root: root.to_path_buf(),
            env,
            timestamp,
        }
    }

    /// Every secret value, to scrub from output.
    pub fn secret_values(&self) -> Vec<String> {
        [env::PFX_BASE64, env::PFX_PASSWORD]
            .iter()
            .filter_map(|n| self.env.get(*n).cloned())
            .collect()
    }

    /// The required variables that are not set.
    pub fn missing(&self) -> Vec<&'static str> {
        self.kind
            .required_env()
            .iter()
            .copied()
            .filter(|n| !self.env.contains_key(*n))
            .collect()
    }

    pub fn tsa_urls(&self) -> Vec<String> {
        if self.timestamp == Timestamp::Skip {
            return Vec::new();
        }
        self.env
            .get(env::TSA_URLS)
            .map(|v| v.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    }
}

/// The tools signing with `kind` needs: PowerShell 7 for the signing
/// script (`test-ca` and `pfx`) and for verification, which every signer
/// but `none` runs. `none` only prints what it would do. The `cloud-hsm`
/// command itself is the operator's, checked when it runs.
pub fn tools(kind: Kind, verify_only: bool) -> Vec<crate::tools::Tool> {
    match kind {
        Kind::None if !verify_only => Vec::new(),
        _ => vec![crate::tools::PWSH],
    }
}

/// The signer for `config`, running commands through `runner`.
pub fn signer<'a>(
    config: &'a Config,
    runner: &'a mut dyn Runner,
) -> Result<Box<dyn Signer + 'a>, String> {
    let missing = config.missing();
    if !missing.is_empty() {
        return Err(format!(
            "signer `{}` is not configured: set {} (docs/releasing.md#code-signing)",
            config.kind.name(),
            missing.join(", ")
        ));
    }
    if config.timestamp == Timestamp::Required && config.tsa_urls().is_empty() {
        return Err(format!(
            "signer `{}` needs at least one timestamp server in {} (docs/releasing.md#code-signing)",
            config.kind.name(),
            env::TSA_URLS
        ));
    }
    for url in config.tsa_urls() {
        if !(url.starts_with("http://") || url.starts_with("https://"))
            || url.contains(['"', '\'', ' '])
        {
            return Err(format!("{}: `{url}` is not an http(s) URL", env::TSA_URLS));
        }
    }
    Ok(match config.kind {
        Kind::None => Box::new(DryRun),
        Kind::CloudHsm => Box::new(CloudHsm { config, runner }),
        Kind::TestCa | Kind::Pfx => Box::new(Script { config, runner }),
    })
}

struct DryRun;

impl Signer for DryRun {
    fn is_dry_run(&self) -> bool {
        true
    }
    fn sign(&mut self, path: &Path) -> Result<(), String> {
        println!("sign(none): would sign {}", path.display());
        Ok(())
    }
    fn verify(&mut self, path: &Path) -> Result<(), String> {
        println!("sign(none): would verify {}", path.display());
        Ok(())
    }
}

/// `test-ca` and `pfx`, through the signing script. Secrets reach it in its
/// environment, never as arguments.
struct Script<'a> {
    config: &'a Config,
    runner: &'a mut dyn Runner,
}

impl Script<'_> {
    fn invocation(&self, action: &str, path: &Path) -> Invocation {
        let mut env = BTreeMap::new();
        for name in [env::PFX_BASE64, env::PFX_PASSWORD] {
            if let Some(value) = self.config.env.get(name) {
                env.insert(name.to_owned(), value.clone());
            }
        }
        // The script reads the servers from here; empty means none.
        env.insert(env::TSA_URLS.to_owned(), self.config.tsa_urls().join(" "));
        let mut args = vec![
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-File".to_owned(),
            self.config.root.join(SCRIPT).display().to_string(),
            "-Action".to_owned(),
            action.to_owned(),
            "-Signer".to_owned(),
            self.config.kind.name().to_owned(),
            "-Path".to_owned(),
            path.display().to_string(),
        ];
        if self.config.timestamp == Timestamp::Required {
            args.push("-RequireTimestamp".to_owned());
        }
        Invocation {
            program: "pwsh".to_owned(),
            args,
            env,
        }
    }
}

impl Signer for Script<'_> {
    fn sign(&mut self, path: &Path) -> Result<(), String> {
        let invocation = self.invocation("sign", path);
        self.runner.run(&invocation)
    }
    fn verify(&mut self, path: &Path) -> Result<(), String> {
        let invocation = self.invocation("verify", path);
        self.runner.run(&invocation)
    }
}

/// `cloud-hsm`: the configured command with `{file}` replaced, split on
/// whitespace and run directly, without a shell, so a file name cannot
/// inject anything. Verification uses the OS tool through the script.
struct CloudHsm<'a> {
    config: &'a Config,
    runner: &'a mut dyn Runner,
}

/// The `cloud-hsm` command for one file.
pub fn hsm_invocation(template: &str, path: &Path) -> Result<Invocation, String> {
    if !template.contains("{file}") {
        return Err(format!(
            "{}: the template has no {{file}}",
            env::HSM_COMMAND
        ));
    }
    let mut words = template
        .split_whitespace()
        .map(|w| w.replace("{file}", &path.display().to_string()));
    let program = words
        .next()
        .ok_or_else(|| format!("{} is empty", env::HSM_COMMAND))?;
    Ok(Invocation {
        program,
        args: words.collect(),
        env: BTreeMap::new(),
    })
}

impl Signer for CloudHsm<'_> {
    fn sign(&mut self, path: &Path) -> Result<(), String> {
        let template = self
            .config
            .env
            .get(env::HSM_COMMAND)
            .ok_or_else(|| format!("{} is not set", env::HSM_COMMAND))?;
        let invocation = hsm_invocation(template, path)?;
        self.runner.run(&invocation)
    }
    /// The script only knows the local signers, so verification goes
    /// through [`verify_file`], which does not name one.
    fn verify(&mut self, path: &Path) -> Result<(), String> {
        verify_file(
            &self.config.root,
            self.config.timestamp,
            &mut *self.runner,
            path,
        )
    }
}

/// Verifies one file with the OS tool through the script, whatever signed
/// it: a valid Authenticode signature, every signature checked, and with
/// [`Timestamp::Required`] an RFC 3161 timestamp.
pub fn verify_file(
    root: &Path,
    timestamp: Timestamp,
    runner: &mut dyn Runner,
    path: &Path,
) -> Result<(), String> {
    let config = Config {
        kind: Kind::TestCa,
        root: root.to_path_buf(),
        env: BTreeMap::new(),
        timestamp,
    };
    let script = Script {
        config: &config,
        runner,
    };
    let mut invocation = script.invocation("verify", path);
    // The signer does not matter for verification.
    invocation.args.retain(|a| a != "-Signer" && a != "test-ca");
    script.runner.run(&invocation)
}

/// `true` for the files Authenticode signs here: PE images and Windows
/// Installer packages.
pub fn is_signable(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| ["exe", "dll", "sys", "msi"].contains(&e.to_ascii_lowercase().as_str()))
}

/// Signs every signable file in `files`, then verifies each one. Fails on
/// the first problem. A signer other than `none` must find at least one
/// file.
pub fn sign_all(signer: &mut dyn Signer, files: &[PathBuf], verify: bool) -> Result<usize, String> {
    let targets: Vec<&PathBuf> = files.iter().filter(|f| is_signable(f)).collect();
    if targets.is_empty() && !signer.is_dry_run() {
        return Err(format!(
            "nothing to sign: none of the {} file(s) given is an .exe, .dll, .sys or .msi",
            files.len()
        ));
    }
    for file in &targets {
        signer.sign(file)?;
    }
    if verify {
        for file in &targets {
            signer.verify(file)?;
        }
    }
    Ok(targets.len())
}

/// Parsed `cargo xtask sign` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub kind: Kind,
    pub verify_only: bool,
    /// `--no-timestamp`: [`Timestamp::Skip`], for the CI test only.
    pub no_timestamp: bool,
    pub files: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        calls: Vec<Invocation>,
        fail_on: Option<&'static str>,
    }

    impl Runner for Recorder {
        fn run(&mut self, invocation: &Invocation) -> Result<(), String> {
            self.calls.push(invocation.clone());
            match self.fail_on {
                Some(word) if invocation.args.iter().any(|a| a == word) => {
                    Err(format!("{word} failed"))
                }
                _ => Ok(()),
            }
        }
    }

    fn config(kind: Kind, vars: &[(&str, &str)]) -> Config {
        Config {
            kind,
            root: PathBuf::from("/repo"),
            env: vars
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            timestamp: if kind.is_release_signer() {
                Timestamp::Required
            } else {
                Timestamp::IfConfigured
            },
        }
    }

    const CANARY: &str = "canary-secret-7f3a";

    #[test]
    fn pfx_secrets_go_in_the_environment_never_the_arguments() {
        let cfg = config(
            Kind::Pfx,
            &[
                (env::PFX_BASE64, CANARY),
                (env::PFX_PASSWORD, CANARY),
                (env::TSA_URLS, "http://tsa.invalid/a https://tsa.invalid/b"),
            ],
        );
        let mut rec = Recorder::default();
        {
            let mut s = signer(&cfg, &mut rec).unwrap();
            let files = vec![
                PathBuf::from("a.exe"),
                PathBuf::from("notes.txt"),
                PathBuf::from("b.MSI"),
            ];
            assert_eq!(sign_all(s.as_mut(), &files, true).unwrap(), 2);
        }
        assert_eq!(rec.calls.len(), 4);
        let actions: Vec<&str> = rec.calls.iter().map(|c| c.args[5].as_str()).collect();
        assert_eq!(actions, ["sign", "sign", "verify", "verify"]);
        for call in &rec.calls {
            assert!(
                !call.args.iter().any(|a| a.contains(CANARY)),
                "{:?}",
                call.args
            );
            assert!(!call.program.contains(CANARY));
            assert_eq!(call.env[env::PFX_PASSWORD], CANARY);
            assert_eq!(
                call.args[3],
                Path::new("/repo").join(SCRIPT).display().to_string()
            );
            assert_eq!(call.args[7], "pfx");
            assert_eq!(call.args.last().unwrap(), "-RequireTimestamp");
            assert_eq!(
                call.env[env::TSA_URLS],
                "http://tsa.invalid/a https://tsa.invalid/b"
            );
        }
    }

    #[test]
    fn the_pfx_test_path_can_skip_timestamps() {
        let mut cfg = config(
            Kind::Pfx,
            &[
                (env::PFX_BASE64, "x"),
                (env::PFX_PASSWORD, "y"),
                (env::TSA_URLS, "https://t.invalid"),
            ],
        );
        cfg.timestamp = Timestamp::Skip;
        let mut rec = Recorder::default();
        {
            let mut s = signer(&cfg, &mut rec).unwrap();
            s.sign(Path::new("a.exe")).unwrap();
        }
        assert_eq!(rec.calls[0].env[env::TSA_URLS], "");
        assert!(!rec.calls[0].args.iter().any(|a| a == "-RequireTimestamp"));
    }

    #[test]
    fn output_is_scrubbed_of_secrets() {
        let secrets = vec![
            CANARY.to_owned(),
            "abc".to_owned(),
            format!("{CANARY}-long"),
        ];
        assert_eq!(
            scrub(&format!("x {CANARY}-long y {CANARY} abc"), &secrets),
            "x *** y *** ***"
        );
        assert_eq!(scrub("keep", &[String::new()]), "keep");
        let cfg = config(
            Kind::Pfx,
            &[
                (env::PFX_BASE64, "base64value"),
                (env::PFX_PASSWORD, CANARY),
            ],
        );
        assert_eq!(cfg.secret_values().len(), 2);
    }

    #[test]
    fn verification_does_not_depend_on_the_signer() {
        let mut rec = Recorder::default();
        verify_file(
            Path::new("/repo"),
            Timestamp::Required,
            &mut rec,
            Path::new("a.msi"),
        )
        .unwrap();
        let call = &rec.calls[0];
        assert!(!call.args.iter().any(|a| a == "-Signer"));
        assert_eq!(call.args[5], "verify");
        assert_eq!(call.args.last().unwrap(), "-RequireTimestamp");
    }

    #[test]
    fn release_signers_need_their_secrets_and_a_timestamp_server() {
        let mut rec = Recorder::default();
        let error = signer(&config(Kind::Pfx, &[]), &mut rec).err().unwrap();
        assert!(
            error.contains(env::PFX_BASE64) && error.contains(env::PFX_PASSWORD),
            "{error}"
        );
        let cfg = config(
            Kind::Pfx,
            &[(env::PFX_BASE64, "x"), (env::PFX_PASSWORD, "y")],
        );
        assert!(
            signer(&cfg, &mut rec)
                .err()
                .unwrap()
                .contains(env::TSA_URLS)
        );
        let cfg = config(Kind::CloudHsm, &[]);
        assert!(
            signer(&cfg, &mut rec)
                .err()
                .unwrap()
                .contains(env::HSM_COMMAND)
        );
        let bad_tsa = config(Kind::TestCa, &[(env::TSA_URLS, "ftp://x")]);
        assert!(signer(&bad_tsa, &mut rec).is_err());
        // The test CA and the dry run need nothing.
        assert!(signer(&config(Kind::TestCa, &[]), &mut rec).is_ok());
        assert!(signer(&config(Kind::None, &[]), &mut rec).is_ok());
    }

    #[test]
    fn a_real_signer_with_nothing_to_sign_fails() {
        let cfg = config(Kind::TestCa, &[]);
        let mut rec = Recorder::default();
        {
            let mut s = signer(&cfg, &mut rec).unwrap();
            let error = sign_all(s.as_mut(), &[PathBuf::from("notes.txt")], true).unwrap_err();
            assert!(error.contains("nothing to sign"), "{error}");
            assert!(sign_all(s.as_mut(), &[], true).is_err());
        }
        assert!(rec.calls.is_empty());
        let none = config(Kind::None, &[]);
        let mut rec = Recorder::default();
        let mut s = signer(&none, &mut rec).unwrap();
        assert_eq!(
            sign_all(s.as_mut(), &[PathBuf::from("notes.txt")], true),
            Ok(0)
        );
    }

    #[test]
    fn the_dry_run_runs_nothing() {
        let cfg = config(Kind::None, &[]);
        let mut rec = Recorder::default();
        {
            let mut s = signer(&cfg, &mut rec).unwrap();
            assert_eq!(
                sign_all(s.as_mut(), &[PathBuf::from("a.exe")], true).unwrap(),
                1
            );
        }
        assert!(rec.calls.is_empty());
    }

    #[test]
    fn a_failed_signature_stops_before_verifying() {
        let cfg = config(Kind::TestCa, &[]);
        let mut rec = Recorder {
            fail_on: Some("sign"),
            ..Recorder::default()
        };
        {
            let mut s = signer(&cfg, &mut rec).unwrap();
            let files = [PathBuf::from("a.exe"), PathBuf::from("b.exe")];
            assert!(sign_all(s.as_mut(), &files, true).is_err());
        }
        assert_eq!(rec.calls.len(), 1);
    }

    #[test]
    fn hsm_commands_run_without_a_shell() {
        let path = Path::new("C:/out/a b;rm.exe");
        let inv =
            hsm_invocation("remote-sign --key release --in {file} --out {file}", path).unwrap();
        assert_eq!(inv.program, "remote-sign");
        assert_eq!(
            inv.args,
            [
                "--key",
                "release",
                "--in",
                "C:/out/a b;rm.exe",
                "--out",
                "C:/out/a b;rm.exe"
            ]
        );
        assert!(hsm_invocation("remote-sign --in", path).is_err());
        assert!(hsm_invocation("   ", path).is_err());
        let cfg = config(
            Kind::CloudHsm,
            &[
                (env::HSM_COMMAND, "remote-sign {file}"),
                (env::TSA_URLS, "https://t.invalid"),
            ],
        );
        let mut rec = Recorder::default();
        {
            let mut s = signer(&cfg, &mut rec).unwrap();
            sign_all(s.as_mut(), &[PathBuf::from("x.msi")], true).unwrap();
        }
        assert_eq!(rec.calls[0].program, "remote-sign");
        assert_eq!(rec.calls[1].program, "pwsh");
        assert_eq!(rec.calls[1].args[5], "verify");
        assert!(
            !rec.calls[1]
                .args
                .iter()
                .any(|a| a == "-Signer" || a == "cloud-hsm")
        );
        assert_eq!(rec.calls[1].args.last().unwrap(), "-RequireTimestamp");
    }

    #[test]
    fn signers_require_powershell_except_a_dry_run() {
        let names = |kind, verify| -> Vec<String> {
            tools(kind, verify)
                .iter()
                .map(crate::tools::Tool::name)
                .collect()
        };
        assert!(names(Kind::None, false).is_empty());
        // Verification runs the OS tool through the script, whatever signed.
        assert_eq!(names(Kind::None, true), ["pwsh"]);
        for kind in [Kind::TestCa, Kind::Pfx, Kind::CloudHsm] {
            assert_eq!(names(kind, false), ["pwsh"], "{kind:?}");
            assert_eq!(names(kind, true), ["pwsh"], "{kind:?}");
        }
    }

    #[test]
    fn signer_names_parse() {
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.name()), Ok(kind));
        }
        assert!(Kind::parse("x").is_err());
    }
}

//! The enrolment bootstrap the installer hands to the agent (#57).
//!
//! `msiexec /i … SERVER_URL=… ENROLL_TOKEN=…` must give the agent what it
//! needs to enrol without the token ever reaching an installer log, the
//! registry or a file anyone but SYSTEM and the administrators can read.
//!
//! **The installer side.** The package writes the non-secret settings
//! (`SERVER_URL`, `GROUP_KEY`, `PROXY`, `MODE`, `SKIP_ENROLL`) to
//! `HKLM\SOFTWARE\Palisade\Agent`, which only SYSTEM and Administrators can
//! read. It never writes the token as a registry value or file row: a
//! verbose installer log records every value and file it writes, hidden
//! property or not. Instead, a deferred custom action with a hidden target
//! runs the installed agent, as SYSTEM, with
//! `--stash-enroll-token=<token>` ([`stash_token`]), right after the files
//! are installed and before the service starts.
//!
//! [`stash_token`] checks that only SYSTEM, Administrators and
//! `TrustedInstaller` can write the data folder, then protects the token
//! with machine-scope DPAPI for [`TOKEN_PURPOSE`] and writes it to
//! [`PROTECTED_FILE`] in that folder. If the folder is not protected, or the
//! write fails, the custom action fails and so does the install (ADR 0018):
//! the token is never left somewhere it could be read or replaced.
//!
//! **The handoff file.** Deployment tools that record command lines can
//! instead place the token in [`HANDOFF_FILE`], `%ProgramData%\Palisade\
//! enroll.token`, which inherits the folder's SYSTEM- and
//! Administrators-only ACL. On every start the agent takes it over
//! ([`take_handoff`]):
//!
//! 1. The file's and the folder's security descriptors are checked as
//!    above. A file that fails the check, is too large, is not one line of
//!    printable ASCII, or cannot be read is **deleted and not used**, and
//!    the reason is reported.
//! 2. A token that passes is stored as [`stash_token`] stores it, and only
//!    then is the handoff file deleted. If that fails, the handoff file is
//!    left for the next start.
//!
//! **Enrolment** (#223) reads the protected copy through [`load_token`],
//! and calls [`consume_token`] once the server has accepted it, so the
//! token does not outlive enrolment. [`Bootstrap`] is the interface it
//! consumes: the stored settings, and whether a token is waiting.
//!
//! Only the folder itself is checked, not the folders above it: the
//! standard `%ProgramData%` ACL lets users add entries but not delete or
//! rename one they do not own, so they cannot swap the protected
//! `Palisade` folder for their own.
//!
//! The token's text is never logged, formatted or put in an error:
//! [`EnrollToken`]'s `Debug` prints its length only, and it is wiped from
//! memory when dropped.

#![forbid(unsafe_code)]

use std::{fmt, fs, io, path::Path};

use palisade_core::{
    Mode,
    platform::{FileSystem, Hive, Registry, RegistryValue},
};
use palisade_fileid::fsctx::{
    acl::{AdminSids, Ancestor, EvaluationOptions, ObjectKind, SecurityDescriptor, assess_path},
    sid::well_known,
};
use zeroize::Zeroizing;

use crate::policy_cache::protect::Protector;

/// The installer's settings key under `HKEY_LOCAL_MACHINE`.
pub const SETTINGS_KEY: &str = r"SOFTWARE\Palisade\Agent";
/// The handoff file's name, in the agent's data folder.
pub const HANDOFF_FILE: &str = "enroll.token";
/// The protected copy's name, in the agent's data folder.
pub const PROTECTED_FILE: &str = "enroll.token.dpapi";
/// The DPAPI purpose (entropy) the token is protected for.
pub const TOKEN_PURPOSE: &[u8] = b"palisade-enroll-token-v1";
/// The longest token accepted, in bytes. Registration codes are at most 24
/// characters (#223); this leaves room for other token formats.
pub const MAX_TOKEN_BYTES: usize = 4096;
/// The longest protected copy read: far above what DPAPI makes of a
/// [`MAX_TOKEN_BYTES`] token.
const MAX_PROTECTED_BYTES: u64 = 16 * 1024;

/// An enrolment token. Never printed; wiped when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollToken(Zeroizing<String>);

impl EnrollToken {
    /// Checks and wraps `text`: at most [`MAX_TOKEN_BYTES`] of ASCII
    /// letters, digits and `-._~+/=:`, with surrounding whitespace (and a
    /// trailing line break) removed. Nothing that could end a quoted
    /// argument or start another one is accepted.
    ///
    /// # Errors
    ///
    /// [`HandoffProblem::Malformed`]; the error never contains the text.
    pub fn parse(text: &str) -> Result<Self, HandoffProblem> {
        let trimmed = text.trim();
        if trimmed.is_empty()
            || trimmed.len() > MAX_TOKEN_BYTES
            || !trimmed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=:".contains(&b))
        {
            return Err(HandoffProblem::Malformed);
        }
        Ok(Self(Zeroizing::new(trimmed.to_owned())))
    }

    /// The token, for the enrolment request only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnrollToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnrollToken(<{} bytes>)", self.0.len())
    }
}

/// Why a handoff file was not taken over. None of these carries the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffProblem {
    /// Someone other than SYSTEM, Administrators or `TrustedInstaller`
    /// could write the file or its folder, or a descriptor could not be
    /// read. The file was deleted.
    Unprotected,
    /// The file is too large, empty, or not one token (see
    /// [`EnrollToken::parse`]). The file was deleted.
    Malformed,
    /// The file could not be read. It was deleted if possible.
    Unreadable,
}

impl fmt::Display for HandoffProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unprotected => {
                "the enrolment token handoff file was writable by someone other than \
                 SYSTEM and administrators; it was deleted and not used"
            }
            Self::Malformed => {
                "the enrolment token handoff file was not a single-line token; it was \
                 deleted and not used"
            }
            Self::Unreadable => "the enrolment token handoff file could not be read",
        })
    }
}

/// What [`take_handoff`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Handoff {
    /// There was no handoff file.
    Absent,
    /// The token was protected and stored, and the handoff file deleted.
    Stored,
    /// The handoff file was refused, for this reason.
    Refused(HandoffProblem),
}

/// Protects `token` and stores it in `data_dir` (see the module docs).
///
/// # Errors
///
/// [`io::ErrorKind::PermissionDenied`] if someone other than SYSTEM and
/// administrators could write `data_dir` (nothing is written), or the I/O
/// error if protecting or writing failed. No error contains the token.
pub fn stash_token<F: FileSystem>(
    fs: &F,
    protector: &dyn Protector,
    data_dir: &Path,
    token: &EnrollToken,
) -> io::Result<()> {
    if !protected(fs, None, data_dir) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the data folder can be written by someone other than SYSTEM and administrators",
        ));
    }
    store(protector, data_dir, token)
}

fn store(protector: &dyn Protector, data_dir: &Path, token: &EnrollToken) -> io::Result<()> {
    let blob = protector.protect(token.expose().as_bytes(), TOKEN_PURPOSE)?;
    write_new(&data_dir.join(PROTECTED_FILE), &blob)
}

/// Takes over the handoff file in `data_dir`, if there is one (see the
/// module docs). `fs` reads the security descriptors.
///
/// # Errors
///
/// The I/O error if a valid token could not be protected or stored; the
/// handoff file is then left in place, so the next start tries again.
pub fn take_handoff<F: FileSystem>(
    fs: &F,
    protector: &dyn Protector,
    data_dir: &Path,
) -> io::Result<Handoff> {
    let handoff = data_dir.join(HANDOFF_FILE);
    let bytes = match read_limited(&handoff, MAX_TOKEN_BYTES as u64 + 2) {
        Ok(None) => return Ok(Handoff::Absent),
        Ok(Some(bytes)) => Zeroizing::new(bytes),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return refuse(&handoff, HandoffProblem::Malformed);
        }
        Err(_) => return refuse(&handoff, HandoffProblem::Unreadable),
    };
    if !protected(fs, Some(&handoff), data_dir) {
        return refuse(&handoff, HandoffProblem::Unprotected);
    }
    let token = match std::str::from_utf8(&bytes)
        .map_err(|_| HandoffProblem::Malformed)
        .and_then(EnrollToken::parse)
    {
        Ok(token) => token,
        Err(problem) => return refuse(&handoff, problem),
    };
    store(protector, data_dir, &token)?;
    remove(&handoff)?;
    Ok(Handoff::Stored)
}

/// The stored token, if there is one.
///
/// # Errors
///
/// The I/O error if the copy exists but cannot be read or unprotected
/// (another machine's copy, or one that was changed); enrolment then needs
/// a new token.
pub fn load_token(protector: &dyn Protector, data_dir: &Path) -> io::Result<Option<EnrollToken>> {
    let Some(blob) = read_limited(&data_dir.join(PROTECTED_FILE), MAX_PROTECTED_BYTES)? else {
        return Ok(None);
    };
    let plain = Zeroizing::new(protector.unprotect(&blob, TOKEN_PURPOSE)?);
    let text = std::str::from_utf8(&plain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stored token is not text"))?;
    EnrollToken::parse(text)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stored token is malformed"))
}

/// Deletes the stored token, once enrolment has used it. A token that is
/// already gone is not an error.
///
/// # Errors
///
/// The I/O error if it exists and cannot be deleted.
pub fn consume_token(data_dir: &Path) -> io::Result<()> {
    remove(&data_dir.join(PROTECTED_FILE))
}

/// The install-time settings, as the package stored them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallSettings {
    /// `SERVER_URL`: the management server. Only `https://` URLs are kept.
    pub server_url: Option<String>,
    /// `GROUP_KEY`: the policy group to join at enrolment.
    pub group_key: Option<String>,
    /// `PROXY`: the proxy for agent traffic.
    pub proxy: Option<String>,
    /// `MODE`: the initial mode. `None` if it is missing or not a mode name.
    pub mode: Option<Mode>,
    /// `SKIP_ENROLL=1`: an offline install, which never enrols.
    pub skip_enroll: bool,
}

impl InstallSettings {
    /// Reads the settings key through `registry`. A value that is missing,
    /// of the wrong type, or (for `SERVER_URL` and `MODE`) not a valid
    /// value is `None`, and reported in the returned messages, which never
    /// contain a value.
    ///
    /// # Errors
    ///
    /// The registry error, if the key exists but cannot be read.
    pub fn read(registry: &dyn Registry) -> palisade_core::platform::Result<(Self, Vec<String>)> {
        let mut problems = Vec::new();
        let mut text = |name: &str| -> palisade_core::platform::Result<Option<String>> {
            Ok(
                match registry.value(Hive::LocalMachine, SETTINGS_KEY, name)? {
                    None => None,
                    Some(RegistryValue::String(s)) if !s.is_empty() => Some(s),
                    Some(RegistryValue::String(_)) => None,
                    Some(_) => {
                        problems.push(format!("{name} is not a string; ignored"));
                        None
                    }
                },
            )
        };
        let server_url = text("ServerUrl")?;
        let group_key = text("GroupKey")?;
        let proxy = text("Proxy")?;
        let mode = text("Mode")?;
        let skip_enroll = text("SkipEnroll")?;
        let server_url = server_url.filter(|url| {
            let ok = is_https(url);
            if !ok {
                problems.push("ServerUrl is not an https:// URL; ignored".to_owned());
            }
            ok
        });
        let mode = mode.and_then(|m| {
            let parsed = mode_from_name(&m);
            if parsed.is_none() {
                problems.push("Mode is not a mode name; ignored".to_owned());
            }
            parsed
        });
        Ok((
            Self {
                server_url,
                group_key,
                proxy,
                mode,
                skip_enroll: skip_enroll.as_deref() == Some("1"),
            },
            problems,
        ))
    }
}

/// What enrolment (#223) starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    /// The stored install-time settings.
    pub settings: InstallSettings,
    /// Whether a protected token is waiting ([`load_token`] reads it).
    pub token_waiting: bool,
}

impl Bootstrap {
    /// Reads the settings through `registry` and checks for a stored token
    /// in `data_dir`. Problems with the settings come back as messages.
    ///
    /// # Errors
    ///
    /// The registry error, if the settings key cannot be read.
    pub fn read(
        registry: &dyn Registry,
        data_dir: &Path,
    ) -> palisade_core::platform::Result<(Self, Vec<String>)> {
        let (settings, problems) = InstallSettings::read(registry)?;
        Ok((
            Self {
                settings,
                token_waiting: data_dir.join(PROTECTED_FILE).is_file(),
            },
            problems,
        ))
    }

    /// What enrolment should do.
    #[must_use]
    pub fn next_step(&self) -> NextStep {
        if self.settings.skip_enroll {
            NextStep::Offline
        } else if self.settings.server_url.is_none() {
            NextStep::NeedsServer
        } else if self.token_waiting {
            NextStep::Enrol
        } else {
            NextStep::NeedsToken
        }
    }
}

/// What enrolment should do with a [`Bootstrap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextStep {
    /// `SKIP_ENROLL=1`: run unmanaged.
    Offline,
    /// No server is configured: wait for one (a reinstall or repair with
    /// `SERVER_URL`).
    NeedsServer,
    /// A server is configured but no token is waiting. A device that has
    /// enrolled already needs none; one that has not waits for a handoff.
    NeedsToken,
    /// Enrol with the stored token.
    Enrol,
}

fn is_https(url: &str) -> bool {
    url.get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        && url.len() > 8
}

fn mode_from_name(name: &str) -> Option<Mode> {
    Some(match name {
        "disabled" => Mode::Disabled,
        "monitor" => Mode::Monitor,
        "audit" => Mode::Audit,
        "learning" => Mode::Learning,
        "enforce" => Mode::Enforce,
        _ => return None,
    })
}

/// Whether only SYSTEM, Administrators and `TrustedInstaller` can write
/// `file` (if given) and `dir`. An unreadable descriptor is "no".
fn protected<F: FileSystem>(fs: &F, file: Option<&Path>, dir: &Path) -> bool {
    let descriptor = |p: &Path| {
        fs.security_descriptor(&p.to_string_lossy())
            .ok()
            .flatten()
            .and_then(|bytes| SecurityDescriptor::from_self_relative(&bytes).ok())
    };
    let options = EvaluationOptions {
        admins: AdminSids::from_sids([
            well_known::LOCAL_SYSTEM,
            well_known::ADMINISTRATORS,
            well_known::TRUSTED_INSTALLER,
        ]),
        ..EvaluationOptions::default()
    };
    let Some(folder) = descriptor(dir) else {
        return false;
    };
    let folder = Ancestor {
        path: dir.display().to_string(),
        descriptor: Some(folder),
    };
    let writability = match file {
        Some(file) => {
            let Some(target) = descriptor(file) else {
                return false;
            };
            assess_path(Some(&target), ObjectKind::File, &[folder], &options)
        }
        None => assess_path(
            folder.descriptor.as_ref(),
            ObjectKind::Directory,
            &[],
            &options,
        ),
    };
    !writability.path_user_writable()
}

/// Deletes the refused handoff file and reports why. A file that cannot be
/// deleted is still refused; the error is logged without the token.
fn refuse(path: &Path, problem: HandoffProblem) -> io::Result<Handoff> {
    if let Err(e) = remove(path) {
        tracing::warn!(error = %e, "cannot delete the refused enrolment token handoff file");
    }
    Ok(Handoff::Refused(problem))
}

fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Reads at most `limit` bytes. `Ok(None)` if the file does not exist,
/// [`io::ErrorKind::InvalidData`] if it is longer.
fn read_limited(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    use io::Read as _;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        bytes.iter_mut().for_each(|b| *b = 0);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(Some(bytes))
}

/// Writes `bytes` to `path` through a temporary file in the same folder,
/// which inherits the folder's SYSTEM-only ACL, then renames it over.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use io::Write as _;
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// `palisade-agent --stash-enroll-token=<token>`, run by the installer as
/// SYSTEM: stores the token for enrolment in the agent's data folder.
/// Prints nothing that contains the token.
#[cfg(windows)]
pub fn run_stash(token: &EnrollToken) -> std::process::ExitCode {
    let dir = match crate::config::default_path() {
        Ok(Some(path)) => path.parent().map(Path::to_path_buf),
        _ => None,
    };
    let Some(dir) = dir else {
        eprintln!("palisade-agent: cannot find the data folder (ProgramData)");
        return std::process::ExitCode::FAILURE;
    };
    let protector = crate::policy_cache::protect::Dpapi;
    match stash_token(
        &crate::platform::windows::WindowsFileSystem,
        &protector,
        &dir,
        token,
    ) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("palisade-agent: cannot store the enrolment token: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// At start-up: takes over a handoff file (see the module docs) and logs
/// what happened, never the token. A failure is logged and does not stop
/// the agent; the file is tried again at the next start.
#[cfg(windows)]
pub fn on_start() {
    let Ok(Some(path)) = crate::config::default_path() else {
        return;
    };
    let Some(dir) = path.parent() else {
        return;
    };
    match take_handoff(
        &crate::platform::windows::WindowsFileSystem,
        &crate::policy_cache::protect::Dpapi,
        dir,
    ) {
        Ok(Handoff::Absent) => {}
        Ok(Handoff::Stored) => tracing::info!("enrolment token taken over from the handoff file"),
        Ok(Handoff::Refused(problem)) => tracing::warn!(%problem, "enrolment token refused"),
        Err(e) => tracing::error!(error = %e, "cannot store the enrolment token; will retry"),
    }
}

#[cfg(test)]
mod tests;

//! The fake agent: `palisade-agent --simulate` (#29).
//!
//! It replays a [`Scenario`] on the mock platform from
//! `palisade_core::test_util`, on any OS, and emits canonical events
//! (`palisade_proto::events::Event`): `agent.started`, one `exec.decision`
//! per step, then `agent.stopped`. The events are built only through the
//! platform traits, generically, so the same code builds them from the real
//! platform once the agent has a process tracker (#59).
//!
//! The binary writes the events to standard output as JSON lines, in their
//! canonical form. Delivering them to a server needs the agent endpoints and
//! enrolment, which do not exist yet (#62, #223, #126); until then, the
//! output is what a server or console developer feeds to their code. See
//! `docs/dev/unix.md`.
//!
//! The decisions are scripted by the scenario, not evaluated: policy
//! evaluation in the agent arrives with the policy cache (#61).

#![forbid(unsafe_code)]

pub mod scenario;

use std::io::Write;

use palisade_core::{
    VerificationError,
    platform::{
        AccountName, Architecture, CertificateSummary, Clock, Elevation, Environment, EventSink,
        FileSystem, GroupMembership, IdentityProvider, IntegrityLevel, MonotonicTime, OpenFile,
        OsVersion, Platform, PlatformError, ProcessInfo, ProcessKey, ProcessRecord, SessionKind,
        SignatureResult, SignatureSource, SignatureVerifier, TokenInfo, UtcTime, ancestry,
    },
    test_util::{MockClock, MockFile, MockPlatform},
};
use palisade_proto::events::{
    self, CURRENT, Event, EventMode, EventType, Host, HostId, Outcome, ParentProcess, Process,
    ProcessSummary, Severity, Signer, TenantId, Timestamp, Token, User, Uuid7,
};
pub use scenario::{Scenario, ScenarioError};

/// Something went wrong while simulating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulateError(pub String);

impl std::fmt::Display for SimulateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SimulateError {}

impl From<PlatformError> for SimulateError {
    fn from(e: PlatformError) -> Self {
        Self(e.to_string())
    }
}

impl From<ScenarioError> for SimulateError {
    fn from(e: ScenarioError) -> Self {
        Self(e.0)
    }
}

fn invalid(what: &str, e: impl std::fmt::Display) -> SimulateError {
    SimulateError(format!("{what}: {e}"))
}

/// The device facts every event carries.
#[derive(Debug, Clone)]
struct Identity {
    tenant: TenantId,
    host: Host,
    mode: EventMode,
}

/// Builds events from a [`Platform`], numbering and chaining them.
///
/// The chain value here is a placeholder: the SHA-256 of the previous
/// event's canonical JSON. The keyed chain belongs to #220 and #202.
struct Producer {
    identity: Identity,
    seq: u64,
    prev: Option<events::Sha256Hex>,
    ids: IdSource,
}

/// Deterministic UUIDv7 values: the timestamp and a counter, so a scenario
/// always produces the same event IDs.
struct IdSource(u64);

impl IdSource {
    fn next(&mut self, at: UtcTime) -> Result<Uuid7, SimulateError> {
        self.0 = self.0.wrapping_add(1);
        let millis = u64::try_from(at.0.div_euclid(1000)).unwrap_or(0);
        let mut bytes = [0u8; 16];
        if let (Some(dst), Some(src)) = (bytes.get_mut(..6), millis.to_be_bytes().get(2..)) {
            dst.copy_from_slice(src);
        }
        if let Some(dst) = bytes.get_mut(8..) {
            dst.copy_from_slice(&self.0.to_be_bytes());
        }
        bytes[6] = 0x70;
        bytes[8] = 0x80 | (bytes[8] & 0x3f);
        Uuid7::from_bytes(bytes).ok_or_else(|| SimulateError("cannot build an event ID".into()))
    }
}

fn timestamp(at: UtcTime) -> Result<Timestamp, SimulateError> {
    Timestamp::from_unix_micros(at.0).ok_or_else(|| SimulateError("time out of range".into()))
}

fn name(text: &str) -> Result<events::Name, SimulateError> {
    events::Name::new(text).map_err(|e| invalid(text, e))
}

fn long(text: &str) -> Result<events::LongText, SimulateError> {
    events::LongText::new(text).map_err(|e| invalid("text", e))
}

impl Producer {
    fn event(
        &mut self,
        clock: &dyn Clock,
        event_type: EventType,
        action: &str,
        outcome: Outcome,
        description: &str,
    ) -> Result<Event, SimulateError> {
        let now = clock.now_utc();
        let event = Event {
            schema_version: CURRENT,
            event_id: self.ids.next(now)?,
            event_type,
            category: event_type.category(),
            action: action.parse::<Token>().map_err(|e| invalid(action, e))?,
            outcome,
            severity: event_type.default_severity(),
            mode: Some(self.identity.mode),
            description: events::Description::new(description)
                .map_err(|e| invalid("description", e))?,
            ts: timestamp(now)?,
            ts_agent_monotonic: Some(clock.monotonic().0),
            clock_synced: true,
            clock_skew_ms: None,
            tenant_id: self.identity.tenant,
            host: self.identity.host.clone(),
            user: None,
            policy: None,
            seq: self.seq,
            prev_hash: self.prev,
            labels: events::Labels::default(),
            source: None,
            process: None,
            file: None,
            script: None,
            native: None,
            agent: None,
            network: None,
            device: None,
            registry: None,
            elevation: None,
            approval: None,
            admin: None,
            identity: None,
            audit_policy: None,
            restriction: None,
            probe: None,
            fim: None,
        };
        Ok(event)
    }

    /// Validates, numbers and chains `event`, then emits it.
    fn emit(&mut self, event: Event, sink: &mut dyn EventSink<Event>) -> Result<(), SimulateError> {
        if let Err(errors) = event.validate() {
            return Err(SimulateError(format!(
                "built an invalid event: {}",
                errors
                    .iter()
                    .map(|e| format!("{e:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let json = event
            .to_canonical_json()
            .map_err(|e| invalid("serialise", e))?;
        self.prev = Some(events::Sha256Hex::from_bytes(sha256(json.as_bytes())));
        self.seq = self.seq.saturating_add(1);
        sink.emit(event)?;
        Ok(())
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

/// The SHA-256 and size of the file at `path`, read through the
/// [`FileSystem`] trait.
fn hash_file<F: FileSystem + ?Sized>(fs: &F, path: &str) -> Result<([u8; 32], u64), SimulateError> {
    use sha2::Digest as _;
    let mut file = fs.open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 8192];
    let mut offset = 0u64;
    loop {
        let n = file.read_at(offset, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or_default());
        offset = offset.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok((hasher.finalize().into(), offset))
}

/// The host facts, read through the [`Environment`] trait.
fn host<E: Environment + ?Sized>(env: &E, host_id: HostId) -> Result<Host, SimulateError> {
    let hostname = env.hostname()?;
    let domain = env.domain()?;
    let version: OsVersion = env.os_version()?;
    let arch = match env.architecture() {
        Architecture::X64 => "x86_64",
        Architecture::Arm64 => "aarch64",
        Architecture::X86 => "x86",
        Architecture::Other => "other",
    };
    let fqdn = domain.as_ref().map(|d| format!("{hostname}.{d}"));
    Ok(Host {
        id: host_id,
        name: Some(name(&hostname)?),
        fqdn: fqdn.as_deref().map(name).transpose()?,
        domain: domain.as_deref().map(name).transpose()?,
        os: Some(name("Windows")?),
        os_build: Some(name(&format!("{}.{}", version.build, version.revision))?),
        arch: Some(name(arch)?),
        agent_version: Some(name(env!("CARGO_PKG_VERSION"))?),
        ips: events::BoundedVec::default(),
        groups: events::BoundedVec::default(),
    })
}

/// The user field set, from a token and the account name.
fn user(token: &TokenInfo, account: Option<&AccountName>) -> Result<User, SimulateError> {
    Ok(User {
        sid: Some(
            token
                .user_sid
                .parse()
                .map_err(|e| invalid(&token.user_sid, e))?,
        ),
        name: account.map(|a| name(&a.name)).transpose()?,
        domain: account
            .and_then(|a| a.domain.as_deref())
            .map(name)
            .transpose()?,
        upn: None,
        session_id: Some(token.session_id),
        logon_id: None,
        logon_type: Some(match token.session_kind {
            SessionKind::RemoteDesktop => events::LogonType::RemoteInteractive,
            SessionKind::Services => events::LogonType::Service,
            SessionKind::Console | SessionKind::Unknown => events::LogonType::Interactive,
        }),
        is_admin: Some(
            token
                .groups
                .iter()
                .any(|g| g.sid.eq_ignore_ascii_case(ADMINISTRATORS)),
        ),
        elevated: Some(token.elevated),
    })
}

fn integrity(level: IntegrityLevel) -> events::IntegrityLevel {
    match level {
        IntegrityLevel::Untrusted => events::IntegrityLevel::Untrusted,
        IntegrityLevel::Low => events::IntegrityLevel::Low,
        IntegrityLevel::Medium => events::IntegrityLevel::Medium,
        IntegrityLevel::MediumPlus => events::IntegrityLevel::MediumPlus,
        IntegrityLevel::High => events::IntegrityLevel::High,
        IntegrityLevel::System => events::IntegrityLevel::System,
        IntegrityLevel::Protected => events::IntegrityLevel::Protected,
    }
}

fn elevation(e: Elevation) -> events::TokenElevationType {
    match e {
        Elevation::Default => events::TokenElevationType::Default,
        Elevation::Full => events::TokenElevationType::Full,
        Elevation::Limited => events::TokenElevationType::Limited,
    }
}

/// `pid@creation-micros`: the process key the events carry (#59).
fn process_key(key: ProcessKey) -> Result<events::Name, SimulateError> {
    name(&format!("{}@{}", key.pid, key.created.0))
}

fn signers<S: SignatureVerifier + ?Sized>(
    sigs: &S,
    path: &str,
) -> Result<events::BoundedVec<Signer, { events::MAX_SIGNERS }>, SimulateError> {
    let mut out = Vec::new();
    for sig in sigs.embedded(path)?.into_iter().take(events::MAX_SIGNERS) {
        let leaf = sig.chain.first();
        out.push(Signer {
            publisher: leaf.map(|c| name(&c.subject)).transpose()?,
            issuer: leaf.map(|c| name(&c.issuer)).transpose()?,
            chain_valid: Some(sig.status == VerificationError::Ok),
            verification_error: u8::try_from(sig.status.code()).ok(),
            ..Signer::default()
        });
    }
    events::BoundedVec::new(out).map_err(|e| invalid("signers", e))
}

/// The process field set for `record`, with its parent and grandparent
/// from the PID-reuse-safe ancestry.
fn process<P: Platform>(platform: &P, record: &ProcessRecord) -> Result<Process, SimulateError> {
    let chain = ancestry(platform.processes(), record.key)?;
    let token = platform.identity().token(record.key)?;
    let parent = chain
        .first()
        .map(|p| -> Result<Box<ParentProcess>, SimulateError> {
            Ok(Box::new(ParentProcess {
                pid: Some(p.key.pid),
                process_key: Some(process_key(p.key)?),
                image_path: Some(long(&p.image_path)?),
                ..ParentProcess::default()
            }))
        })
        .transpose()?;
    let grandparent = chain
        .get(1)
        .map(|g| -> Result<ProcessSummary, SimulateError> {
            Ok(ProcessSummary {
                pid: Some(g.key.pid),
                process_key: Some(process_key(g.key)?),
                image_path: Some(long(&g.image_path)?),
            })
        })
        .transpose()?;
    Ok(Process {
        pid: Some(record.key.pid),
        process_key: Some(process_key(record.key)?),
        image_path: Some(long(&record.image_path)?),
        image_path_normalised: Some(long(
            palisade_core::path::normalize(&record.image_path).as_str(),
        )?),
        cmdline: record.command_line.as_deref().map(long).transpose()?,
        signers: signers(platform.signatures(), &record.image_path)?,
        integrity_level: Some(integrity(token.integrity)),
        token_elevation_type: Some(elevation(token.elevation)),
        owner_sid: Some(
            token
                .user_sid
                .parse()
                .map_err(|e| invalid(&token.user_sid, e))?,
        ),
        parent,
        grandparent,
        ..Process::default()
    })
}

/// The `exec.decision` event for the process `key`, read entirely through
/// the platform traits.
fn exec_decision<P: Platform>(
    producer: &mut Producer,
    platform: &P,
    key: ProcessKey,
    outcome: Outcome,
) -> Result<Event, SimulateError> {
    let record = platform.processes().get(key)?;
    let token = platform.identity().token(key)?;
    let account = platform.identity().account_name(&token.user_sid)?;
    let verb = match outcome {
        Outcome::Blocked => "blocked",
        Outcome::Audited => "audited (would have been blocked)",
        _ => "allowed",
    };
    let mut event = producer.event(
        platform.clock(),
        EventType::ExecDecision,
        "execute",
        outcome,
        &format!("Simulated: {} was {verb}.", record.image_path),
    )?;
    if outcome != Outcome::Allowed {
        event.severity =
            Severity::new(event.severity.get().saturating_add(2)).unwrap_or(Severity::MAX);
    }
    event.user = Some(user(&token, account.as_ref())?);
    let process = process(platform, &record)?;
    let (digest, size) = hash_file(platform.file_system(), &record.image_path)?;
    let file = events::File {
        path: process.image_path.clone(),
        path_normalised: process.image_path_normalised.clone(),
        object_type: Some(events::ObjectType::Executable),
        size: Some(size),
        hashes: events::Hashes {
            sha256: Some(events::Sha256Hex::from_bytes(digest)),
            ..events::Hashes::default()
        },
        signers: process.signers.clone(),
        ..events::File::default()
    };
    event.process = Some(process);
    event.file = Some(file);
    Ok(event)
}

/// The contents the simulator gives an image: invented, but distinct per
/// path, so every image has its own hash.
fn image_contents(path: &str) -> Vec<u8> {
    format!("MZ simulated image {path}").into_bytes()
}

/// `BUILTIN\\Administrators`.
const ADMINISTRATORS: &str = "S-1-5-32-544";

/// The token of a process run by `sid`: elevated users hold the
/// Administrators group.
fn token_for(scenario: &Scenario, sid: &str) -> Result<TokenInfo, SimulateError> {
    let spec = scenario
        .users
        .iter()
        .find(|u| u.sid.eq_ignore_ascii_case(sid))
        .ok_or_else(|| SimulateError(format!("user {sid} is not declared")))?;
    let session_kind = match spec.session.as_str() {
        "remote_desktop" => SessionKind::RemoteDesktop,
        "services" => SessionKind::Services,
        _ => SessionKind::Console,
    };
    let system = session_kind == SessionKind::Services;
    Ok(TokenInfo {
        user_sid: spec.sid.clone(),
        groups: if spec.elevated {
            vec![GroupMembership {
                sid: ADMINISTRATORS.to_owned(),
                deny_only: false,
            }]
        } else {
            Vec::new()
        },
        session_id: if system { 0 } else { 1 },
        session_kind,
        integrity: if system {
            IntegrityLevel::System
        } else if spec.elevated {
            IntegrityLevel::High
        } else {
            IntegrityLevel::Medium
        },
        elevation: if spec.elevated {
            Elevation::Full
        } else {
            Elevation::Default
        },
        elevated: spec.elevated,
    })
}

/// Builds the mock platform for `scenario`: the device, the users and the
/// processes already running.
fn setup(scenario: &Scenario) -> Result<(MockPlatform, Identity), SimulateError> {
    let start = UtcTime(scenario.start.unix_micros());
    let mut platform = MockPlatform {
        clock: MockClock::new(start, MonotonicTime(0)),
        ..MockPlatform::default()
    };
    let d = &scenario.device;
    platform.environment.hostname.clone_from(&d.hostname);
    platform.environment.domain.clone_from(&d.domain);
    platform.environment.os_version = parse_version(&d.os_version)?;
    platform.environment.architecture = match d.architecture.as_str() {
        "x64" => Architecture::X64,
        "arm64" => Architecture::Arm64,
        "x86" => Architecture::X86,
        other => return Err(SimulateError(format!("unknown architecture `{other}`"))),
    };
    for u in &scenario.users {
        platform.identity.set_account_name(
            &u.sid,
            AccountName {
                domain: u.domain.clone(),
                name: u.name.clone(),
            },
        );
    }
    // Running processes were created before the agent started, in order.
    let count = i64::try_from(scenario.running.len()).unwrap_or(i64::MAX);
    for (i, p) in scenario.running.iter().enumerate() {
        let i = i64::try_from(i).unwrap_or(i64::MAX);
        let key = ProcessKey {
            pid: p.pid,
            created: start.saturating_add_micros((i - count).saturating_mul(1_000_000)),
        };
        add_process(&mut platform, key, p.parent, &p.image, None);
        platform
            .identity
            .set_token(key, token_for(scenario, &p.user)?);
    }
    let mode = match scenario.mode.as_str() {
        "monitor" => EventMode::Monitor,
        "learning" => EventMode::Learning,
        "enforce" => EventMode::Enforce,
        _ => EventMode::Audit,
    };
    let tenant = TenantId(d.tenant_id.parse().map_err(|e| invalid("tenant_id", e))?);
    let host_id = HostId(d.host_id.parse().map_err(|e| invalid("host_id", e))?);
    let host = host(&platform.environment, host_id)?;
    Ok((platform, Identity { tenant, host, mode }))
}

fn parse_version(text: &str) -> Result<OsVersion, SimulateError> {
    let parts: Vec<u32> = text
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|e| invalid("os_version", e))?;
    match parts.as_slice() {
        [major, minor, build, revision] => Ok(OsVersion {
            major: *major,
            minor: *minor,
            build: *build,
            revision: *revision,
        }),
        _ => Err(SimulateError(format!(
            "os_version `{text}` is not major.minor.build.revision"
        ))),
    }
}

fn add_process(
    platform: &mut MockPlatform,
    key: ProcessKey,
    parent: Option<u32>,
    image: &str,
    command_line: Option<&str>,
) {
    platform.processes.start(ProcessRecord {
        key,
        parent_pid: parent,
        image_path: image.to_owned(),
        command_line: command_line.map(str::to_owned),
    });
    platform
        .fs
        .insert(image, MockFile::new(image_contents(image)));
}

/// Replays `scenario`, emitting every event into `sink`. Returns the number
/// of events emitted.
///
/// # Errors
///
/// A scenario value the event schema rejects (an invalid SID or ID, an
/// over-long name), or a sink that refuses an event.
pub fn run(scenario: &Scenario, sink: &mut dyn EventSink<Event>) -> Result<u64, SimulateError> {
    let (mut platform, identity) = setup(scenario)?;
    let mut producer = Producer {
        identity,
        seq: 0,
        prev: None,
        ids: IdSource(0),
    };
    let started = producer.event(
        platform.clock(),
        EventType::AgentStarted,
        "start",
        Outcome::Info,
        "Simulated agent started.",
    )?;
    producer.emit(started, sink)?;
    for step in &scenario.steps {
        // At least one microsecond passes, so no two processes share a
        // creation time, and a reused process ID always gets a new key.
        platform
            .clock
            .advance(step.after_ms.saturating_mul(1000).max(1));
        for pid in &step.exited {
            platform.processes.exit(*pid);
        }
        let key = ProcessKey {
            pid: step.pid,
            created: platform.clock.now_utc(),
        };
        add_process(
            &mut platform,
            key,
            step.parent,
            &step.image,
            step.command_line.as_deref(),
        );
        platform
            .identity
            .set_token(key, token_for(scenario, &step.user)?);
        // Each step states the image's signature, so a later unsigned step
        // with the same image path does not inherit an earlier signature.
        platform.signatures.set_embedded(&step.image, Vec::new());
        if let Some(publisher) = &step.signer {
            platform.signatures.set_embedded(
                &step.image,
                vec![SignatureResult {
                    source: SignatureSource::Embedded,
                    status: VerificationError::Ok,
                    chain: vec![CertificateSummary {
                        subject: publisher.clone(),
                        issuer: format!("{publisher} Code Signing CA"),
                        sha256: sha256(publisher.as_bytes()),
                    }],
                    signing_time: None,
                }],
            );
        }
        let outcome = scenario::parse_outcome(&step.outcome)
            .ok_or_else(|| SimulateError(format!("unknown outcome `{}`", step.outcome)))?;
        let event = exec_decision(&mut producer, &platform, key, outcome)?;
        producer.emit(event, sink)?;
    }
    platform.clock.advance(1000);
    let stopped = producer.event(
        platform.clock(),
        EventType::AgentStopped,
        "stop",
        Outcome::Info,
        "Simulated agent stopped.",
    )?;
    producer.emit(stopped, sink)?;
    Ok(producer.seq)
}

/// Writes each event as one line of canonical JSON.
pub struct JsonLines<W: Write>(pub W);

impl<W: Write> EventSink<Event> for JsonLines<W> {
    fn emit(&mut self, event: Event) -> palisade_core::platform::Result<()> {
        let json = event.to_canonical_json().map_err(|e| {
            PlatformError::new(palisade_core::platform::ErrorKind::Other, e.to_string())
        })?;
        writeln!(self.0, "{json}").map_err(|e| crate::platform::io_error(&e, "write"))
    }
}

#[cfg(test)]
mod tests;

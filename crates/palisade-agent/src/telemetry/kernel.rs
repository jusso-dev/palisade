//! Decoding the kernel process provider's ETW records (#59).
//!
//! The ETW consumer (`ffi::etw`, Windows only) copies each record's header
//! fields and user data out of the OS buffer and hands them over as a
//! [`RawEvent`]. This module turns the user data into a [`KernelEvent`].
//! It has no `unsafe` code and no OS calls, so it runs, is tested and is
//! fuzzed on every OS.
//!
//! The layouts are the provider's manifest templates, bound by provider
//! GUID ([`KERNEL_PROCESS`]), event ID and event version:
//!
//! | ID | Event | Versions |
//! |---|---|---|
//! | 1 | process start | 0 to 4 |
//! | 2 | process stop | 0 to 2 |
//! | 5 | image load | 0 |
//! | 6 | image unload | 0 |
//!
//! Fail closed (ADR 0018): a record that is short, has an unknown version,
//! a string without its terminator or text that is not valid UTF-16 is an
//! error, never a guessed value. A newer version than this module knows is
//! [`DecodeError::UnknownVersion`]: later versions append fields, but this
//! module does not assume that, so a new OS build is reported, not misread.
//! Trailing bytes after the last known field are also an error.

#![cfg_attr(not(windows), allow(dead_code))]

use std::fmt;

use palisade_core::platform::{Elevation, IntegrityLevel, UtcTime};
use palisade_fileid::fsctx::Sid;

use crate::platform::nt;

/// The kernel process provider's GUID, `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`.
/// Bind by GUID; the provider's name is for display only.
pub const KERNEL_PROCESS: u128 = 0x22fb_2cd6_0e7b_422b_a0c7_2fad_1fd0_e716;

/// The provider's keyword for process start and stop events.
pub const KEYWORD_PROCESS: u64 = 0x10;
/// The provider's keyword for image load and unload events.
pub const KEYWORD_IMAGE: u64 = 0x40;

/// The process start event ID.
pub const EVENT_PROCESS_START: u16 = 1;
/// The process stop event ID.
pub const EVENT_PROCESS_STOP: u16 = 2;
/// The image load event ID.
pub const EVENT_IMAGE_LOAD: u16 = 5;
/// The image unload event ID.
pub const EVENT_IMAGE_UNLOAD: u16 = 6;

/// The longest string field accepted, in UTF-16 code units: the longest
/// path or name the OS writes (`UNICODE_STRING` holds 32,767 units).
pub const MAX_STRING_UNITS: usize = 32_767;

/// The largest user data accepted, in bytes. ETW events are at most
/// 64 KiB.
pub const MAX_USER_DATA: usize = 64 * 1024;

/// One ETW record, as the consumer copied it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawEvent {
    /// The provider GUID, as a `u128` in the text order of the GUID.
    pub provider: u128,
    /// The event ID.
    pub id: u16,
    /// The event version.
    pub version: u8,
    /// The pointer size of the process that logged it: 4 or 8. Kernel
    /// providers log with the kernel's pointer size.
    pub pointer_size: u8,
    /// The process ID in the record header.
    pub header_pid: u32,
    /// The thread ID in the record header.
    pub header_tid: u32,
    /// The header timestamp, as a `FILETIME` (100 ns since 1601).
    pub timestamp: u64,
    /// The user data.
    pub data: Vec<u8>,
}

/// A process start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStart {
    /// The new process's ID.
    pub pid: u32,
    /// The OS's process sequence number (version 3 and later): unique per
    /// boot, so it identifies the process even when the ID is reused.
    pub sequence: Option<u64>,
    /// When the process was created.
    pub created: UtcTime,
    /// The parent process ID the OS recorded. A creator can name any
    /// process it may open as the parent, so this can differ from the
    /// creator ([`RawEvent::header_pid`]).
    pub parent_pid: u32,
    /// The parent's sequence number (version 3 and later).
    pub parent_sequence: Option<u64>,
    /// The session ID.
    pub session_id: u32,
    /// The process flags (version 1 and later).
    pub flags: Option<u32>,
    /// The token elevation type (version 3 and later).
    pub elevation: Option<Elevation>,
    /// Whether the token is elevated (version 3 and later).
    pub elevated: Option<bool>,
    /// The integrity level, from the mandatory label (version 3 and later).
    pub integrity: Option<IntegrityLevel>,
    /// The image path, as an NT device path.
    pub image_name: String,
    /// The image header checksum (version 2 and later).
    pub image_checksum: Option<u32>,
    /// The image header time stamp (version 2 and later).
    pub time_date_stamp: Option<u32>,
    /// The package full name, for packaged processes (version 2 and later).
    pub package_full_name: Option<String>,
    /// The package-relative app ID (version 2 and later).
    pub package_app_id: Option<String>,
    /// The mitigation flags (version 4 and later).
    pub security_mitigations: Option<u32>,
    /// The process ID of the thread that logged the event: the creator.
    pub creator_pid: u32,
}

/// A process stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStop {
    /// The process ID.
    pub pid: u32,
    /// The sequence number (version 2 and later).
    pub sequence: Option<u64>,
    /// When the process was created.
    pub created: UtcTime,
    /// When it exited.
    pub exited: UtcTime,
    /// The exit code.
    pub exit_code: u32,
    /// The image file name, as the kernel records it (ANSI, 15 characters
    /// at most). For display only.
    pub image_name: String,
}

/// An image load or unload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageEvent {
    /// The process the image was mapped into. 0 or 4 for a kernel-mode
    /// image (a driver).
    pub pid: u32,
    /// The base address.
    pub base: u64,
    /// The mapped size.
    pub size: u64,
    /// The image header checksum.
    pub checksum: u32,
    /// The image header time stamp.
    pub time_date_stamp: u32,
    /// The image's preferred base.
    pub default_base: u64,
    /// The image path, as an NT device path.
    pub image_name: String,
    /// When the event was logged.
    pub timestamp: UtcTime,
}

impl ImageEvent {
    /// Whether the image is kernel mode (a driver): mapped into the idle or
    /// system process.
    #[must_use]
    pub const fn is_kernel(&self) -> bool {
        self.pid == 0 || self.pid == 4
    }
}

/// A decoded kernel process event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelEvent {
    /// A process started.
    ProcessStart(ProcessStart),
    /// A process stopped.
    ProcessStop(ProcessStop),
    /// An image was mapped.
    ImageLoad(ImageEvent),
    /// An image was unmapped.
    ImageUnload(ImageEvent),
}

/// Why a record could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Not the kernel process provider.
    WrongProvider,
    /// An event ID this module does not decode.
    UnknownEvent(u16),
    /// A version of a known event that this module does not know.
    UnknownVersion {
        /// The event ID.
        id: u16,
        /// The version.
        version: u8,
    },
    /// A pointer size other than 4 or 8.
    BadPointerSize(u8),
    /// The user data is larger than [`MAX_USER_DATA`].
    TooLarge,
    /// The record is malformed; the field and why.
    Malformed(&'static str, &'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongProvider => f.write_str("not a kernel process provider event"),
            Self::UnknownEvent(id) => write!(f, "unknown kernel process event {id}"),
            Self::UnknownVersion { id, version } => {
                write!(f, "unknown version {version} of kernel process event {id}")
            }
            Self::BadPointerSize(n) => write!(f, "pointer size {n}"),
            Self::TooLarge => write!(f, "user data larger than {MAX_USER_DATA} bytes"),
            Self::Malformed(field, why) => write!(f, "malformed {field}: {why}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A cursor over user data.
struct Reader<'a> {
    bytes: &'a [u8],
    pointer_size: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        if self.bytes.len() < n {
            return Err(DecodeError::Malformed(field, "truncated"));
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, DecodeError> {
        let b = self.take(4, field)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        let b = self.take(8, field)?;
        let mut word = [0_u8; 8];
        word.copy_from_slice(b);
        Ok(u64::from_le_bytes(word))
    }

    fn pointer(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        if self.pointer_size == 4 {
            self.u32(field).map(u64::from)
        } else {
            self.u64(field)
        }
    }

    fn filetime(&mut self, field: &'static str) -> Result<UtcTime, DecodeError> {
        self.u64(field).map(nt::filetime_to_utc)
    }

    /// A NUL-terminated UTF-16 string.
    fn unicode(&mut self, field: &'static str) -> Result<String, DecodeError> {
        let mut units = Vec::new();
        loop {
            let b = self.take(2, field)?;
            let unit = u16::from_le_bytes([b[0], b[1]]);
            if unit == 0 {
                break;
            }
            if units.len() == MAX_STRING_UNITS {
                return Err(DecodeError::Malformed(field, "too long"));
            }
            units.push(unit);
        }
        String::from_utf16(&units).map_err(|_| DecodeError::Malformed(field, "not valid UTF-16"))
    }

    /// A NUL-terminated ANSI string. Only ASCII is accepted: the code page
    /// is not known here, and a guess could misread a name.
    fn ansi(&mut self, field: &'static str) -> Result<String, DecodeError> {
        let end = self
            .bytes
            .iter()
            .position(|&b| b == 0)
            .ok_or(DecodeError::Malformed(field, "no terminator"))?;
        if end > MAX_STRING_UNITS {
            return Err(DecodeError::Malformed(field, "too long"));
        }
        let text = self.take(end, field)?;
        self.take(1, field)?;
        if !text.is_ascii() {
            return Err(DecodeError::Malformed(field, "not ASCII"));
        }
        Ok(text.iter().map(|&b| char::from(b)).collect())
    }

    /// A SID, in its binary form.
    fn sid(&mut self, field: &'static str) -> Result<Sid, DecodeError> {
        let (sid, used) =
            Sid::from_bytes(self.bytes).map_err(|_| DecodeError::Malformed(field, "bad SID"))?;
        self.take(used, field)?;
        Ok(sid)
    }

    fn finish(&self) -> Result<(), DecodeError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Malformed("record", "trailing bytes"))
        }
    }
}

/// `SECURITY_MANDATORY_LABEL_AUTHORITY`.
const MANDATORY_LABEL_AUTHORITY: u64 = 16;

fn integrity_of(sid: &Sid) -> Result<IntegrityLevel, DecodeError> {
    match (sid.authority(), sid.sub_authorities()) {
        (MANDATORY_LABEL_AUTHORITY, [rid]) => Ok(nt::integrity_from_rid(*rid)),
        _ => Err(DecodeError::Malformed(
            "MandatoryLabel",
            "not an integrity SID",
        )),
    }
}

fn elevation_of(value: u32) -> Result<Elevation, DecodeError> {
    nt::elevation_type(value)
        .map_err(|_| DecodeError::Malformed("ProcessTokenElevationType", "unknown value"))
}

fn optional(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

/// Decodes one record.
///
/// # Errors
///
/// [`DecodeError`] for a record of another provider, an unknown event or
/// version, or malformed user data.
pub fn decode(raw: &RawEvent) -> Result<KernelEvent, DecodeError> {
    if raw.provider != KERNEL_PROCESS {
        return Err(DecodeError::WrongProvider);
    }
    if raw.data.len() > MAX_USER_DATA {
        return Err(DecodeError::TooLarge);
    }
    let pointer_size = match raw.pointer_size {
        4 => 4,
        8 => 8,
        other => return Err(DecodeError::BadPointerSize(other)),
    };
    let mut r = Reader {
        bytes: &raw.data,
        pointer_size,
    };
    let unknown = || DecodeError::UnknownVersion {
        id: raw.id,
        version: raw.version,
    };
    let event = match raw.id {
        EVENT_PROCESS_START => {
            if raw.version > 4 {
                return Err(unknown());
            }
            KernelEvent::ProcessStart(process_start(&mut r, raw)?)
        }
        EVENT_PROCESS_STOP => {
            if raw.version > 2 {
                return Err(unknown());
            }
            KernelEvent::ProcessStop(process_stop(&mut r, raw.version)?)
        }
        EVENT_IMAGE_LOAD | EVENT_IMAGE_UNLOAD => {
            if raw.version != 0 {
                return Err(unknown());
            }
            let image = image(&mut r, raw.timestamp)?;
            if raw.id == EVENT_IMAGE_LOAD {
                KernelEvent::ImageLoad(image)
            } else {
                KernelEvent::ImageUnload(image)
            }
        }
        other => return Err(DecodeError::UnknownEvent(other)),
    };
    r.finish()?;
    Ok(event)
}

fn process_start(r: &mut Reader<'_>, raw: &RawEvent) -> Result<ProcessStart, DecodeError> {
    let v = raw.version;
    let pid = r.u32("ProcessID")?;
    let sequence = if v >= 3 {
        Some(r.u64("ProcessSequenceNumber")?)
    } else {
        None
    };
    let created = r.filetime("CreateTime")?;
    let parent_pid = r.u32("ParentProcessID")?;
    let parent_sequence = if v >= 3 {
        Some(r.u64("ParentProcessSequenceNumber")?)
    } else {
        None
    };
    let session_id = r.u32("SessionID")?;
    let flags = if v >= 1 { Some(r.u32("Flags")?) } else { None };
    let (elevation, elevated, integrity) = if v >= 3 {
        let elevation = elevation_of(r.u32("ProcessTokenElevationType")?)?;
        let elevated = match r.u32("ProcessTokenIsElevated")? {
            0 => false,
            1 => true,
            _ => {
                return Err(DecodeError::Malformed(
                    "ProcessTokenIsElevated",
                    "not 0 or 1",
                ));
            }
        };
        let integrity = integrity_of(&r.sid("MandatoryLabel")?)?;
        (Some(elevation), Some(elevated), Some(integrity))
    } else {
        (None, None, None)
    };
    let image_name = r.unicode("ImageName")?;
    let (image_checksum, time_date_stamp, package_full_name, package_app_id) = if v >= 2 {
        (
            Some(r.u32("ImageChecksum")?),
            Some(r.u32("TimeDateStamp")?),
            optional(r.unicode("PackageFullName")?),
            optional(r.unicode("PackageRelativeAppId")?),
        )
    } else {
        (None, None, None, None)
    };
    let security_mitigations = if v >= 4 {
        Some(r.u32("SecurityMitigations")?)
    } else {
        None
    };
    Ok(ProcessStart {
        pid,
        sequence,
        created,
        parent_pid,
        parent_sequence,
        session_id,
        flags,
        elevation,
        elevated,
        integrity,
        image_name,
        image_checksum,
        time_date_stamp,
        package_full_name,
        package_app_id,
        security_mitigations,
        creator_pid: raw.header_pid,
    })
}

fn process_stop(r: &mut Reader<'_>, v: u8) -> Result<ProcessStop, DecodeError> {
    let pid = r.u32("ProcessID")?;
    let sequence = if v >= 2 {
        Some(r.u64("ProcessSequenceNumber")?)
    } else {
        None
    };
    let created = r.filetime("CreateTime")?;
    let exited = r.filetime("ExitTime")?;
    let exit_code = r.u32("ExitCode")?;
    r.u32("TokenElevationType")?;
    r.u32("HandleCount")?;
    r.u64("CommitCharge")?;
    r.u64("CommitPeak")?;
    if v >= 1 {
        r.u64("CPUCycleCount")?;
        for field in [
            "ReadOperationCount",
            "WriteOperationCount",
            "ReadTransferKiloBytes",
            "WriteTransferKiloBytes",
            "HardFaultCount",
        ] {
            r.u32(field)?;
        }
    }
    let image_name = r.ansi("ImageName")?;
    Ok(ProcessStop {
        pid,
        sequence,
        created,
        exited,
        exit_code,
        image_name,
    })
}

fn image(r: &mut Reader<'_>, timestamp: u64) -> Result<ImageEvent, DecodeError> {
    Ok(ImageEvent {
        base: r.pointer("ImageBase")?,
        size: r.pointer("ImageSize")?,
        pid: r.u32("ProcessID")?,
        checksum: r.u32("ImageCheckSum")?,
        time_date_stamp: r.u32("TimeDateStamp")?,
        default_base: r.pointer("DefaultBase")?,
        image_name: r.unicode("ImageName")?,
        timestamp: nt::filetime_to_utc(timestamp),
    })
}

/// Builds records in the provider's layouts, for tests, fuzz seeds and the
/// simulator.
pub mod encode {
    use super::{EVENT_IMAGE_LOAD, EVENT_PROCESS_START, EVENT_PROCESS_STOP, KERNEL_PROCESS};
    use super::{ImageEvent, ProcessStart, ProcessStop, RawEvent};

    /// `FILETIME` of a [`palisade_core::platform::UtcTime`].
    #[must_use]
    pub fn filetime(utc: palisade_core::platform::UtcTime) -> u64 {
        let ft = i128::from(utc.0) * 10 + 116_444_736_000_000_000;
        u64::try_from(ft).unwrap_or(0)
    }

    fn unicode(out: &mut Vec<u8>, text: &str) {
        for unit in text.encode_utf16().chain([0]) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
    }

    fn mandatory_label(out: &mut Vec<u8>, rid: u32) {
        out.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16]);
        out.extend_from_slice(&rid.to_le_bytes());
    }

    const fn integrity_rid(level: palisade_core::platform::IntegrityLevel) -> u32 {
        use palisade_core::platform::IntegrityLevel as L;
        match level {
            L::Untrusted => 0,
            L::Low => 0x1000,
            L::Medium => 0x2000,
            L::MediumPlus => 0x2100,
            L::High => 0x3000,
            L::System => 0x4000,
            L::Protected => 0x5000,
        }
    }

    const fn elevation_code(e: palisade_core::platform::Elevation) -> u32 {
        use palisade_core::platform::Elevation as E;
        match e {
            E::Default => 1,
            E::Full => 2,
            E::Limited => 3,
        }
    }

    /// A process start record of `version` (0 to 4). Fields the version
    /// does not carry are left out; fields it carries but `start` leaves
    /// `None` are written as zero or empty.
    #[must_use]
    pub fn process_start(start: &ProcessStart, version: u8, timestamp: u64) -> RawEvent {
        let mut d = Vec::new();
        d.extend_from_slice(&start.pid.to_le_bytes());
        if version >= 3 {
            d.extend_from_slice(&start.sequence.unwrap_or(0).to_le_bytes());
        }
        d.extend_from_slice(&filetime(start.created).to_le_bytes());
        d.extend_from_slice(&start.parent_pid.to_le_bytes());
        if version >= 3 {
            d.extend_from_slice(&start.parent_sequence.unwrap_or(0).to_le_bytes());
        }
        d.extend_from_slice(&start.session_id.to_le_bytes());
        if version >= 1 {
            d.extend_from_slice(&start.flags.unwrap_or(0).to_le_bytes());
        }
        if version >= 3 {
            let e = start
                .elevation
                .unwrap_or(palisade_core::platform::Elevation::Default);
            d.extend_from_slice(&elevation_code(e).to_le_bytes());
            d.extend_from_slice(&u32::from(start.elevated.unwrap_or(false)).to_le_bytes());
            let level = start
                .integrity
                .unwrap_or(palisade_core::platform::IntegrityLevel::Medium);
            mandatory_label(&mut d, integrity_rid(level));
        }
        unicode(&mut d, &start.image_name);
        if version >= 2 {
            d.extend_from_slice(&start.image_checksum.unwrap_or(0).to_le_bytes());
            d.extend_from_slice(&start.time_date_stamp.unwrap_or(0).to_le_bytes());
            unicode(&mut d, start.package_full_name.as_deref().unwrap_or(""));
            unicode(&mut d, start.package_app_id.as_deref().unwrap_or(""));
        }
        if version >= 4 {
            d.extend_from_slice(&start.security_mitigations.unwrap_or(0).to_le_bytes());
        }
        RawEvent {
            provider: KERNEL_PROCESS,
            id: EVENT_PROCESS_START,
            version,
            pointer_size: 8,
            header_pid: start.creator_pid,
            header_tid: 1,
            timestamp,
            data: d,
        }
    }

    /// A process stop record of `version` (0 to 2).
    #[must_use]
    pub fn process_stop(stop: &ProcessStop, version: u8, timestamp: u64) -> RawEvent {
        let mut d = Vec::new();
        d.extend_from_slice(&stop.pid.to_le_bytes());
        if version >= 2 {
            d.extend_from_slice(&stop.sequence.unwrap_or(0).to_le_bytes());
        }
        d.extend_from_slice(&filetime(stop.created).to_le_bytes());
        d.extend_from_slice(&filetime(stop.exited).to_le_bytes());
        d.extend_from_slice(&stop.exit_code.to_le_bytes());
        d.extend_from_slice(&[0; 4 + 4 + 8 + 8]);
        if version >= 1 {
            d.extend_from_slice(&[0; 8 + 5 * 4]);
        }
        d.extend_from_slice(stop.image_name.as_bytes());
        d.push(0);
        RawEvent {
            provider: KERNEL_PROCESS,
            id: EVENT_PROCESS_STOP,
            version,
            pointer_size: 8,
            header_pid: stop.pid,
            header_tid: 1,
            timestamp,
            data: d,
        }
    }

    /// An image load record with pointers of `pointer_size` bytes (4 or 8).
    #[must_use]
    pub fn image_load(image: &ImageEvent, pointer_size: u8) -> RawEvent {
        let mut d = Vec::new();
        let pointer = |d: &mut Vec<u8>, v: u64| {
            if pointer_size == 4 {
                d.extend_from_slice(&u32::try_from(v).unwrap_or(0).to_le_bytes());
            } else {
                d.extend_from_slice(&v.to_le_bytes());
            }
        };
        pointer(&mut d, image.base);
        pointer(&mut d, image.size);
        d.extend_from_slice(&image.pid.to_le_bytes());
        d.extend_from_slice(&image.checksum.to_le_bytes());
        d.extend_from_slice(&image.time_date_stamp.to_le_bytes());
        pointer(&mut d, image.default_base);
        unicode(&mut d, &image.image_name);
        RawEvent {
            provider: KERNEL_PROCESS,
            id: EVENT_IMAGE_LOAD,
            version: 0,
            pointer_size,
            header_pid: image.pid,
            header_tid: 1,
            timestamp: filetime(image.timestamp),
            data: d,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> ProcessStart {
        ProcessStart {
            pid: 4242,
            sequence: Some(901),
            created: UtcTime(1_795_000_000_000_000),
            parent_pid: 1000,
            parent_sequence: Some(77),
            session_id: 1,
            flags: Some(0),
            elevation: Some(Elevation::Limited),
            elevated: Some(false),
            integrity: Some(IntegrityLevel::Medium),
            image_name: "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe".into(),
            image_checksum: Some(0x1234),
            time_date_stamp: Some(0x5678),
            package_full_name: None,
            package_app_id: None,
            security_mitigations: Some(3),
            creator_pid: 1000,
        }
    }

    /// What a decode of `version` keeps of `start`.
    fn as_version(mut s: ProcessStart, v: u8) -> ProcessStart {
        if v < 1 {
            s.flags = None;
        }
        if v < 2 {
            s.image_checksum = None;
            s.time_date_stamp = None;
        }
        if v < 3 {
            s.sequence = None;
            s.parent_sequence = None;
            s.elevation = None;
            s.elevated = None;
            s.integrity = None;
        }
        if v < 4 {
            s.security_mitigations = None;
        }
        s
    }

    #[test]
    fn every_process_start_version_round_trips() {
        for v in 0..=4 {
            let raw = encode::process_start(&start(), v, 0);
            let got = decode(&raw).unwrap();
            assert_eq!(
                got,
                KernelEvent::ProcessStart(as_version(start(), v)),
                "v{v}"
            );
        }
    }

    #[test]
    fn package_names_are_kept() {
        let mut s = start();
        s.package_full_name = Some("App_1.0.0.0_x64__abc".into());
        s.package_app_id = Some("App".into());
        let raw = encode::process_start(&s, 2, 0);
        let KernelEvent::ProcessStart(got) = decode(&raw).unwrap() else {
            panic!()
        };
        assert_eq!(
            got.package_full_name.as_deref(),
            Some("App_1.0.0.0_x64__abc")
        );
        assert_eq!(got.package_app_id.as_deref(), Some("App"));
    }

    #[test]
    fn every_process_stop_version_round_trips() {
        let stop = ProcessStop {
            pid: 9,
            sequence: Some(5),
            created: UtcTime(1_000_000),
            exited: UtcTime(2_000_000),
            exit_code: 259,
            image_name: "cmd.exe".into(),
        };
        for v in 0..=2 {
            let raw = encode::process_stop(&stop, v, 0);
            let mut want = stop.clone();
            if v < 2 {
                want.sequence = None;
            }
            assert_eq!(decode(&raw).unwrap(), KernelEvent::ProcessStop(want));
        }
    }

    #[test]
    fn image_loads_decode_in_both_pointer_sizes() {
        let image = ImageEvent {
            pid: 4,
            base: 0x1000,
            size: 0x2000,
            checksum: 7,
            time_date_stamp: 8,
            default_base: 0x4000,
            image_name: "\\SystemRoot\\System32\\drivers\\x.sys".into(),
            timestamp: UtcTime(1_795_000_000_000_000),
        };
        for ptr in [4, 8] {
            let raw = encode::image_load(&image, ptr);
            let KernelEvent::ImageLoad(got) = decode(&raw).unwrap() else {
                panic!()
            };
            assert_eq!(got, image);
            assert!(got.is_kernel());
            let mut unload = raw.clone();
            unload.id = EVENT_IMAGE_UNLOAD;
            assert!(matches!(decode(&unload), Ok(KernelEvent::ImageUnload(_))));
        }
        let user = ImageEvent { pid: 100, ..image };
        assert!(!user.is_kernel());
    }

    #[test]
    fn unknown_inputs_are_refused() {
        let mut raw = encode::process_start(&start(), 4, 0);
        raw.provider = 1;
        assert_eq!(decode(&raw), Err(DecodeError::WrongProvider));
        let mut raw = encode::process_start(&start(), 4, 0);
        raw.version = 5;
        assert_eq!(
            decode(&raw),
            Err(DecodeError::UnknownVersion { id: 1, version: 5 })
        );
        let mut raw = encode::process_start(&start(), 4, 0);
        raw.id = 3;
        assert_eq!(decode(&raw), Err(DecodeError::UnknownEvent(3)));
        let mut raw = encode::process_start(&start(), 4, 0);
        raw.pointer_size = 2;
        assert_eq!(decode(&raw), Err(DecodeError::BadPointerSize(2)));
        let mut raw = encode::process_start(&start(), 4, 0);
        raw.data = vec![0; MAX_USER_DATA + 1];
        assert_eq!(decode(&raw), Err(DecodeError::TooLarge));
        let mut raw = encode::process_stop(
            &ProcessStop {
                pid: 1,
                sequence: None,
                created: UtcTime(0),
                exited: UtcTime(0),
                exit_code: 0,
                image_name: "a".into(),
            },
            0,
            0,
        );
        raw.version = 3;
        assert!(matches!(
            decode(&raw),
            Err(DecodeError::UnknownVersion { .. })
        ));
        let mut img = encode::image_load(
            &ImageEvent {
                pid: 1,
                base: 0,
                size: 0,
                checksum: 0,
                time_date_stamp: 0,
                default_base: 0,
                image_name: "a".into(),
                timestamp: UtcTime(0),
            },
            8,
        );
        img.version = 1;
        assert!(matches!(
            decode(&img),
            Err(DecodeError::UnknownVersion { .. })
        ));
    }

    #[test]
    fn malformed_records_fail_closed() {
        let good = encode::process_start(&start(), 4, 0);
        // Every truncation fails.
        for n in 0..good.data.len() {
            let mut raw = good.clone();
            raw.data.truncate(n);
            assert!(decode(&raw).is_err(), "truncated to {n}");
        }
        // Trailing bytes.
        let mut raw = good.clone();
        raw.data.push(0);
        assert_eq!(
            decode(&raw),
            Err(DecodeError::Malformed("record", "trailing bytes"))
        );
        // A lone surrogate in the image name.
        let mut raw = encode::process_start(&start(), 0, 0);
        let at = 4 + 8 + 4 + 4;
        raw.data[at..at + 2].copy_from_slice(&0xd800_u16.to_le_bytes());
        assert_eq!(
            decode(&raw),
            Err(DecodeError::Malformed("ImageName", "not valid UTF-16"))
        );
    }

    #[test]
    fn token_fields_are_checked() {
        let v3 = encode::process_start(&start(), 3, 0);
        // Offsets: pid 4, seq 8, created 8, ppid 4, pseq 8, session 4,
        // flags 4, then elevation type, is-elevated, label.
        let elevation_at = 4 + 8 + 8 + 4 + 8 + 4 + 4;
        let mut raw = v3.clone();
        raw.data[elevation_at..elevation_at + 4].copy_from_slice(&9_u32.to_le_bytes());
        assert_eq!(
            decode(&raw),
            Err(DecodeError::Malformed(
                "ProcessTokenElevationType",
                "unknown value"
            ))
        );
        let mut raw = v3.clone();
        raw.data[elevation_at + 4..elevation_at + 8].copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            decode(&raw),
            Err(DecodeError::Malformed("ProcessTokenIsElevated", _))
        ));
        // A label that is not a mandatory label SID.
        let mut raw = v3.clone();
        raw.data[elevation_at + 8 + 7] = 5;
        assert!(matches!(
            decode(&raw),
            Err(DecodeError::Malformed(
                "MandatoryLabel",
                "not an integrity SID"
            ))
        ));
        let mut raw = v3;
        raw.data[elevation_at + 8] = 2;
        assert!(matches!(
            decode(&raw),
            Err(DecodeError::Malformed("MandatoryLabel", "bad SID"))
        ));
        // An elevated token decodes.
        let mut s = start();
        s.elevated = Some(true);
        s.elevation = Some(Elevation::Full);
        s.integrity = Some(IntegrityLevel::High);
        let KernelEvent::ProcessStart(got) = decode(&encode::process_start(&s, 3, 0)).unwrap()
        else {
            panic!()
        };
        assert_eq!(got.elevated, Some(true));
        assert_eq!(got.integrity, Some(IntegrityLevel::High));
    }

    #[test]
    fn ansi_names_must_be_terminated_ascii() {
        let stop = ProcessStop {
            pid: 1,
            sequence: None,
            created: UtcTime(0),
            exited: UtcTime(0),
            exit_code: 0,
            image_name: "a".into(),
        };
        let mut raw = encode::process_stop(&stop, 0, 0);
        raw.data.pop();
        assert_eq!(
            decode(&raw),
            Err(DecodeError::Malformed("ImageName", "no terminator"))
        );
        let mut raw = encode::process_stop(&stop, 0, 0);
        let n = raw.data.len();
        raw.data[n - 2] = 0xe9;
        assert_eq!(
            decode(&raw),
            Err(DecodeError::Malformed("ImageName", "not ASCII"))
        );
        let mut raw = encode::process_stop(&stop, 0, 0);
        raw.data.pop();
        raw.data.pop();
        raw.data
            .extend(std::iter::repeat_n(b'a', MAX_STRING_UNITS + 1));
        raw.data.push(0);
        assert_eq!(
            decode(&raw),
            Err(DecodeError::Malformed("ImageName", "too long"))
        );
    }

    #[test]
    fn overlong_unicode_strings_are_refused() {
        // A whole record that long is over the size limit first.
        let mut s = start();
        s.image_name = "a".repeat(MAX_STRING_UNITS + 1);
        assert_eq!(
            decode(&encode::process_start(&s, 0, 0)),
            Err(DecodeError::TooLarge)
        );
        let mut bytes = Vec::new();
        for _ in 0..=MAX_STRING_UNITS {
            bytes.extend_from_slice(&u16::from(b'a').to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        let mut r = Reader {
            bytes: &bytes,
            pointer_size: 8,
        };
        assert_eq!(
            r.unicode("ImageName"),
            Err(DecodeError::Malformed("ImageName", "too long"))
        );
    }

    #[test]
    fn errors_display() {
        for e in [
            DecodeError::WrongProvider,
            DecodeError::UnknownEvent(1),
            DecodeError::UnknownVersion { id: 1, version: 9 },
            DecodeError::BadPointerSize(3),
            DecodeError::TooLarge,
            DecodeError::Malformed("a", "b"),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}

//! The spool's segment file format (#63, #197), and its reader.
//!
//! A segment is an append-only file of records of one [`Class`]:
//!
//! ```text
//! segment := MAGIC record*
//! MAGIC   := "PALSPOOL" 0x00 0x01            (10 bytes)
//! record  := len:u32le crc:u32le body
//! body    := seq:u64le class:u8 time:i64le chain:[u8; 32] payload
//! ```
//!
//! - `len` is the length of `body`, at least [`BODY_FIXED`] and at most
//!   [`BODY_FIXED`] + [`MAX_PAYLOAD`].
//! - `crc` is the CRC-32C of `body`. It catches torn writes and media
//!   errors; the hash chain (`chain`, the chain value of this record's
//!   event) catches tampering, server-side.
//! - `seq` increases strictly within a segment, and `class` is the
//!   segment's class.
//!
//! The reader is written for untrusted bytes (the file is on disk, and a
//! crash can leave anything at its end) and is fuzzed (`spool_segment`).
//! It never panics. It returns every record up to the first one that is
//! incomplete or fails a check, and the length of that valid prefix, so
//! recovery can truncate the file there (truncate-on-recovery).

#![forbid(unsafe_code)]

use super::crc32c::crc32c;

/// The file magic and format version.
pub const MAGIC: [u8; 10] = *b"PALSPOOL\x00\x01";

/// Bytes before a record's body: `len` and `crc`.
pub const RECORD_HEADER: usize = 8;

/// The fixed part of a record's body: `seq`, `class`, `time` and `chain`.
pub const BODY_FIXED: usize = 8 + 1 + 8 + 32;

/// The largest payload a record may carry: 1 MiB, well above the largest
/// canonical event.
pub const MAX_PAYLOAD: usize = 1 << 20;

/// The kinds of events the spool keeps apart, in the order it gives them
/// up when it must: [`Class::Diagnostic`] first, [`Class::Security`] last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Local diagnostics.
    Diagnostic,
    /// Allowed-decision summaries.
    Summary,
    /// Allowed decisions in full.
    Allowed,
    /// Information events: process creation, policy state, inventory.
    Info,
    /// Audited (would-block) decisions.
    Audit,
    /// Blocked decisions.
    Blocked,
    /// Tamper, security and agent-health events.
    Security,
}

impl Class {
    /// Every class, in eviction order.
    pub const ALL: [Self; 7] = [
        Self::Diagnostic,
        Self::Summary,
        Self::Allowed,
        Self::Info,
        Self::Audit,
        Self::Blocked,
        Self::Security,
    ];

    /// The upload order: priority classes first, so a backlog of allowed
    /// events never delays a block (#63).
    pub const UPLOAD_ORDER: [Self; 7] = [
        Self::Security,
        Self::Blocked,
        Self::Audit,
        Self::Info,
        Self::Allowed,
        Self::Summary,
        Self::Diagnostic,
    ];

    /// Whether the class is uploaded with priority and kept until the
    /// spool is physically full.
    #[must_use]
    pub const fn is_priority(self) -> bool {
        matches!(self, Self::Audit | Self::Blocked | Self::Security)
    }

    /// Whether the spool keeps it only while there is room under the soft
    /// cap. Audited events are uploaded with priority but given up before
    /// blocked and security events (#197).
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::Blocked | Self::Security)
    }

    /// The byte that stands for it on disk.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Diagnostic => 0,
            Self::Summary => 1,
            Self::Allowed => 2,
            Self::Info => 3,
            Self::Audit => 4,
            Self::Blocked => 5,
            Self::Security => 6,
        }
    }

    /// The class for a byte, if it stands for one.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Diagnostic,
            1 => Self::Summary,
            2 => Self::Allowed,
            3 => Self::Info,
            4 => Self::Audit,
            5 => Self::Blocked,
            6 => Self::Security,
            _ => return None,
        })
    }

    /// Its name, as used in segment file names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Diagnostic => "diagnostic",
            Self::Summary => "summary",
            Self::Allowed => "allowed",
            Self::Info => "info",
            Self::Audit => "audit",
            Self::Blocked => "blocked",
            Self::Security => "security",
        }
    }

    /// The class named `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// One spooled event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// The event's sequence number.
    pub seq: u64,
    /// Its class.
    pub class: Class,
    /// When it was recorded, in microseconds since the Unix epoch.
    pub time: i64,
    /// The chain value of this event: what the next event's `prev_hash`
    /// is. Kept so the chain head survives a restart.
    pub chain: [u8; 32],
    /// The event, in its canonical encoding.
    pub payload: Vec<u8>,
}

impl StoredRecord {
    /// Its size on disk.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        RECORD_HEADER + BODY_FIXED + self.payload.len()
    }
}

/// A record whose payload is over [`MAX_PAYLOAD`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLarge;

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a spool record holds at most {MAX_PAYLOAD} bytes")
    }
}

impl std::error::Error for TooLarge {}

/// Appends the encoding of `record` to `out`.
///
/// # Errors
///
/// [`TooLarge`] if the payload is over [`MAX_PAYLOAD`]; nothing is written.
pub fn encode(record: &StoredRecord, out: &mut Vec<u8>) -> Result<(), TooLarge> {
    if record.payload.len() > MAX_PAYLOAD {
        return Err(TooLarge);
    }
    let len = u32::try_from(BODY_FIXED + record.payload.len()).map_err(|_| TooLarge)?;
    let mut body = Vec::with_capacity(BODY_FIXED + record.payload.len());
    body.extend_from_slice(&record.seq.to_le_bytes());
    body.push(record.class.code());
    body.extend_from_slice(&record.time.to_le_bytes());
    body.extend_from_slice(&record.chain);
    body.extend_from_slice(&record.payload);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&crc32c(&body).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(())
}

/// How a segment ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    /// Every byte belongs to a valid record.
    Clean,
    /// The last record is incomplete: a write that did not finish.
    Torn,
    /// A record failed a check (CRC, length, class or order). It and
    /// everything after it are not trusted.
    Corrupt,
    /// The file does not start with [`MAGIC`]. Nothing in it is trusted.
    BadMagic,
}

/// What [`decode`] read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The valid records, in file order.
    pub records: Vec<StoredRecord>,
    /// The length of the valid prefix, including the magic. 0 when the
    /// magic is wrong.
    pub valid_len: usize,
    /// How it ended.
    pub tail: Tail,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at.checked_add(4)?)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at.checked_add(8)?)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Reads a segment of class `class` (see the module docs).
#[must_use]
pub fn decode(bytes: &[u8], class: Class) -> Decoded {
    let mut decoded = Decoded {
        records: Vec::new(),
        valid_len: 0,
        tail: Tail::Clean,
    };
    match bytes.get(..MAGIC.len()) {
        Some(magic) if magic == MAGIC => {}
        Some(_) => {
            decoded.tail = Tail::BadMagic;
            return decoded;
        }
        // A file shorter than the magic: torn while it was being created,
        // if what is there is a prefix of the magic.
        None => {
            decoded.tail = if MAGIC.starts_with(bytes) {
                Tail::Torn
            } else {
                Tail::BadMagic
            };
            return decoded;
        }
    }
    let mut at = MAGIC.len();
    decoded.valid_len = at;
    let mut last_seq: Option<u64> = None;
    while at < bytes.len() {
        let (Some(len), Some(crc)) = (u32_at(bytes, at), u32_at(bytes, at + 4)) else {
            decoded.tail = Tail::Torn;
            return decoded;
        };
        let Ok(len) = usize::try_from(len) else {
            decoded.tail = Tail::Corrupt;
            return decoded;
        };
        if !(BODY_FIXED..=BODY_FIXED + MAX_PAYLOAD).contains(&len) {
            decoded.tail = Tail::Corrupt;
            return decoded;
        }
        let start = at + RECORD_HEADER;
        let Some(body) = start.checked_add(len).and_then(|end| bytes.get(start..end)) else {
            decoded.tail = Tail::Torn;
            return decoded;
        };
        if crc32c(body) != crc {
            decoded.tail = Tail::Corrupt;
            return decoded;
        }
        let record = (|| {
            let seq = u64_at(body, 0)?;
            let record_class = Class::from_code(*body.get(8)?)?;
            let time = i64::from_le_bytes(body.get(9..17)?.try_into().ok()?);
            let chain: [u8; 32] = body.get(17..49)?.try_into().ok()?;
            let payload = body.get(BODY_FIXED..)?.to_vec();
            (record_class == class && last_seq.is_none_or(|l| seq > l)).then_some(StoredRecord {
                seq,
                class,
                time,
                chain,
                payload,
            })
        })();
        let Some(record) = record else {
            decoded.tail = Tail::Corrupt;
            return decoded;
        };
        last_seq = Some(record.seq);
        decoded.records.push(record);
        at = start + len;
        decoded.valid_len = at;
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64, class: Class, payload: &[u8]) -> StoredRecord {
        StoredRecord {
            seq,
            class,
            time: 1_700_000_000_000_000 + i64::try_from(seq).unwrap(),
            chain: [u8::try_from(seq % 256).unwrap(); 32],
            payload: payload.to_vec(),
        }
    }

    fn segment(records: &[StoredRecord]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for r in records {
            encode(r, &mut out).unwrap();
        }
        out
    }

    #[test]
    fn records_round_trip() {
        let records = [
            rec(3, Class::Blocked, b"{\"a\":1}"),
            rec(9, Class::Blocked, b""),
            rec(10, Class::Blocked, &[0xff; 300]),
        ];
        let bytes = segment(&records);
        let d = decode(&bytes, Class::Blocked);
        assert_eq!(d.tail, Tail::Clean);
        assert_eq!(d.valid_len, bytes.len());
        assert_eq!(d.records, records);
        assert_eq!(
            records.iter().map(StoredRecord::encoded_len).sum::<usize>() + MAGIC.len(),
            bytes.len()
        );
        // Just the magic is an empty, clean segment.
        let d = decode(&MAGIC, Class::Info);
        assert_eq!((d.records.len(), d.valid_len, d.tail), (0, 10, Tail::Clean));
    }

    #[test]
    fn every_truncation_is_torn_and_keeps_the_complete_records() {
        let records = [rec(1, Class::Info, b"one"), rec(2, Class::Info, b"two")];
        let bytes = segment(&records);
        let first_end = MAGIC.len() + records[0].encoded_len();
        for cut in 0..bytes.len() {
            let d = decode(&bytes[..cut], Class::Info);
            // A cut on a record boundary leaves a clean, shorter segment.
            let boundary = cut == MAGIC.len() || cut == first_end;
            let tail = if boundary { Tail::Clean } else { Tail::Torn };
            assert_eq!(d.tail, tail, "cut {cut}");
            let want = usize::from(cut >= first_end);
            assert_eq!(d.records.len(), want, "cut {cut}");
            assert_eq!(
                d.valid_len,
                match (cut < MAGIC.len(), want) {
                    (true, _) => 0,
                    (false, 0) => MAGIC.len(),
                    _ => first_end,
                },
                "cut {cut}"
            );
        }
    }

    #[test]
    fn any_flipped_bit_after_the_magic_is_caught() {
        let records = [rec(1, Class::Audit, b"payload")];
        let bytes = segment(&records);
        for i in MAGIC.len()..bytes.len() {
            for bit in 0..8 {
                let mut bad = bytes.clone();
                bad[i] ^= 1 << bit;
                let d = decode(&bad, Class::Audit);
                assert!(d.records.is_empty(), "byte {i} bit {bit}");
                assert_ne!(d.tail, Tail::Clean, "byte {i} bit {bit}");
                assert_eq!(d.valid_len, MAGIC.len());
            }
        }
    }

    #[test]
    fn checks_stop_at_the_first_bad_record() {
        let good = rec(5, Class::Security, b"x");
        // A record of another class.
        let bytes = segment(&[good.clone(), rec(6, Class::Blocked, b"y")]);
        let d = decode(&bytes, Class::Security);
        assert_eq!((d.records, d.tail), (vec![good.clone()], Tail::Corrupt));
        // A sequence number that does not increase.
        let bytes = segment(&[good.clone(), rec(5, Class::Security, b"y")]);
        assert_eq!(decode(&bytes, Class::Security).tail, Tail::Corrupt);
        // A length below the fixed part, and above the maximum.
        for len in [
            0u32,
            48,
            u32::try_from(BODY_FIXED + MAX_PAYLOAD + 1).unwrap(),
        ] {
            let mut bytes = segment(std::slice::from_ref(&good));
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(&[0; 4]);
            let d = decode(&bytes, Class::Security);
            assert_eq!(d.tail, Tail::Corrupt, "len {len}");
            assert_eq!(d.records.len(), 1);
        }
        // An unknown class byte, with a correct CRC.
        let mut body = vec![0u8; BODY_FIXED];
        body[8] = 7;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&crc32c(&body).to_le_bytes());
        bytes.extend_from_slice(&body);
        assert_eq!(decode(&bytes, Class::Diagnostic).tail, Tail::Corrupt);
    }

    #[test]
    fn a_wrong_magic_trusts_nothing() {
        let mut bytes = segment(&[rec(1, Class::Info, b"x")]);
        bytes[0] = b'X';
        let d = decode(&bytes, Class::Info);
        assert_eq!(
            (d.records.len(), d.valid_len, d.tail),
            (0, 0, Tail::BadMagic)
        );
        assert_eq!(decode(b"XY", Class::Info).tail, Tail::BadMagic);
        assert_eq!(decode(b"PAL", Class::Info).tail, Tail::Torn);
    }

    #[test]
    fn oversized_payloads_are_refused() {
        let mut out = Vec::new();
        let big = rec(1, Class::Info, &vec![0; MAX_PAYLOAD + 1]);
        assert_eq!(encode(&big, &mut out), Err(TooLarge));
        assert!(out.is_empty());
        assert!(TooLarge.to_string().contains("at most"));
        let max = rec(1, Class::Info, &vec![7; MAX_PAYLOAD]);
        encode(&max, &mut out).unwrap();
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&out);
        assert_eq!(decode(&bytes, Class::Info).records, [max]);
    }

    #[test]
    fn classes_have_stable_codes_and_names() {
        for (i, class) in Class::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(class.code()), i);
            assert_eq!(Class::from_code(class.code()), Some(class));
            assert_eq!(Class::from_name(class.as_str()), Some(class));
            assert_eq!(class.is_protected(), class >= Class::Blocked);
            assert_eq!(class.is_priority(), class >= Class::Audit);
            assert!(Class::UPLOAD_ORDER.contains(&class));
        }
        assert_eq!(Class::from_code(7), None);
        assert_eq!(Class::from_name("x"), None);
    }
}

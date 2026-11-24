//! The canonical fields a mapping may write, and how a source value is read
//! into each.
//!
//! A mapping names its targets by JSON Pointer into [`Event`](crate::events::Event).
//! Only the leaves listed here are writable. Envelope fields that the agent
//! owns (`event_id`, `seq`, `prev_hash`, `tenant_id`, `host`, the clock
//! fields, `labels`) and the fields that the mapping entry itself sets
//! (`event_type`, `category`, `action`, `outcome`, `mode`, `severity`,
//! `description`, `ts`, `source`) are not, so an OS log can never claim a
//! sequence number, a chain value or another device. The test
//! `every_target_exists_in_the_schema` checks each pointer against the
//! generated JSON Schema, so a target cannot name a field that does not
//! exist.

use std::str::FromStr;

use serde_json::Value;

use crate::events::{Guid, HexBytes, Md5Hex, Sha1Hex, Sha256Hex, Sid, Timestamp};

/// How a source value is read for a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Text of at most this many characters.
    Text(usize),
    /// A security identifier.
    Sid,
    /// A GUID. Braces and uppercase are accepted and normalised.
    Guid,
    /// A SHA-256 digest. A `0x` prefix and uppercase are accepted.
    Sha256,
    /// A SHA-1 digest.
    Sha1,
    /// An MD5 digest.
    Md5,
    /// 1 to 64 bytes of hex.
    HexBytes,
    /// An unsigned integer, decimal or `0x` hex, at most this value.
    Unsigned(u64),
    /// `true`, `false`, `1` or `0`, in any case.
    Bool,
    /// An RFC 3339 UTC timestamp, 0 to 9 fractional digits.
    Timestamp,
}

const NAME: Kind = Kind::Text(256);
const LONG: Kind = Kind::Text(32_767);
const U8: Kind = Kind::Unsigned(u8::MAX as u64);
const U32: Kind = Kind::Unsigned(u32::MAX as u64);
const U64: Kind = Kind::Unsigned(u64::MAX);

/// Writable leaves of the event, by JSON Pointer.
pub(crate) const EVENT_TARGETS: &[(&str, Kind)] = &[
    ("/user/sid", Kind::Sid),
    ("/user/name", NAME),
    ("/user/domain", NAME),
    ("/user/upn", NAME),
    ("/user/session_id", U32),
    ("/user/logon_id", U64),
    ("/process/pid", U32),
    ("/process/image_path", LONG),
    ("/process/image_path_normalised", LONG),
    ("/process/cmdline", LONG),
    ("/process/owner_sid", Kind::Sid),
    ("/file/path", LONG),
    ("/file/path_normalised", LONG),
    ("/file/package_name", NAME),
    ("/file/size", U64),
    ("/file/created", Kind::Timestamp),
    ("/file/modified", Kind::Timestamp),
    ("/file/owner_sid", Kind::Sid),
    ("/file/hashes/sha256", Kind::Sha256),
    ("/file/hashes/sha1", Kind::Sha1),
    ("/file/hashes/md5", Kind::Md5),
    ("/file/hashes/authenticode_sha256", Kind::Sha256),
    ("/file/hashes/authenticode_sha1", Kind::Sha1),
    ("/file/version_info/original_filename", NAME),
    ("/file/version_info/internal_name", NAME),
    ("/file/version_info/product_name", NAME),
    ("/file/version_info/company", NAME),
    ("/file/version_info/file_version", NAME),
    ("/file/version_info/product_version", NAME),
    ("/file/version_info/description", NAME),
    ("/file/user_writable_location", Kind::Bool),
    ("/script/path", LONG),
    ("/script/interpreter", NAME),
    ("/script/content_sha256", Kind::Sha256),
    ("/script/script_block_id", Kind::Guid),
    ("/native/status_code", U32),
    ("/native/requested_signing_level", U8),
    ("/native/validated_signing_level", U8),
    ("/native/signing_scenario", U32),
    ("/native/policy_name", NAME),
    ("/native/policy_id", NAME),
    ("/native/policy_guid", Kind::Guid),
    ("/native/policy_hash", Kind::HexBytes),
    ("/native/policy_options", U32),
    ("/native/policy_count", U32),
    ("/native/clsid", Kind::Guid),
    ("/native/rule_guid", Kind::Guid),
    ("/native/rule_name", NAME),
    ("/native/rule_sddl", LONG),
    ("/native/rule_hash", Kind::HexBytes),
    ("/native/fqbn", LONG),
    ("/native/catalog_sha256", Kind::Sha256),
    ("/native/catalog_sha1", Kind::Sha1),
    ("/native/policy_audit_mode", Kind::Bool),
    ("/native/managed_installer_enabled", Kind::Bool),
    ("/native/passes_managed_installer", Kind::Bool),
];

/// Writable leaves of one signer, relative to the signer object.
pub(crate) const SIGNER_TARGETS: &[(&str, Kind)] = &[
    ("publisher", NAME),
    ("issuer", NAME),
    ("leaf_thumbprint", Kind::HexBytes),
    ("tbs_hash", Kind::HexBytes),
    ("issuer_tbs_hash", Kind::HexBytes),
    ("signature_type", U8),
    ("signing_level", U8),
    ("verification_error", U8),
];

/// Where a mapping entry with `signatures: true` puts its signers.
pub(crate) const SIGNERS_POINTER: &str = "/file/signers";

pub(crate) fn event_target(pointer: &str) -> Option<Kind> {
    EVENT_TARGETS
        .iter()
        .find(|(p, _)| *p == pointer)
        .map(|(_, k)| *k)
}

pub(crate) fn signer_target(name: &str) -> Option<Kind> {
    SIGNER_TARGETS
        .iter()
        .find(|(p, _)| *p == name)
        .map(|(_, k)| *k)
}

/// Lowercases hex and drops a `0x` prefix.
fn normalise_hex(raw: &str) -> String {
    raw.strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw)
        .to_ascii_lowercase()
}

fn parse_unsigned(raw: &str, max: u64) -> Option<u64> {
    let value = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
            u64::from_str_radix(hex, 16).ok()?
        }
        Some(_) => return None,
        None if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) => raw.parse().ok()?,
        None => return None,
    };
    (value <= max).then_some(value)
}

fn canonical<T: FromStr + ToString>(text: &str) -> Option<Value> {
    text.parse::<T>().ok().map(|v| Value::String(v.to_string()))
}

impl Kind {
    /// Reads a source value. `Ok(None)` for an empty value (treated as
    /// absent). `Err` with the reason for a value that does not fit.
    pub(crate) fn read(self, raw: &str) -> Result<Option<Value>, &'static str> {
        if raw.is_empty() {
            return Ok(None);
        }
        let value = match self {
            Self::Text(max) => {
                if raw.chars().count() > max {
                    return Err("text is too long for the target field");
                }
                Some(Value::String(raw.to_owned()))
            }
            Self::Sid => canonical::<Sid>(raw),
            Self::Guid => {
                let inner = raw
                    .strip_prefix('{')
                    .and_then(|s| s.strip_suffix('}'))
                    .unwrap_or(raw);
                canonical::<Guid>(&inner.to_ascii_lowercase())
            }
            Self::Sha256 => canonical::<Sha256Hex>(&normalise_hex(raw)),
            Self::Sha1 => canonical::<Sha1Hex>(&normalise_hex(raw)),
            Self::Md5 => canonical::<Md5Hex>(&normalise_hex(raw)),
            Self::HexBytes => canonical::<HexBytes>(&normalise_hex(raw)),
            Self::Unsigned(max) => parse_unsigned(raw, max).map(Value::from),
            Self::Bool => match raw.to_ascii_lowercase().as_str() {
                "true" | "1" => Some(Value::Bool(true)),
                "false" | "0" => Some(Value::Bool(false)),
                _ => None,
            },
            Self::Timestamp => Timestamp::parse_utc(raw)
                .ok()
                .map(|t| Value::String(t.to_string())),
        };
        value.map(Some).ok_or(match self {
            Self::Text(_) => "not text",
            Self::Sid => "not a security identifier",
            Self::Guid => "not a GUID",
            Self::Sha256 | Self::Sha1 | Self::Md5 | Self::HexBytes => {
                "not hexadecimal of the right length"
            }
            Self::Unsigned(_) => "not an unsigned integer in range",
            Self::Bool => "not a boolean",
            Self::Timestamp => "not an RFC 3339 UTC timestamp",
        })
    }
}

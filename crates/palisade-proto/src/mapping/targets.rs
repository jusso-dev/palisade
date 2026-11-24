//! The canonical fields a mapping may write, and how a source value is read
//! into each.
//!
//! A mapping names its targets by JSON Pointer into [`Event`](crate::events::Event).
//! Only the leaves listed here are writable. Envelope fields that the agent
//! owns (`event_id`, `seq`, `prev_hash`, `tenant_id`, `host`, the clock
//! fields, `labels`) and the fields that the mapping entry itself sets
//! (`event_type`, `category`, `action`, `outcome`, `mode`, `severity`,
//! `description`, `ts`, and `source` apart from the source's own rule and
//! policy names) are not, so an OS log can never claim a sequence number, a
//! chain value or another device. Fields that only Palisade components
//! produce are not writable either: principals (which need a `kind` a log
//! cannot vouch for), administrative diffs, and JSON values.
//!
//! The test `every_target_exists_in_the_schema` checks each pointer against
//! the generated JSON Schema, and `enum_targets_match_the_schema` checks
//! each enum target's values against the schema's, so a target cannot name
//! a field or a value that does not exist.

use std::str::FromStr;

use serde_json::Value;

use crate::events::{
    DnsName, Guid, HexBytes, IpAddress, Md5Hex, RegistryKey, Sha1Hex, Sha256Hex, Sid, Timestamp,
};

/// How a source value is read for a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Text of at most this many characters.
    Text(usize),
    /// A security identifier, in any spelling the OS writes.
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
    /// A flag written only when set: `true` or `1` sets it, `false` or `0`
    /// leaves it out.
    Flag,
    /// An RFC 3339 UTC timestamp, 0 to 9 fractional digits.
    Timestamp,
    /// An IPv4 or IPv6 address in any form the standard library reads;
    /// written in canonical form.
    Ip,
    /// A DNS name; lowercased, without a trailing dot.
    Dns,
    /// A registry key; the kernel form and short root names are accepted.
    RegistryKey,
    /// One of these enum values, exactly as written (after a value table).
    Enum(&'static [&'static str]),
    /// A set of these enum values, written in this order (the schema's).
    EnumSet(&'static [&'static str]),
}

const NAME: Kind = Kind::Text(256);
const LONG: Kind = Kind::Text(32_767);
const REMARK: Kind = Kind::Text(1024);
const U8: Kind = Kind::Unsigned(u8::MAX as u64);
const U16: Kind = Kind::Unsigned(u16::MAX as u64);
const U32: Kind = Kind::Unsigned(u32::MAX as u64);
const U64: Kind = Kind::Unsigned(u64::MAX);

/// The values of each enum a target can hold, in the order the schema lists
/// them (the declaration order).
pub(crate) mod enums {
    pub const LOGON_TYPE: &[&str] = &[
        "interactive",
        "network",
        "batch",
        "service",
        "unlock",
        "network_cleartext",
        "new_credentials",
        "remote_interactive",
        "cached_interactive",
        "cached_remote_interactive",
        "cached_unlock",
    ];
    pub const INTEGRITY_LEVEL: &[&str] = &[
        "untrusted",
        "low",
        "medium",
        "medium_plus",
        "high",
        "system",
        "protected",
    ];
    pub const TOKEN_ELEVATION_TYPE: &[&str] = &["default", "full", "limited"];
    pub const SCRIPT_KIND: &[&str] = &[
        "powershell",
        "batch",
        "cmd",
        "vbscript",
        "jscript",
        "wsf",
        "wsc",
        "python",
        "java",
        "reg",
        "other",
    ];
    pub const LANGUAGE_MODE: &[&str] = &[
        "full_language",
        "constrained_language",
        "restricted_language",
        "no_language",
    ];
    pub const DIRECTION: &[&str] = &["inbound", "outbound", "local"];
    pub const RESOLUTION: &[&str] = &[
        "dns",
        "dns_cache",
        "hosts_file",
        "local_name",
        "tls_sni",
        "http_host",
        "reverse_dns",
        "requested",
    ];
    pub const DEVICE_INTERFACE: &[&str] = &[
        "usb",
        "thunderbolt",
        "firewire",
        "bluetooth",
        "sd_card",
        "sata",
        "nvme",
        "serial",
        "other",
    ];
    pub const DEVICE_CLASS: &[&str] = &[
        "storage",
        "hid",
        "network",
        "imaging",
        "media",
        "printer",
        "smart_card",
        "portable",
        "optical",
        "other",
    ];
    pub const ENCRYPTION_STATE: &[&str] = &["encrypted", "unencrypted", "suspended", "in_progress"];
    pub const REGISTRY_OPERATION: &[&str] = &[
        "create_key",
        "delete_key",
        "set_value",
        "delete_value",
        "read_key",
        "read_value",
    ];
    pub const REGISTRY_VALUE_TYPE: &[&str] = &[
        "none",
        "string",
        "expand_string",
        "binary",
        "dword",
        "dword_big_endian",
        "link",
        "multi_string",
        "resource_list",
        "full_resource_descriptor",
        "resource_requirements_list",
        "qword",
    ];
    pub const ELEVATION_METHOD: &[&str] = &[
        "jit",
        "on_demand",
        "auto",
        "challenge_response",
        "uac_replacement",
    ];
    pub const GROUP_SCOPE: &[&str] = &["local", "global", "universal"];
    pub const AUDIT_CATEGORY: &[&str] = &[
        "system",
        "logon_logoff",
        "object_access",
        "privilege_use",
        "detailed_tracking",
        "policy_change",
        "account_management",
        "directory_service_access",
        "account_logon",
    ];
    pub const AUDIT_POLICY_CHANGE: &[&str] = &[
        "success_added",
        "success_removed",
        "failure_added",
        "failure_removed",
    ];
    pub const FIM_CHANGE: &[&str] = &[
        "created",
        "modified",
        "deleted",
        "renamed",
        "permissions_changed",
        "attributes_changed",
    ];
}

/// Writable leaves of the event, by JSON Pointer.
pub(crate) const EVENT_TARGETS: &[(&str, Kind)] = &[
    ("/user/sid", Kind::Sid),
    ("/user/name", NAME),
    ("/user/domain", NAME),
    ("/user/upn", NAME),
    ("/user/session_id", U32),
    ("/user/logon_id", U64),
    ("/user/logon_type", Kind::Enum(enums::LOGON_TYPE)),
    ("/user/is_admin", Kind::Bool),
    ("/user/elevated", Kind::Bool),
    ("/source/rule_name", NAME),
    ("/process/pid", U32),
    ("/process/image_path", LONG),
    ("/process/image_path_normalised", LONG),
    ("/process/cmdline", LONG),
    ("/process/owner_sid", Kind::Sid),
    (
        "/process/integrity_level",
        Kind::Enum(enums::INTEGRITY_LEVEL),
    ),
    (
        "/process/token_elevation_type",
        Kind::Enum(enums::TOKEN_ELEVATION_TYPE),
    ),
    ("/process/hashes/sha256", Kind::Sha256),
    ("/process/parent/pid", U32),
    ("/process/parent/image_path", LONG),
    ("/process/parent/cmdline", LONG),
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
    ("/file/signers/0/publisher", NAME),
    ("/file/signers/0/issuer", NAME),
    ("/file/signers/0/leaf_thumbprint", Kind::HexBytes),
    ("/file/signers/0/tbs_hash", Kind::HexBytes),
    ("/file/signers/0/issuer_tbs_hash", Kind::HexBytes),
    ("/file/version_info/original_filename", NAME),
    ("/file/version_info/internal_name", NAME),
    ("/file/version_info/product_name", NAME),
    ("/file/version_info/company", NAME),
    ("/file/version_info/file_version", NAME),
    ("/file/version_info/product_version", NAME),
    ("/file/version_info/description", NAME),
    ("/file/user_writable_location", Kind::Bool),
    ("/script/path", LONG),
    ("/script/inline", Kind::Flag),
    ("/script/kind", Kind::Enum(enums::SCRIPT_KIND)),
    ("/script/interpreter", NAME),
    ("/script/content_sha256", Kind::Sha256),
    ("/script/language_mode", Kind::Enum(enums::LANGUAGE_MODE)),
    ("/script/script_block_id", Kind::Guid),
    ("/script/text", LONG),
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
    // Since 1.1.
    ("/network/direction", Kind::Enum(enums::DIRECTION)),
    ("/network/protocol", U8),
    ("/network/local_ip", Kind::Ip),
    ("/network/local_port", U16),
    ("/network/remote_ip", Kind::Ip),
    ("/network/remote_port", U16),
    ("/network/remote_hostname", Kind::Dns),
    ("/network/resolution", Kind::Enum(enums::RESOLUTION)),
    ("/network/url", LONG),
    ("/network/unc", LONG),
    ("/device/interface", Kind::Enum(enums::DEVICE_INTERFACE)),
    ("/device/class", Kind::Enum(enums::DEVICE_CLASS)),
    ("/device/vendor_id", U16),
    ("/device/product_id", U16),
    ("/device/serial", NAME),
    ("/device/friendly_name", NAME),
    ("/device/instance_id", NAME),
    ("/device/encryption", Kind::Enum(enums::ENCRYPTION_STATE)),
    ("/registry/key", Kind::RegistryKey),
    ("/registry/value_name", Kind::Text(16_383)),
    ("/registry/default_value", Kind::Flag),
    ("/registry/operation", Kind::Enum(enums::REGISTRY_OPERATION)),
    (
        "/registry/old/value_type",
        Kind::Enum(enums::REGISTRY_VALUE_TYPE),
    ),
    ("/registry/old/size", U32),
    ("/registry/old/sha256", Kind::Sha256),
    (
        "/registry/new/value_type",
        Kind::Enum(enums::REGISTRY_VALUE_TYPE),
    ),
    ("/registry/new/size", U32),
    ("/registry/new/sha256", Kind::Sha256),
    ("/elevation/method", Kind::Enum(enums::ELEVATION_METHOD)),
    ("/elevation/token_profile", NAME),
    ("/elevation/justification", REMARK),
    ("/elevation/duration_seconds", U64),
    ("/identity/authentication_package", NAME),
    ("/identity/logon_process", NAME),
    ("/identity/workstation", NAME),
    ("/identity/status_code", U32),
    ("/identity/sub_status_code", U32),
    ("/identity/group/sid", Kind::Sid),
    ("/identity/group/name", NAME),
    ("/identity/group/domain", NAME),
    ("/identity/group/distinguished_name", LONG),
    ("/identity/group_scope", Kind::Enum(enums::GROUP_SCOPE)),
    ("/identity/member/sid", Kind::Sid),
    ("/identity/member/name", NAME),
    ("/identity/member/domain", NAME),
    ("/identity/member/distinguished_name", LONG),
    ("/audit_policy/category", Kind::Enum(enums::AUDIT_CATEGORY)),
    ("/audit_policy/subcategory_guid", Kind::Guid),
    (
        "/audit_policy/changes",
        Kind::EnumSet(enums::AUDIT_POLICY_CHANGE),
    ),
    (
        "/restriction/language_mode",
        Kind::Enum(enums::LANGUAGE_MODE),
    ),
    ("/restriction/title", NAME),
    ("/restriction/message", LONG),
    ("/restriction/error_id", NAME),
    ("/fim/change", Kind::Enum(enums::FIM_CHANGE)),
    ("/fim/old_path", LONG),
    ("/fim/old_sha256", Kind::Sha256),
    ("/fim/old_size", U64),
    ("/fim/watch", NAME),
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

/// Where a mapping entry with `signatures` puts its signers.
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
    /// Reads one source value. `Ok(None)` for an empty value (treated as
    /// absent) and for an unset [`Kind::Flag`]. `Err` with the reason for a
    /// value that does not fit.
    ///
    /// A [`Kind::EnumSet`] reads one member here; the engine collects the
    /// members of a split field into the set.
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
            Self::Sid => Sid::normalise(raw)
                .ok()
                .map(|v| Value::String(v.to_string())),
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
            Self::Flag => match raw.to_ascii_lowercase().as_str() {
                "true" | "1" => Some(Value::Bool(true)),
                "false" | "0" => return Ok(None),
                _ => None,
            },
            Self::Timestamp => Timestamp::parse_utc(raw)
                .ok()
                .map(|t| Value::String(t.to_string())),
            Self::Ip => raw
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|a| Value::String(IpAddress(a).to_string())),
            Self::Dns => DnsName::normalise(raw)
                .ok()
                .map(|n| Value::String(n.to_string())),
            Self::RegistryKey => RegistryKey::normalise(raw)
                .ok()
                .map(|k| Value::String(k.to_string())),
            Self::Enum(values) | Self::EnumSet(values) => {
                values.contains(&raw).then(|| Value::String(raw.to_owned()))
            }
        };
        value.map(Some).ok_or(match self {
            Self::Text(_) => "not text",
            Self::Sid => "not a security identifier",
            Self::Guid => "not a GUID",
            Self::Sha256 | Self::Sha1 | Self::Md5 | Self::HexBytes => {
                "not hexadecimal of the right length"
            }
            Self::Unsigned(_) => "not an unsigned integer in range",
            Self::Bool | Self::Flag => "not a boolean",
            Self::Timestamp => "not an RFC 3339 UTC timestamp",
            Self::Ip => "not an IP address",
            Self::Dns => "not a DNS name",
            Self::RegistryKey => "not a registry key",
            Self::Enum(_) | Self::EnumSet(_) => "not one of the field's values",
        })
    }

    /// For an enum set, the position of a member in schema order.
    pub(crate) fn set_rank(self, member: &str) -> Option<usize> {
        match self {
            Self::EnumSet(values) => values.iter().position(|v| *v == member),
            _ => None,
        }
    }
}

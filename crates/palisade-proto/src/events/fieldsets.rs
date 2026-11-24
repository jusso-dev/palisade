//! The field sets added in schema version 1.1 (#196): network, device,
//! registry, elevation, approval, admin, identity, audit policy, language
//! restriction and compliance probe.
//!
//! Every type follows the rules of the 1.0 field sets: one accepted form per
//! value, no `null`, bounded text and lists, and unknown fields rejected.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use palisade_core::Uuid7;

use super::value::present;
use super::{
    BoundedVec, Description, DnsName, Guid, IpAddress, JsonPointer, JsonValue, LanguageMode,
    LongText, Name, RegistryKey, Sha256Hex, Sid, SortedSet, Text, Token,
};

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Free text that someone wrote: a justification, a reason or a comment. At
/// most 1024 characters.
pub type Remark = Text<1024>;

/// Who acted: a person, a client or a component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A person signed in to the console or a client.
    User,
    /// An API client, identified by its token or client ID.
    ApiClient,
    /// A service account.
    ServiceAccount,
    /// Directory provisioning (SCIM).
    Scim,
    /// A scheduled server job.
    SystemJob,
    /// An operator of the Palisade instance, outside the tenant.
    InstanceOperator,
    /// A Palisade agent.
    Agent,
}

/// Who acted, as the server knows them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// What kind of principal.
    pub kind: PrincipalKind,
    /// The principal's stable ID: a user ID, an API token or client ID, or
    /// a job name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub id: Option<Name>,
    /// The display name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub name: Option<Name>,
    /// The user principal name or e-mail address.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub upn: Option<Name>,
    /// The Windows security identifier, for directory accounts.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sid: Option<Sid>,
}

/// An account or group in a directory or on the device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// The security identifier.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sid: Option<Sid>,
    /// The account name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub name: Option<Name>,
    /// The domain, or the device name for a local account.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub domain: Option<Name>,
    /// The directory distinguished name, for example
    /// `CN=Alice,OU=Staff,DC=example,DC=org`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub distinguished_name: Option<LongText>,
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Which way a connection goes, seen from the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Towards the device.
    Inbound,
    /// Away from the device.
    Outbound,
    /// Between two endpoints on the device.
    Local,
}

/// How a remote host name was learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMethod {
    /// A DNS query the agent observed.
    Dns,
    /// The OS resolver cache.
    DnsCache,
    /// The local hosts file.
    HostsFile,
    /// NetBIOS, LLMNR or multicast DNS.
    LocalName,
    /// The TLS server name indication.
    TlsSni,
    /// The HTTP `Host` header.
    HttpHost,
    /// A reverse lookup of the remote address.
    ReverseDns,
    /// The name the application asked for, before resolution.
    Requested,
}

/// A network connection or request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Which way it goes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub direction: Option<Direction>,
    /// The IP protocol number (IANA), for example 6 for TCP and 17 for UDP.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub protocol: Option<u8>,
    /// The device's address.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub local_ip: Option<IpAddress>,
    /// The device's port.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub local_port: Option<u16>,
    /// The other end's address.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub remote_ip: Option<IpAddress>,
    /// The other end's port.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub remote_port: Option<u16>,
    /// The other end's host name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub remote_hostname: Option<DnsName>,
    /// How `remote_hostname` was learned. Present only with it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub resolution: Option<ResolutionMethod>,
    /// The URL requested, as reported.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub url: Option<LongText>,
    /// The UNC path requested, for example `\\files\share\a.exe`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub unc: Option<LongText>,
}

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

/// The bus a peripheral is connected through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceInterface {
    /// USB.
    Usb,
    /// Thunderbolt.
    Thunderbolt,
    /// IEEE 1394.
    Firewire,
    /// Bluetooth.
    Bluetooth,
    /// An SD or other memory-card reader.
    SdCard,
    /// SATA or eSATA.
    Sata,
    /// NVMe.
    Nvme,
    /// A serial or parallel port.
    Serial,
    /// Anything else.
    Other,
}

/// What kind of peripheral it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    /// Removable or external storage.
    Storage,
    /// A keyboard, mouse or other human interface device.
    Hid,
    /// A network adapter.
    Network,
    /// A camera or scanner.
    Imaging,
    /// Audio or video.
    Media,
    /// A printer.
    Printer,
    /// A smart card reader.
    SmartCard,
    /// A phone or portable media device.
    Portable,
    /// An optical drive.
    Optical,
    /// Anything else.
    Other,
}

/// Whether a storage device's contents are encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionState {
    /// Fully encrypted and protected.
    Encrypted,
    /// Not encrypted.
    Unencrypted,
    /// Encrypted, with protection suspended.
    Suspended,
    /// Encryption or decryption is in progress.
    InProgress,
}

/// A peripheral device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// The bus it is connected through.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub interface: Option<DeviceInterface>,
    /// What kind of device it is.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub class: Option<DeviceClass>,
    /// The vendor ID (for USB, the 16-bit VID).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub vendor_id: Option<u16>,
    /// The product ID (for USB, the 16-bit PID).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub product_id: Option<u16>,
    /// The serial number, as reported.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub serial: Option<Name>,
    /// The name shown to users.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub friendly_name: Option<Name>,
    /// The OS device instance ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub instance_id: Option<Name>,
    /// For storage: whether the contents are encrypted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub encryption: Option<EncryptionState>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// What was done to a registry key or value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistryOperation {
    /// A key was created.
    CreateKey,
    /// A key was deleted.
    DeleteKey,
    /// A value was written.
    SetValue,
    /// A value was deleted.
    DeleteValue,
    /// A key's values or subkeys were read.
    ReadKey,
    /// A value was read.
    ReadValue,
}

/// The type of registry value data. The names follow the OS value types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistryValueType {
    /// No type.
    None,
    /// A string.
    String,
    /// A string with unexpanded environment variables.
    ExpandString,
    /// Binary data.
    Binary,
    /// A 32-bit number.
    Dword,
    /// A 32-bit number, big-endian.
    DwordBigEndian,
    /// A symbolic link.
    Link,
    /// A list of strings.
    MultiString,
    /// A hardware resource list.
    ResourceList,
    /// A hardware resource descriptor.
    FullResourceDescriptor,
    /// A hardware resource requirements list.
    ResourceRequirementsList,
    /// A 64-bit number.
    Qword,
}

/// Registry value data: recorded truncated, hashed, or both, never in full
/// beyond the preview limit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryData {
    /// The value type.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub value_type: Option<RegistryValueType>,
    /// The size of the data in bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub size: Option<u32>,
    /// SHA-256 of the data's raw bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sha256: Option<Sha256Hex>,
    /// The data as text: strings as they are, numbers in decimal, a list of
    /// strings joined with line feeds, anything else as lowercase hex. At
    /// most 1024 characters.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub preview: Option<Text<1024>>,
    /// The preview is shorter than the data. Only with a `preview`.
    #[serde(
        default,
        skip_serializing_if = "super::is_false",
        deserialize_with = "super::flag"
    )]
    #[schemars(schema_with = "super::value::flag_schema")]
    pub truncated: bool,
}

/// A registry key or value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// The key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub key: Option<RegistryKey>,
    /// The value's name. The unnamed (default) value has no name: it is
    /// recorded with `default_value` instead.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub value_name: Option<Text<16_383>>,
    /// The value is the key's unnamed (default) value. Never with a
    /// `value_name`.
    #[serde(
        default,
        skip_serializing_if = "super::is_false",
        deserialize_with = "super::flag"
    )]
    #[schemars(schema_with = "super::value::flag_schema")]
    pub default_value: bool,
    /// What was done.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub operation: Option<RegistryOperation>,
    /// The data before the change.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub old: Option<RegistryData>,
    /// The data after the change.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub new: Option<RegistryData>,
}

// ---------------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------------

/// How elevation was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElevationMethod {
    /// A just-in-time grant, requested and approved (#158).
    Jit,
    /// The user asked for it on one application (#155).
    OnDemand,
    /// A rule elevated the application without asking.
    Auto,
    /// An offline challenge/response code (#159).
    ChallengeResponse,
    /// Palisade's replacement for the OS consent prompt (#155).
    UacReplacement,
}

/// A privilege elevation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Elevation {
    /// How it was obtained.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub method: Option<ElevationMethod>,
    /// The token profile applied, by name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub token_profile: Option<Name>,
    /// The user's justification.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub justification: Option<Remark>,
    /// Who approved it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub approver: Option<Principal>,
    /// The request it fulfils, if one was made.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub request_id: Option<Uuid7>,
    /// How long the grant lasts, in seconds.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub duration_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// Approval
// ---------------------------------------------------------------------------

/// What an approval request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// Running an application.
    Execute,
    /// Installing software.
    Install,
    /// Elevated rights.
    Elevate,
    /// Using a device.
    Device,
    /// Network or web access.
    Network,
    /// A policy exception.
    Exception,
    /// A temporary override of the policy (#120).
    Override,
}

/// What an approval would cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// This one action.
    Once,
    /// This user on this device.
    UserOnDevice,
    /// This device, for every user.
    Device,
    /// This user, on every device.
    User,
    /// A group of devices.
    DeviceGroup,
    /// The whole tenant.
    Tenant,
}

/// Where an approval request stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Not decided yet.
    Pending,
    /// Approved.
    Approved,
    /// Refused.
    Denied,
    /// Not decided in time.
    Expired,
    /// Withdrawn by the requester.
    Cancelled,
}

/// The channel an approval was requested or decided through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalChannel {
    /// The console.
    Console,
    /// An e-mail link.
    Email,
    /// A team-chat message.
    Chat,
    /// An ITSM ticket.
    Itsm,
    /// A mobile notification.
    Mobile,
    /// An offline code read out to the user (#120, #159).
    OfflineCode,
}

/// An approval request and its decision.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// The request.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub request_id: Option<Uuid7>,
    /// What is asked for.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub kind: Option<ApprovalKind>,
    /// What the approval would cover.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub requested_scope: Option<ApprovalScope>,
    /// How long an approval would last, in seconds.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub duration_seconds: Option<u64>,
    /// Where the request stands.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub decision: Option<ApprovalDecision>,
    /// Who decided.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub decided_by: Option<Principal>,
    /// The channel it went through.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub channel: Option<ApprovalChannel>,
    /// The requester's or approver's reason.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub reason: Option<Remark>,
    /// The ITSM ticket reference.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub ticket_ref: Option<Name>,
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

/// The channel an administrative action came through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdminChannel {
    /// The console.
    Console,
    /// The REST API.
    Api,
    /// The command-line tool.
    Cli,
    /// Directory provisioning.
    Scim,
    /// A webhook callback.
    WebhookCallback,
    /// An e-mail link.
    EmailLink,
    /// A team-chat action.
    Chat,
    /// An ITSM integration.
    Itsm,
    /// A scheduled job.
    Job,
    /// An agent's own report.
    Agent,
}

/// One kind of change in a JSON Patch-like diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOp {
    /// A member was added: `new` only.
    Add,
    /// A member was removed: `old` only.
    Remove,
    /// A member's value changed: `old` and `new`.
    Replace,
}

/// One change to an object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Change {
    /// What happened to the member.
    pub op: ChangeOp,
    /// The member, as a JSON Pointer into the object.
    pub path: JsonPointer,
    /// The value before: for `remove` and `replace` only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub old: Option<JsonValue>,
    /// The value after: for `add` and `replace` only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub new: Option<JsonValue>,
}

impl Change {
    /// Whether `old` and `new` are present exactly as `op` needs.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        match self.op {
            ChangeOp::Add => self.old.is_none() && self.new.is_some(),
            ChangeOp::Remove => self.old.is_some() && self.new.is_none(),
            ChangeOp::Replace => self.old.is_some() && self.new.is_some(),
        }
    }
}

/// Most changes recorded for one administrative action.
pub const MAX_CHANGES: usize = 256;

/// An administrative action on the server (#132).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    /// Who acted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub actor: Option<Principal>,
    /// The channel it came through.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub channel: Option<AdminChannel>,
    /// The client's address.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub source_ip: Option<IpAddress>,
    /// The client's user agent.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub user_agent: Option<Text<1024>>,
    /// The kind of object acted on, for example `policy` or `computer`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub object_type: Option<Token>,
    /// The object's ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub object_id: Option<Name>,
    /// The object's display name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub object_name: Option<Name>,
    /// The object before the action, redacted (#228).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub before: Option<JsonValue>,
    /// The object after the action, redacted (#228).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub after: Option<JsonValue>,
    /// What changed, member by member.
    #[serde(default, skip_serializing_if = "BoundedVec::is_empty")]
    pub changes: BoundedVec<Change, MAX_CHANGES>,
    /// The reason given.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub reason: Option<Remark>,
    /// The change ticket reference.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub ticket_ref: Option<Name>,
    /// Ties together every record of one bulk operation or deployment.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub correlation_id: Option<Uuid7>,
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// The scope of a security group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GroupScope {
    /// A group on one device, or a domain-local group.
    Local,
    /// A directory global group.
    Global,
    /// A directory universal group.
    Universal,
}

/// Identity details: logons and group membership changes. The account that
/// logged on, or that made a change, is [`super::Event::user`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// The authentication package, for example `Kerberos` or `NTLM`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub authentication_package: Option<Name>,
    /// The logon process.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub logon_process: Option<Name>,
    /// The name of the workstation the logon came from.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub workstation: Option<Name>,
    /// For a failed logon: the OS status code (an NTSTATUS value).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub status_code: Option<u32>,
    /// For a failed logon: the more specific OS status code.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sub_status_code: Option<u32>,
    /// The group whose membership changed.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub group: Option<Account>,
    /// The group's scope.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub group_scope: Option<GroupScope>,
    /// The account added to or removed from the group.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub member: Option<Account>,
}

// ---------------------------------------------------------------------------
// Audit policy
// ---------------------------------------------------------------------------

/// A category of the OS audit policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// System.
    System,
    /// Logon and logoff.
    LogonLogoff,
    /// Object access.
    ObjectAccess,
    /// Privilege use.
    PrivilegeUse,
    /// Detailed tracking (process creation and the like).
    DetailedTracking,
    /// Policy change.
    PolicyChange,
    /// Account management.
    AccountManagement,
    /// Directory service access.
    DirectoryServiceAccess,
    /// Account logon.
    AccountLogon,
}

/// One change to an audit policy subcategory.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuditPolicyChange {
    /// Success auditing was turned on.
    SuccessAdded,
    /// Success auditing was turned off.
    SuccessRemoved,
    /// Failure auditing was turned on.
    FailureAdded,
    /// Failure auditing was turned off.
    FailureRemoved,
}

/// A change to the OS audit policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditPolicy {
    /// The category of the changed subcategory.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub category: Option<AuditCategory>,
    /// The changed subcategory's GUID, which identifies it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub subcategory_guid: Option<Guid>,
    /// What changed, in the order the schema lists the values.
    #[serde(default, skip_serializing_if = "SortedSet::is_empty")]
    pub changes: SortedSet<AuditPolicyChange, 4>,
}

// ---------------------------------------------------------------------------
// Language restriction
// ---------------------------------------------------------------------------

/// A restriction a script interpreter applied, or in audit mode would have
/// applied, because the script is not allowed to run unrestricted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Restriction {
    /// The language mode that applies, or would apply.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub language_mode: Option<LanguageMode>,
    /// The kind of restriction, as the interpreter titles it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub title: Option<Name>,
    /// The interpreter's message, with the script position.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub message: Option<LongText>,
    /// The interpreter's identifier for the restriction.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub error_id: Option<Name>,
}

// ---------------------------------------------------------------------------
// Compliance probe
// ---------------------------------------------------------------------------

/// The result of a compliance probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// The device meets the requirement.
    Pass,
    /// The device does not meet the requirement.
    Fail,
    /// The probe could not run.
    Error,
    /// The requirement does not apply to this device.
    NotApplicable,
}

/// One compliance probe and its result (#210).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// The probe's stable ID, for example `powershell_script_block_logging`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub id: Option<Token>,
    /// The probe's name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub name: Option<Name>,
    /// The control it evidences, for example `ISM-1623`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub control: Option<Name>,
    /// The result.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub status: Option<ProbeStatus>,
    /// The value the requirement expects.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub expected: Option<JsonValue>,
    /// The value found on the device.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub observed: Option<JsonValue>,
    /// A short explanation of the result.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub detail: Option<Description>,
}

// ---------------------------------------------------------------------------
// File integrity monitoring
// ---------------------------------------------------------------------------

/// What happened to a monitored file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FimChange {
    /// The file was created.
    Created,
    /// The file's content changed.
    Modified,
    /// The file was deleted.
    Deleted,
    /// The file was renamed or moved: the old path is in `old_path`.
    Renamed,
    /// The file's owner or permissions changed.
    PermissionsChanged,
    /// The file's attributes or timestamps changed.
    AttributesChanged,
}

/// A change to a monitored file (#183). The file as it is now is
/// [`super::Event::file`]; this records what it was before.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fim {
    /// What happened.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub change: Option<FimChange>,
    /// For a rename, the path before.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub old_path: Option<LongText>,
    /// SHA-256 of the content before.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub old_sha256: Option<Sha256Hex>,
    /// The size before, in bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub old_size: Option<u64>,
    /// The monitoring rule that matched, by name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub watch: Option<Name>,
}

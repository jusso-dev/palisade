//! Where enrolment state lives (#223): registration codes, enrolled devices
//! and their certificates, published policy.
//!
//! [`EnrolStore`] is the seam to the ADR 0006 database. Its rows belong in
//! tenant-scoped tables with row-level security (a `registration_code`,
//! `device` and `device_certificate` migration, #127). Until those exist,
//! [`MemoryStore`] keeps everything in process memory for development and
//! tests: a restart forgets every device, so agents must re-enrol.
//!
//! Every operation that decides something (consuming a code use, recording
//! a nonce) is a single call that checks and changes state under one lock,
//! so two concurrent enrolments cannot both take a code's last use.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use palisade_proto::comms::KeyProtection;
use palisade_proto::events::{HostId, Sha256Hex, TenantId, Timestamp, Uuid7};

/// A registration code as stored: only its peppered hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeRecord {
    /// The tenant the code enrols into.
    pub tenant: TenantId,
    /// The group the code enrols into.
    pub group: Uuid7,
    /// When the code stops working, if ever.
    pub expires_at: Option<Timestamp>,
    /// How many enrolments it allows, if limited.
    pub max_uses: Option<u32>,
    /// How many it has allowed.
    pub uses: u32,
    /// Whether an administrator revoked it.
    pub revoked: bool,
    /// Source networks allowed to enrol with it (`register restrictions`).
    /// Empty means any source.
    pub allowed_sources: Vec<IpNet>,
    /// Whether only hardware-protected keys may enrol with it
    /// (`enrol.require_hardware_key`).
    pub require_hardware_key: bool,
}

/// An IP network: an address and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// A network, or `None` if the prefix is longer than the address.
    #[must_use]
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { addr, prefix })
    }

    /// Whether `ip` is in this network. An IPv4 address never matches an
    /// IPv6 network or the reverse, except that an IPv4-mapped IPv6
    /// address is compared as IPv4.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_match(net: &[u8], ip: &[u8], prefix: u8) -> bool {
    let mut left = usize::from(prefix);
    for (n, i) in net.iter().zip(ip) {
        if left == 0 {
            return true;
        }
        let bits = left.min(8);
        // `bits` is 1 to 8, so the shift is 0 to 7.
        let mask = 0xffu8 << (8 - bits);
        if n & mask != i & mask {
            return false;
        }
        left -= bits;
    }
    true
}

impl std::str::FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{s}` is not an IP address or CIDR network"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse()
                .map_err(|_| format!("`{s}` has an invalid prefix length"))?,
        };
        Self::new(addr, prefix).ok_or_else(|| format!("`{s}` has a prefix longer than {max}"))
    }
}

/// Why a code was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeRefusal {
    /// No such code, revoked, expired or used up.
    Rejected,
    /// The source address is not allowed.
    Source,
    /// The code needs a hardware key.
    HardwareKey,
}

/// An enrolled device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device ID.
    pub device: HostId,
    /// Its tenant.
    pub tenant: TenantId,
    /// Its group.
    pub group: Uuid7,
    /// The SHA-256 of its key's `SubjectPublicKeyInfo`.
    pub key_sha256: Sha256Hex,
    /// The serial of its current certificate.
    pub serial: Vec<u8>,
    /// How its key is protected.
    pub key_protection: KeyProtection,
    /// The hostname it reported.
    pub hostname: String,
    /// When it enrolled.
    pub enrolled_at: Timestamp,
    /// When it last checked in.
    pub last_seen: Option<Timestamp>,
    /// Whether an administrator revoked it. A revoked device is refused at
    /// once, whatever its certificate's lifetime.
    pub revoked: bool,
}

/// A published policy bundle envelope for a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The bundle's `policy_version`.
    pub version: u64,
    /// The SHA-256 of the canonical bundle bytes.
    pub bundle_hash: Sha256Hex,
    /// The signed envelope, as agents store it.
    pub envelope: Arc<[u8]>,
}

/// Enrolment state. Implementations must make each method atomic.
pub trait EnrolStore: Send + Sync + std::fmt::Debug {
    /// Checks the code with hash `hash` for an enrolment from `source` with
    /// a key protected by `protection` at `now`, and on success takes one
    /// use and returns the code.
    ///
    /// # Errors
    ///
    /// The [`CodeRefusal`]; no use is taken.
    fn consume_code(
        &self,
        hash: &Sha256Hex,
        source: IpAddr,
        protection: KeyProtection,
        now: Timestamp,
    ) -> Result<CodeRecord, CodeRefusal>;

    /// Records an enrolment nonce until `expires`. Returns `false` if it was
    /// seen already (a replay). Expired nonces may be forgotten.
    fn remember_nonce(&self, nonce: &[u8], now: Timestamp, expires: Timestamp) -> bool;

    /// Stores a newly enrolled device.
    fn add_device(&self, device: DeviceRecord);

    /// The device whose current certificate has `serial` and certifies the
    /// key with hash `key_sha256`, if it is enrolled and not revoked.
    fn device_by_certificate(&self, serial: &[u8], key_sha256: &Sha256Hex) -> Option<DeviceRecord>;

    /// Records a check-in.
    fn touch(&self, device: HostId, now: Timestamp);

    /// Revokes a device.
    fn revoke_device(&self, device: HostId) -> bool;

    /// The policy published for a group, if any.
    fn published(&self, tenant: TenantId, group: Uuid7) -> Option<Published>;
}

#[derive(Debug, Default)]
struct State {
    codes: BTreeMap<Sha256Hex, CodeRecord>,
    nonces: BTreeMap<Vec<u8>, Timestamp>,
    devices: BTreeMap<HostId, DeviceRecord>,
    policies: BTreeMap<(TenantId, Uuid7), Published>,
}

/// The in-memory development store.
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<State>);

/// The most nonces kept. Past it, the oldest-expiring are dropped first;
/// the age check still refuses anything older than the window.
const MAX_NONCES: usize = 100_000;

impl MemoryStore {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adds a registration code by its hash.
    pub fn add_code(&self, hash: Sha256Hex, record: CodeRecord) {
        self.lock().codes.insert(hash, record);
    }

    /// Revokes a code. Returns whether it existed.
    pub fn revoke_code(&self, hash: &Sha256Hex) -> bool {
        self.lock()
            .codes
            .get_mut(hash)
            .map(|c| c.revoked = true)
            .is_some()
    }

    /// Publishes a policy envelope for a group.
    pub fn publish(&self, tenant: TenantId, group: Uuid7, published: Published) {
        self.lock().policies.insert((tenant, group), published);
    }

    /// Every enrolled device.
    #[must_use]
    pub fn devices(&self) -> Vec<DeviceRecord> {
        self.lock().devices.values().cloned().collect()
    }
}

impl EnrolStore for MemoryStore {
    fn consume_code(
        &self,
        hash: &Sha256Hex,
        source: IpAddr,
        protection: KeyProtection,
        now: Timestamp,
    ) -> Result<CodeRecord, CodeRefusal> {
        let mut state = self.lock();
        let code = state.codes.get_mut(hash).ok_or(CodeRefusal::Rejected)?;
        if code.revoked
            || code.expires_at.is_some_and(|e| now >= e)
            || code.max_uses.is_some_and(|m| code.uses >= m)
        {
            return Err(CodeRefusal::Rejected);
        }
        if !code.allowed_sources.is_empty()
            && !code.allowed_sources.iter().any(|n| n.contains(source))
        {
            return Err(CodeRefusal::Source);
        }
        if code.require_hardware_key && protection != KeyProtection::Hardware {
            return Err(CodeRefusal::HardwareKey);
        }
        code.uses = code.uses.saturating_add(1);
        Ok(code.clone())
    }

    fn remember_nonce(&self, nonce: &[u8], now: Timestamp, expires: Timestamp) -> bool {
        let mut state = self.lock();
        state.nonces.retain(|_, e| *e > now);
        if state.nonces.contains_key(nonce) {
            return false;
        }
        if state.nonces.len() >= MAX_NONCES
            && let Some(oldest) = state
                .nonces
                .iter()
                .min_by_key(|(_, e)| **e)
                .map(|(k, _)| k.clone())
        {
            state.nonces.remove(&oldest);
        }
        state.nonces.insert(nonce.to_vec(), expires);
        true
    }

    fn add_device(&self, device: DeviceRecord) {
        self.lock().devices.insert(device.device, device);
    }

    fn device_by_certificate(&self, serial: &[u8], key_sha256: &Sha256Hex) -> Option<DeviceRecord> {
        self.lock()
            .devices
            .values()
            .find(|d| !d.revoked && d.serial == serial && d.key_sha256 == *key_sha256)
            .cloned()
    }

    fn touch(&self, device: HostId, now: Timestamp) {
        if let Some(d) = self.lock().devices.get_mut(&device) {
            d.last_seen = Some(now);
        }
    }

    fn revoke_device(&self, device: HostId) -> bool {
        self.lock()
            .devices
            .get_mut(&device)
            .map(|d| d.revoked = true)
            .is_some()
    }

    fn published(&self, tenant: TenantId, group: Uuid7) -> Option<Published> {
        self.lock().policies.get(&(tenant, group)).cloned()
    }
}

/// The IDs of every enrolled device, for tests.
#[cfg(test)]
pub(crate) fn ids(store: &MemoryStore) -> std::collections::BTreeSet<HostId> {
    store.devices().into_iter().map(|d| d.device).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ts(s: i64) -> Timestamp {
        Timestamp::from_unix_micros(s * 1_000_000).unwrap()
    }

    fn tenant() -> TenantId {
        TenantId(Uuid7::from_str("019a0000-0000-7000-8000-0000000000aa").unwrap())
    }

    fn group() -> Uuid7 {
        Uuid7::from_str("019a0000-0000-7000-8000-0000000000bb").unwrap()
    }

    fn code(max_uses: Option<u32>) -> CodeRecord {
        CodeRecord {
            tenant: tenant(),
            group: group(),
            expires_at: Some(ts(100)),
            max_uses,
            uses: 0,
            revoked: false,
            allowed_sources: Vec::new(),
            require_hardware_key: false,
        }
    }

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));

    #[test]
    fn codes_are_refused_when_unknown_revoked_expired_or_used_up() {
        let s = MemoryStore::default();
        let h = Sha256Hex::from_bytes([1; 32]);
        let sw = KeyProtection::Software;
        assert_eq!(
            s.consume_code(&h, IP, sw, ts(1)),
            Err(CodeRefusal::Rejected)
        );
        s.add_code(h, code(Some(2)));
        assert_eq!(s.consume_code(&h, IP, sw, ts(1)).unwrap().uses, 1);
        assert_eq!(s.consume_code(&h, IP, sw, ts(1)).unwrap().uses, 2);
        assert_eq!(
            s.consume_code(&h, IP, sw, ts(1)),
            Err(CodeRefusal::Rejected)
        );

        let h2 = Sha256Hex::from_bytes([2; 32]);
        s.add_code(h2, code(None));
        assert_eq!(
            s.consume_code(&h2, IP, sw, ts(100)),
            Err(CodeRefusal::Rejected)
        );
        assert!(s.consume_code(&h2, IP, sw, ts(99)).is_ok());
        assert!(s.revoke_code(&h2));
        assert!(!s.revoke_code(&Sha256Hex::from_bytes([9; 32])));
        assert_eq!(
            s.consume_code(&h2, IP, sw, ts(1)),
            Err(CodeRefusal::Rejected)
        );
    }

    #[test]
    fn source_restrictions_and_hardware_keys_are_enforced_without_taking_a_use() {
        let s = MemoryStore::default();
        let h = Sha256Hex::from_bytes([3; 32]);
        let mut c = code(Some(1));
        c.allowed_sources = vec![IpNet::from_str("10.0.0.0/8").unwrap()];
        c.require_hardware_key = true;
        s.add_code(h, c);
        assert_eq!(
            s.consume_code(&h, IP, KeyProtection::Hardware, ts(1)),
            Err(CodeRefusal::Source)
        );
        let inside: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(
            s.consume_code(&h, inside, KeyProtection::Software, ts(1)),
            Err(CodeRefusal::HardwareKey)
        );
        // Neither refusal took the single use.
        assert!(
            s.consume_code(&h, inside, KeyProtection::Hardware, ts(1))
                .is_ok()
        );
    }

    #[test]
    fn networks_match_by_prefix() {
        let n = IpNet::from_str("192.0.2.0/25").unwrap();
        assert!(n.contains("192.0.2.127".parse().unwrap()));
        assert!(!n.contains("192.0.2.128".parse().unwrap()));
        assert!(n.contains("::ffff:192.0.2.1".parse().unwrap()));
        assert!(!n.contains("2001:db8::1".parse().unwrap()));
        let v6 = IpNet::from_str("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(IpNet::from_str("0.0.0.0/0").unwrap().contains(IP));
        assert!(IpNet::from_str("192.0.2.7").unwrap().contains(IP));
        assert!(IpNet::from_str("192.0.2.0/33").is_err());
        assert!(IpNet::from_str("192.0.2.0/x").is_err());
        assert!(IpNet::from_str("host/8").is_err());
    }

    #[test]
    fn nonces_are_single_use_until_they_expire() {
        let s = MemoryStore::default();
        assert!(s.remember_nonce(b"n", ts(1), ts(10)));
        assert!(!s.remember_nonce(b"n", ts(2), ts(10)));
        assert!(s.remember_nonce(b"n", ts(10), ts(20)));
    }

    #[test]
    fn devices_are_found_by_serial_and_key_until_revoked() {
        let s = MemoryStore::default();
        let id = HostId(Uuid7::from_str("019a0000-0000-7000-8000-000000000001").unwrap());
        let key = Sha256Hex::from_bytes([4; 32]);
        s.add_device(DeviceRecord {
            device: id,
            tenant: tenant(),
            group: group(),
            key_sha256: key,
            serial: vec![1, 2],
            key_protection: KeyProtection::Software,
            hostname: "ws".to_owned(),
            enrolled_at: ts(1),
            last_seen: None,
            revoked: false,
        });
        assert!(s.device_by_certificate(&[1, 2], &key).is_some());
        assert!(s.device_by_certificate(&[1, 3], &key).is_none());
        assert!(
            s.device_by_certificate(&[1, 2], &Sha256Hex::from_bytes([5; 32]))
                .is_none()
        );
        s.touch(id, ts(5));
        assert_eq!(s.devices()[0].last_seen, Some(ts(5)));
        assert_eq!(ids(&s).len(), 1);
        assert!(s.revoke_device(id));
        assert!(s.device_by_certificate(&[1, 2], &key).is_none());
        assert!(!s.revoke_device(HostId(group())));
        assert!(s.published(tenant(), group()).is_none());
        s.publish(
            tenant(),
            group(),
            Published {
                version: 1,
                bundle_hash: key,
                envelope: Arc::from(&b"x"[..]),
            },
        );
        assert_eq!(s.published(tenant(), group()).unwrap().version, 1);
    }
}

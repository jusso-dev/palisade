//! `proptest` strategies for events.
//!
//! [`event`] produces events that pass [`Event::validate`]: the category
//! matches the type, every required field set is present, and the chain rule
//! holds. Tests that want invalid events mutate one of these.

// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::net::IpAddr;

use proptest::collection::vec;
use proptest::option::of;
use proptest::prelude::*;
use proptest::sample::select;

use super::*;

fn bytes<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    vec(any::<u8>(), N).prop_map(|v| {
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    })
}

pub fn uuid7() -> impl Strategy<Value = Uuid7> {
    bytes::<16>().prop_map(|mut b| {
        b[6] = (b[6] & 0x0f) | 0x70;
        b[8] = (b[8] & 0x3f) | 0x80;
        Uuid7::from_bytes(b).unwrap()
    })
}

pub fn timestamp() -> impl Strategy<Value = Timestamp> {
    (Timestamp::MIN.unix_micros()..=Timestamp::MAX.unix_micros())
        .prop_map(|m| Timestamp::from_unix_micros(m).unwrap())
}

fn text<const MAX: usize>() -> impl Strategy<Value = Text<MAX>> {
    "[ -~\u{e9}\u{4e2d}\u{1F6E1}\\\\]{1,40}".prop_map(|s| Text::new(s).unwrap())
}

fn name() -> impl Strategy<Value = Name> {
    text::<256>()
}

fn long() -> impl Strategy<Value = LongText> {
    text::<32_767>()
}

fn token() -> impl Strategy<Value = Token> {
    "[a-z][a-z0-9_]{0,15}".prop_map(|s| s.parse().unwrap())
}

fn sid() -> impl Strategy<Value = Sid> {
    (0u64..(1 << 48), vec(any::<u32>(), 0..=15)).prop_map(|(auth, subs)| {
        palisade_fileid::fsctx::sid::Sid::new(auth, &subs)
            .unwrap()
            .into()
    })
}

fn guid() -> impl Strategy<Value = Guid> {
    bytes::<16>().prop_map(Guid::from_bytes)
}

fn hex_bytes() -> impl Strategy<Value = HexBytes> {
    vec(any::<u8>(), 1..=64).prop_map(|b| HexBytes::new(&b).unwrap())
}

fn ip() -> impl Strategy<Value = IpAddress> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|b| IpAddress(IpAddr::from(b))),
        any::<[u8; 16]>().prop_map(|b| IpAddress(IpAddr::from(b))),
    ]
}

fn labels() -> BoxedStrategy<Labels> {
    proptest::collection::btree_map("[a-z][a-z0-9_.:-]{0,10}", name(), 0..4)
        .prop_map(|m| {
            let map: BTreeMap<LabelKey, Name> = m
                .into_iter()
                .map(|(k, v)| (k.parse().unwrap(), v))
                .collect();
            Labels::new(map).unwrap()
        })
        .boxed()
}

fn hashes() -> BoxedStrategy<Hashes> {
    (
        of(bytes::<32>()),
        of(bytes::<20>()),
        of(bytes::<16>()),
        of(bytes::<32>()),
        of(bytes::<20>()),
    )
        .prop_map(|(a, b, c, d, e)| Hashes {
            sha256: a.map(Hex::from_bytes),
            sha1: b.map(Hex::from_bytes),
            md5: c.map(Hex::from_bytes),
            authenticode_sha256: d.map(Hex::from_bytes),
            authenticode_sha1: e.map(Hex::from_bytes),
        })
        .boxed()
}

fn signer() -> BoxedStrategy<Signer> {
    (
        of(name()),
        of(name()),
        of(hex_bytes()),
        of(hex_bytes()),
        of(hex_bytes()),
        of(any::<bool>()),
        of(timestamp()),
        of(0u8..8),
        of(0u8..15),
        of(0u8..29),
    )
        .prop_map(|(p, i, lt, t, it, cv, ts, st, sl, ve)| Signer {
            publisher: p,
            issuer: i,
            leaf_thumbprint: lt,
            tbs_hash: t,
            issuer_tbs_hash: it,
            chain_valid: cv,
            timestamp: ts,
            signature_type: st,
            signing_level: sl,
            verification_error: ve,
        })
        .boxed()
}

fn signers() -> BoxedStrategy<BoundedVec<Signer, MAX_SIGNERS>> {
    vec(signer(), 0..3)
        .prop_map(|v| BoundedVec::new(v).unwrap())
        .boxed()
}

fn version_info() -> BoxedStrategy<VersionInfo> {
    (
        of(name()),
        of(name()),
        of(name()),
        of(name()),
        of(name()),
        of(name()),
        of(name()),
    )
        .prop_map(|(a, b, c, d, e, f, g)| VersionInfo {
            original_filename: a,
            internal_name: b,
            product_name: c,
            company: d,
            file_version: e,
            product_version: f,
            description: g,
        })
        .boxed()
}

fn origin() -> BoxedStrategy<Origin> {
    (
        of(select(vec![
            Zone::LocalMachine,
            Zone::Intranet,
            Zone::Trusted,
            Zone::Internet,
            Zone::Restricted,
        ])),
        of(long()),
        of(long()),
    )
        .prop_map(|(z, h, r)| Origin {
            motw_zone: z,
            host_url: h,
            referrer_url: r,
        })
        .boxed()
}

type ProcessParts = (
    (
        Option<u32>,
        Option<Name>,
        Option<LongText>,
        Option<LongText>,
        Option<LongText>,
    ),
    (Hashes, BoundedVec<Signer, MAX_SIGNERS>, VersionInfo),
    (
        Option<IntegrityLevel>,
        Option<TokenElevationType>,
        Option<Sid>,
        Option<Origin>,
    ),
);

fn process_parts() -> BoxedStrategy<ProcessParts> {
    (
        (
            of(any::<u32>()),
            of(name()),
            of(long()),
            of(long()),
            of(long()),
        ),
        (hashes(), signers(), version_info()),
        (
            of(select(vec![
                IntegrityLevel::Untrusted,
                IntegrityLevel::Low,
                IntegrityLevel::Medium,
                IntegrityLevel::MediumPlus,
                IntegrityLevel::High,
                IntegrityLevel::System,
                IntegrityLevel::Protected,
            ])),
            of(select(vec![
                TokenElevationType::Default,
                TokenElevationType::Full,
                TokenElevationType::Limited,
            ])),
            of(sid()),
            of(origin()),
        ),
    )
        .boxed()
}

macro_rules! build_process {
    ($ty:ident, $parts:expr, { $($extra:tt)* }) => {{
        let ((pid, key, image, norm, cmd), (hashes, signers, version_info), (il, tet, owner, origin)) = $parts;
        $ty {
            pid,
            process_key: key,
            image_path: image,
            image_path_normalised: norm,
            cmdline: cmd,
            hashes,
            signers,
            version_info,
            integrity_level: il,
            token_elevation_type: tet,
            owner_sid: owner,
            origin,
            $($extra)*
        }
    }};
}

fn process() -> BoxedStrategy<Process> {
    (
        process_parts(),
        of(process_parts()),
        of((of(any::<u32>()), of(name()), of(long()))),
    )
        .prop_map(|(own, parent, grand)| {
            let parent = parent.map(|p| Box::new(build_process!(ParentProcess, p, {})));
            let grandparent = grand.map(|(pid, key, image)| ProcessSummary {
                pid,
                process_key: key,
                image_path: image,
            });
            build_process!(Process, own, { parent, grandparent })
        })
        .boxed()
}

fn file() -> BoxedStrategy<File> {
    (
        (
            of(long()),
            of(long()),
            of(name()),
            of(select(ObjectType::ALL.to_vec())),
            of(any::<u64>()),
        ),
        (
            of(timestamp()),
            of(timestamp()),
            of(sid()),
            hashes(),
            signers(),
            version_info(),
        ),
        (
            of(any::<bool>()),
            of(select(vec![
                DeviceType::Fixed,
                DeviceType::Removable,
                DeviceType::Network,
                DeviceType::Cdrom,
                DeviceType::Virtual,
            ])),
            of(name()),
        ),
    )
        .prop_map(
            |(
                (path, norm, pkg, ot, size),
                (created, modified, owner, hashes, signers, vi),
                (uw, dt, ads),
            )| File {
                path,
                path_normalised: norm,
                package_name: pkg,
                object_type: ot,
                size,
                created,
                modified,
                owner_sid: owner,
                hashes,
                signers,
                version_info: vi,
                user_writable_location: uw,
                device_type: dt,
                ads_name: ads,
            },
        )
        .boxed()
}

fn script() -> BoxedStrategy<Script> {
    (
        prop_oneof![Just((None, true)), long().prop_map(|p| (Some(p), false))],
        of(select(ScriptKind::ALL.to_vec())),
        of(name()),
        of(bytes::<32>()),
        of(select(vec![
            LanguageMode::FullLanguage,
            LanguageMode::ConstrainedLanguage,
            LanguageMode::RestrictedLanguage,
            LanguageMode::NoLanguage,
        ])),
        of(bytes::<32>()),
        of(guid()),
    )
        .prop_map(
            |((path, inline), kind, interp, content, lm, amsi, block)| Script {
                path,
                inline,
                kind,
                interpreter: interp,
                content_sha256: content.map(Hex::from_bytes),
                language_mode: lm,
                amsi_content_sha256: amsi.map(Hex::from_bytes),
                script_block_id: block,
                text: None,
            },
        )
        .boxed()
}

fn native() -> BoxedStrategy<Native> {
    (
        (
            of(any::<u32>()),
            of(0u8..15),
            of(0u8..15),
            of(0u32..2),
            of(name()),
            of(name()),
            of(guid()),
        ),
        (
            of(hex_bytes()),
            of(any::<u32>()),
            of(any::<u32>()),
            of(guid()),
            of(guid()),
            of(name()),
            of(long()),
        ),
        (
            of(hex_bytes()),
            of(long()),
            of(bytes::<32>()),
            of(bytes::<20>()),
            of(any::<bool>()),
            of(any::<bool>()),
            of(any::<bool>()),
        ),
    )
        .prop_map(
            |(
                (sc, rsl, vsl, ss, pn, pi, pg),
                (ph, po, pc, clsid, rg, rn, rs),
                (rh, fq, c256, c1, am, mi, pmi),
            )| Native {
                status_code: sc,
                requested_signing_level: rsl,
                validated_signing_level: vsl,
                signing_scenario: ss,
                policy_name: pn,
                policy_id: pi,
                policy_guid: pg,
                policy_hash: ph,
                policy_options: po,
                policy_count: pc,
                clsid,
                rule_guid: rg,
                rule_name: rn,
                rule_sddl: rs,
                rule_hash: rh,
                fqbn: fq,
                catalog_sha256: c256.map(Hex::from_bytes),
                catalog_sha1: c1.map(Hex::from_bytes),
                policy_audit_mode: am,
                managed_installer_enabled: mi,
                passes_managed_installer: pmi,
            },
        )
        .boxed()
}

fn agent() -> BoxedStrategy<AgentInfo> {
    (
        of(select(vec![
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
        ])),
        of((of(any::<u64>()), of(any::<u64>()), of(any::<u64>()))),
        of(any::<u64>()),
        of(any::<u64>()),
        of(any::<u64>()),
    )
        .prop_map(|(health, cache, t, d, ta)| AgentInfo {
            health,
            cache: cache.map(|(entries, hits, misses)| CacheStats {
                entries,
                hits,
                misses,
            }),
            throttled_count: t,
            dropped_count: d,
            tamper_attempts: ta,
        })
        .boxed()
}

fn user() -> BoxedStrategy<User> {
    (
        (of(sid()), of(name()), of(name()), of(name())),
        (of(any::<u32>()), of(any::<u64>())),
        (
            of(select(vec![
                LogonType::Interactive,
                LogonType::Network,
                LogonType::Batch,
                LogonType::Service,
                LogonType::Unlock,
                LogonType::NetworkCleartext,
                LogonType::NewCredentials,
                LogonType::RemoteInteractive,
                LogonType::CachedInteractive,
                LogonType::CachedRemoteInteractive,
                LogonType::CachedUnlock,
            ])),
            of(any::<bool>()),
            of(any::<bool>()),
        ),
    )
        .prop_map(
            |((sid, name, domain, upn), (session, logon), (lt, admin, elevated))| User {
                sid,
                name,
                domain,
                upn,
                session_id: session,
                logon_id: logon,
                logon_type: lt,
                is_admin: admin,
                elevated,
            },
        )
        .boxed()
}

fn policy_ref() -> BoxedStrategy<PolicyRef> {
    (
        of(uuid7()),
        of(name()),
        of(any::<u64>()),
        of(bytes::<32>()),
        of(uuid7()),
        of(name()),
        of(token()),
        of(uuid7()),
    )
        .prop_map(
            |(id, name, version, hash, rule, rule_name, rule_type, profile)| PolicyRef {
                id: id.map(PolicyId),
                name,
                version,
                hash: hash.map(Hex::from_bytes),
                rule_id: rule.map(RuleId),
                rule_name,
                rule_type,
                profile_id: profile,
            },
        )
        .boxed()
}

fn host() -> BoxedStrategy<Host> {
    (
        uuid7(),
        (
            of(name()),
            of(name()),
            of(name()),
            of(name()),
            of(name()),
            of(name()),
            of(name()),
        ),
        vec(ip(), 0..3),
        vec(name(), 0..3),
    )
        .prop_map(
            |(id, (n, fqdn, domain, os, build, arch, av), ips, groups)| Host {
                id: HostId(id),
                name: n,
                fqdn,
                domain,
                os,
                os_build: build,
                arch,
                agent_version: av,
                ips: BoundedVec::new(ips).unwrap(),
                groups: BoundedVec::new(groups).unwrap(),
            },
        )
        .boxed()
}

fn source() -> BoxedStrategy<Source> {
    (
        select(SourceKind::ALL.to_vec()),
        of(any::<u32>()),
        of(any::<u64>()),
        of(name()),
        of(guid()),
        token(),
        of(name()),
    )
        .prop_map(
            |(kind, event_id, record_id, channel, activity_id, format, rule_name)| Source {
                kind,
                event_id,
                record_id,
                channel,
                activity_id,
                format: (kind == SourceKind::ThirdParty).then_some(format),
                rule_name,
            },
        )
        .boxed()
}

// ---------------------------------------------------------------- 1.1 sets

fn dns_name() -> impl Strategy<Value = DnsName> {
    "[a-z0-9_]([a-z0-9-]{0,8}[a-z0-9])?(\\.[a-z0-9]([a-z0-9_-]{0,8}[a-z0-9_])?){0,3}"
        .prop_map(|s| s.parse().unwrap())
}

fn registry_key() -> impl Strategy<Value = RegistryKey> {
    (
        select(vec![
            "HKEY_LOCAL_MACHINE",
            "HKEY_USERS",
            "HKEY_CURRENT_USER",
            "HKEY_CLASSES_ROOT",
            "HKEY_CURRENT_CONFIG",
        ]),
        vec("[ -\\[\\]-~\u{e9}]{1,12}", 0..4),
    )
        .prop_map(|(root, parts)| {
            let mut key = root.to_owned();
            for p in parts {
                key.push('\\');
                key.push_str(&p);
            }
            key.parse().unwrap()
        })
}

fn json_pointer() -> impl Strategy<Value = JsonPointer> {
    vec("([a-z0-9 ]|~0|~1){0,6}", 1..4).prop_map(|parts| {
        let text: String = parts.iter().map(|p| format!("/{p}")).collect();
        text.parse().unwrap()
    })
}

pub fn json_value() -> BoxedStrategy<JsonValue> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(serde_json::Value::from),
        any::<u64>().prop_map(serde_json::Value::from),
        "[ -~\u{e9}]{0,12}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
            proptest::collection::btree_map("[a-z~/ ]{0,6}", inner, 0..4)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
    .prop_map(|v| JsonValue::new(v).unwrap())
    .boxed()
}

fn principal() -> BoxedStrategy<Principal> {
    (
        select(vec![
            PrincipalKind::User,
            PrincipalKind::ApiClient,
            PrincipalKind::ServiceAccount,
            PrincipalKind::Scim,
            PrincipalKind::SystemJob,
            PrincipalKind::InstanceOperator,
            PrincipalKind::Agent,
        ]),
        of(name()),
        of(name()),
        of(name()),
        of(sid()),
    )
        .prop_map(|(kind, id, name, upn, sid)| Principal {
            kind,
            id,
            name,
            upn,
            sid,
        })
        .boxed()
}

fn account() -> BoxedStrategy<Account> {
    (of(sid()), of(name()), of(name()), of(long()))
        .prop_map(|(sid, name, domain, dn)| Account {
            sid,
            name,
            domain,
            distinguished_name: dn,
        })
        .boxed()
}

fn network() -> BoxedStrategy<Network> {
    (
        (
            of(select(vec![
                Direction::Inbound,
                Direction::Outbound,
                Direction::Local,
            ])),
            of(any::<u8>()),
            of(ip()),
            of(any::<u16>()),
            of(ip()),
            of(any::<u16>()),
        ),
        (
            of(dns_name()),
            of(select(vec![
                ResolutionMethod::Dns,
                ResolutionMethod::DnsCache,
                ResolutionMethod::HostsFile,
                ResolutionMethod::LocalName,
                ResolutionMethod::TlsSni,
                ResolutionMethod::HttpHost,
                ResolutionMethod::ReverseDns,
                ResolutionMethod::Requested,
            ])),
            of(long()),
            of(long()),
        ),
    )
        .prop_map(|((d, p, li, lp, ri, rp), (host, res, url, unc))| Network {
            direction: d,
            protocol: p,
            local_ip: li,
            local_port: lp,
            remote_ip: ri,
            remote_port: rp,
            resolution: host.as_ref().and(res),
            remote_hostname: host,
            url,
            unc,
        })
        .boxed()
}

fn device() -> BoxedStrategy<Device> {
    (
        of(select(vec![
            DeviceInterface::Usb,
            DeviceInterface::Thunderbolt,
            DeviceInterface::Firewire,
            DeviceInterface::Bluetooth,
            DeviceInterface::SdCard,
            DeviceInterface::Sata,
            DeviceInterface::Nvme,
            DeviceInterface::Serial,
            DeviceInterface::Other,
        ])),
        of(select(vec![
            DeviceClass::Storage,
            DeviceClass::Hid,
            DeviceClass::Network,
            DeviceClass::Imaging,
            DeviceClass::Media,
            DeviceClass::Printer,
            DeviceClass::SmartCard,
            DeviceClass::Portable,
            DeviceClass::Optical,
            DeviceClass::Other,
        ])),
        of(any::<u16>()),
        of(any::<u16>()),
        of(name()),
        of(name()),
        of(name()),
        of(select(vec![
            EncryptionState::Encrypted,
            EncryptionState::Unencrypted,
            EncryptionState::Suspended,
            EncryptionState::InProgress,
        ])),
    )
        .prop_map(|(i, c, v, p, s, f, id, e)| Device {
            interface: i,
            class: c,
            vendor_id: v,
            product_id: p,
            serial: s,
            friendly_name: f,
            instance_id: id,
            encryption: e,
        })
        .boxed()
}

fn registry_data() -> BoxedStrategy<RegistryData> {
    (
        of(select(vec![
            RegistryValueType::None,
            RegistryValueType::String,
            RegistryValueType::ExpandString,
            RegistryValueType::Binary,
            RegistryValueType::Dword,
            RegistryValueType::DwordBigEndian,
            RegistryValueType::Link,
            RegistryValueType::MultiString,
            RegistryValueType::ResourceList,
            RegistryValueType::FullResourceDescriptor,
            RegistryValueType::ResourceRequirementsList,
            RegistryValueType::Qword,
        ])),
        of(any::<u32>()),
        of(bytes::<32>()),
        of(text::<1024>()),
        any::<bool>(),
    )
        .prop_map(|(t, size, hash, preview, truncated)| RegistryData {
            value_type: t,
            size,
            sha256: hash.map(Hex::from_bytes),
            truncated: truncated && preview.is_some(),
            preview,
        })
        .boxed()
}

fn registry() -> BoxedStrategy<Registry> {
    (
        of(registry_key()),
        prop_oneof![
            Just((None, false)),
            Just((None, true)),
            text::<16_383>().prop_map(|n| (Some(n), false)),
        ],
        of(select(vec![
            RegistryOperation::CreateKey,
            RegistryOperation::DeleteKey,
            RegistryOperation::SetValue,
            RegistryOperation::DeleteValue,
            RegistryOperation::ReadKey,
            RegistryOperation::ReadValue,
        ])),
        of(registry_data()),
        of(registry_data()),
    )
        .prop_map(
            |(key, (value_name, default_value), op, old, new)| Registry {
                key,
                value_name,
                default_value,
                operation: op,
                old,
                new,
            },
        )
        .boxed()
}

fn elevation() -> BoxedStrategy<Elevation> {
    (
        of(select(vec![
            ElevationMethod::Jit,
            ElevationMethod::OnDemand,
            ElevationMethod::Auto,
            ElevationMethod::ChallengeResponse,
            ElevationMethod::UacReplacement,
        ])),
        of(name()),
        of(text::<1024>()),
        of(principal()),
        of(uuid7()),
        of(any::<u64>()),
    )
        .prop_map(|(m, tp, j, a, r, d)| Elevation {
            method: m,
            token_profile: tp,
            justification: j,
            approver: a,
            request_id: r,
            duration_seconds: d,
        })
        .boxed()
}

fn approval() -> BoxedStrategy<Approval> {
    (
        (
            of(uuid7()),
            of(select(vec![
                ApprovalKind::Execute,
                ApprovalKind::Install,
                ApprovalKind::Elevate,
                ApprovalKind::Device,
                ApprovalKind::Network,
                ApprovalKind::Exception,
                ApprovalKind::Override,
            ])),
            of(select(vec![
                ApprovalScope::Once,
                ApprovalScope::UserOnDevice,
                ApprovalScope::Device,
                ApprovalScope::User,
                ApprovalScope::DeviceGroup,
                ApprovalScope::Tenant,
            ])),
            of(any::<u64>()),
            of(select(vec![
                ApprovalDecision::Pending,
                ApprovalDecision::Approved,
                ApprovalDecision::Denied,
                ApprovalDecision::Expired,
                ApprovalDecision::Cancelled,
            ])),
        ),
        (
            of(principal()),
            of(select(vec![
                ApprovalChannel::Console,
                ApprovalChannel::Email,
                ApprovalChannel::Chat,
                ApprovalChannel::Itsm,
                ApprovalChannel::Mobile,
                ApprovalChannel::OfflineCode,
            ])),
            of(text::<1024>()),
            of(name()),
        ),
    )
        .prop_map(
            |((id, kind, scope, dur, dec), (by, ch, reason, ticket))| Approval {
                request_id: id,
                kind,
                requested_scope: scope,
                duration_seconds: dur,
                decision: dec,
                decided_by: by,
                channel: ch,
                reason,
                ticket_ref: ticket,
            },
        )
        .boxed()
}

fn change() -> BoxedStrategy<Change> {
    (
        select(vec![ChangeOp::Add, ChangeOp::Remove, ChangeOp::Replace]),
        json_pointer(),
        json_value(),
        json_value(),
    )
        .prop_map(|(op, path, a, b)| Change {
            op,
            path,
            old: (op != ChangeOp::Add).then_some(a),
            new: (op != ChangeOp::Remove).then_some(b),
        })
        .boxed()
}

fn admin() -> BoxedStrategy<Admin> {
    (
        (
            of(principal()),
            of(select(vec![
                AdminChannel::Console,
                AdminChannel::Api,
                AdminChannel::Cli,
                AdminChannel::Scim,
                AdminChannel::WebhookCallback,
                AdminChannel::EmailLink,
                AdminChannel::Chat,
                AdminChannel::Itsm,
                AdminChannel::Job,
                AdminChannel::Agent,
            ])),
            of(ip()),
            of(text::<1024>()),
            of(token()),
            of(name()),
            of(name()),
        ),
        (
            of(json_value()),
            of(json_value()),
            vec(change(), 0..3),
            of(text::<1024>()),
            of(name()),
            of(uuid7()),
        ),
    )
        .prop_map(
            |(
                (actor, ch, ip, ua, ot, oid, oname),
                (before, after, changes, reason, ticket, corr),
            )| {
                Admin {
                    actor,
                    channel: ch,
                    source_ip: ip,
                    user_agent: ua,
                    object_type: ot,
                    object_id: oid,
                    object_name: oname,
                    before,
                    after,
                    changes: BoundedVec::new(changes).unwrap(),
                    reason,
                    ticket_ref: ticket,
                    correlation_id: corr,
                }
            },
        )
        .boxed()
}

fn identity() -> BoxedStrategy<Identity> {
    (
        of(name()),
        of(name()),
        of(name()),
        of(any::<u32>()),
        of(any::<u32>()),
        of(account()),
        of(select(vec![
            GroupScope::Local,
            GroupScope::Global,
            GroupScope::Universal,
        ])),
        of(account()),
    )
        .prop_map(|(ap, lp, ws, st, sst, group, scope, member)| Identity {
            authentication_package: ap,
            logon_process: lp,
            workstation: ws,
            status_code: st,
            sub_status_code: sst,
            group,
            group_scope: scope,
            member,
        })
        .boxed()
}

fn audit_policy() -> BoxedStrategy<AuditPolicy> {
    (
        of(select(vec![
            AuditCategory::System,
            AuditCategory::LogonLogoff,
            AuditCategory::ObjectAccess,
            AuditCategory::PrivilegeUse,
            AuditCategory::DetailedTracking,
            AuditCategory::PolicyChange,
            AuditCategory::AccountManagement,
            AuditCategory::DirectoryServiceAccess,
            AuditCategory::AccountLogon,
        ])),
        of(guid()),
        vec(
            select(vec![
                AuditPolicyChange::SuccessAdded,
                AuditPolicyChange::SuccessRemoved,
                AuditPolicyChange::FailureAdded,
                AuditPolicyChange::FailureRemoved,
            ]),
            0..6,
        ),
    )
        .prop_map(|(category, guid, changes)| AuditPolicy {
            category,
            subcategory_guid: guid,
            changes: SortedSet::new(changes).unwrap(),
        })
        .boxed()
}

fn restriction() -> BoxedStrategy<Restriction> {
    (
        of(select(vec![
            LanguageMode::FullLanguage,
            LanguageMode::ConstrainedLanguage,
            LanguageMode::RestrictedLanguage,
            LanguageMode::NoLanguage,
        ])),
        of(name()),
        of(long()),
        of(name()),
    )
        .prop_map(|(lm, title, message, id)| Restriction {
            language_mode: lm,
            title,
            message,
            error_id: id,
        })
        .boxed()
}

fn probe() -> BoxedStrategy<Probe> {
    (
        of(token()),
        of(name()),
        of(name()),
        of(select(vec![
            ProbeStatus::Pass,
            ProbeStatus::Fail,
            ProbeStatus::Error,
            ProbeStatus::NotApplicable,
        ])),
        of(json_value()),
        of(json_value()),
        of(text::<1024>()),
    )
        .prop_map(
            |(id, name, control, status, expected, observed, detail)| Probe {
                id,
                name,
                control,
                status,
                expected,
                observed,
                detail,
            },
        )
        .boxed()
}

fn fim() -> BoxedStrategy<Fim> {
    (
        of(select(vec![
            FimChange::Created,
            FimChange::Modified,
            FimChange::Deleted,
            FimChange::Renamed,
            FimChange::PermissionsChanged,
            FimChange::AttributesChanged,
        ])),
        of(long()),
        of(bytes::<32>()),
        of(any::<u64>()),
        of(name()),
    )
        .prop_map(|(change, old_path, hash, size, watch)| Fim {
            change,
            old_path,
            old_sha256: hash.map(Hex::from_bytes),
            old_size: size,
            watch,
        })
        .boxed()
}

/// The 1.1 field sets, each present or not.
#[derive(Clone, Debug)]
struct Sets11 {
    network: Option<Network>,
    device: Option<Device>,
    registry: Option<Registry>,
    elevation: Option<Elevation>,
    approval: Option<Approval>,
    admin: Option<Admin>,
    identity: Option<Identity>,
    audit_policy: Option<AuditPolicy>,
    restriction: Option<Restriction>,
    probe: Option<Probe>,
    fim: Option<Fim>,
}

/// Each 1.1 field set present with probability `1/weight`, so most events
/// stay small.
fn sets_11(always: bool) -> BoxedStrategy<Sets11> {
    fn maybe<T: std::fmt::Debug + Clone + 'static>(
        s: BoxedStrategy<T>,
        always: bool,
    ) -> BoxedStrategy<Option<T>> {
        if always {
            s.prop_map(Some).boxed()
        } else {
            proptest::option::weighted(0.2, s).boxed()
        }
    }
    (
        (
            maybe(network(), always),
            maybe(device(), always),
            maybe(registry(), always),
            maybe(elevation(), always),
            maybe(approval(), always),
            maybe(admin(), always),
        ),
        (
            maybe(identity(), always),
            maybe(audit_policy(), always),
            maybe(restriction(), always),
            maybe(probe(), always),
            maybe(fim(), always),
        ),
    )
        .prop_map(
            |(
                (network, device, registry, elevation, approval, admin),
                (identity, audit_policy, restriction, probe, fim),
            )| {
                Sets11 {
                    network,
                    device,
                    registry,
                    elevation,
                    approval,
                    admin,
                    identity,
                    audit_policy,
                    restriction,
                    probe,
                    fim,
                }
            },
        )
        .boxed()
}

/// Any valid event.
pub fn event() -> BoxedStrategy<Event> {
    (
        (
            select(EventType::ALL.to_vec()),
            uuid7(),
            token(),
            select(vec![
                Outcome::Allowed,
                Outcome::Blocked,
                Outcome::Audited,
                Outcome::Elevated,
                Outcome::Cancelled,
                Outcome::Failed,
                Outcome::Info,
            ]),
            (0u8..=10),
            of(select(vec![
                EventMode::Enforce,
                EventMode::Monitor,
                EventMode::Audit,
                EventMode::Learning,
                EventMode::Maintenance,
                EventMode::Simulate,
            ])),
            text::<1024>(),
        ),
        (
            timestamp(),
            of(any::<u64>()),
            any::<bool>(),
            of(any::<i64>()),
            uuid7(),
            host(),
        ),
        (
            prop_oneof![Just(0u64), 1u64..],
            bytes::<32>(),
            labels(),
            of(source()),
        ),
        (
            of(user()),
            of(policy_ref()),
            of(process()),
            of(file()),
            of(script()),
            of(native()),
            of(agent()),
        ),
        (
            user(),
            policy_ref(),
            process(),
            file(),
            script(),
            native(),
            agent(),
        ),
        (sets_11(false), sets_11(true), of(long()), any::<bool>()),
    )
        .prop_map(
            |(
                (event_type, event_id, action, outcome, severity, mode, description),
                (ts, mono, synced, skew, tenant, host),
                (seq, prev, labels, source),
                (user, policy, process, file, script, native, agent),
                (u2, p2, pr2, f2, s2, n2, a2),
                (sets, full, script_text, label_oldest),
            )| {
                let mut event = Event {
                    schema_version: CURRENT,
                    event_id,
                    event_type,
                    category: event_type.category(),
                    action,
                    outcome,
                    severity: Severity::new(severity).unwrap(),
                    mode,
                    description,
                    ts,
                    ts_agent_monotonic: mono,
                    clock_synced: synced,
                    clock_skew_ms: skew,
                    tenant_id: TenantId(tenant),
                    host,
                    user,
                    policy,
                    seq,
                    prev_hash: (seq != 0).then(|| Hex::from_bytes(prev)),
                    labels,
                    source,
                    process,
                    file,
                    script,
                    native,
                    agent,
                    network: sets.network,
                    device: sets.device,
                    registry: sets.registry,
                    elevation: sets.elevation,
                    approval: sets.approval,
                    admin: sets.admin,
                    identity: sets.identity,
                    audit_policy: sets.audit_policy,
                    restriction: sets.restriction,
                    probe: sets.probe,
                    fim: sets.fim,
                };
                if let Some(s) = event.script.as_mut() {
                    s.text = script_text;
                }
                // Fill every field set the type requires.
                for &set in event_type.required() {
                    match set {
                        FieldSet::User => {
                            event.user.get_or_insert(u2.clone());
                        }
                        FieldSet::Policy => {
                            event.policy.get_or_insert(p2.clone());
                        }
                        FieldSet::Process => {
                            event.process.get_or_insert(pr2.clone());
                        }
                        FieldSet::File => {
                            event.file.get_or_insert(f2.clone());
                        }
                        FieldSet::Script => {
                            event.script.get_or_insert(s2.clone());
                        }
                        FieldSet::Native => {
                            event.native.get_or_insert(n2.clone());
                        }
                        FieldSet::Agent => {
                            event.agent.get_or_insert(a2.clone());
                        }
                        FieldSet::Network => {
                            event.network.get_or_insert(full.network.clone().unwrap());
                        }
                        FieldSet::Device => {
                            event.device.get_or_insert(full.device.clone().unwrap());
                        }
                        FieldSet::Registry => {
                            event.registry.get_or_insert(full.registry.clone().unwrap());
                        }
                        FieldSet::Elevation => {
                            event
                                .elevation
                                .get_or_insert(full.elevation.clone().unwrap());
                        }
                        FieldSet::Approval => {
                            event.approval.get_or_insert(full.approval.clone().unwrap());
                        }
                        FieldSet::Admin => {
                            event.admin.get_or_insert(full.admin.clone().unwrap());
                        }
                        FieldSet::Identity => {
                            event.identity.get_or_insert(full.identity.clone().unwrap());
                        }
                        FieldSet::AuditPolicy => {
                            event
                                .audit_policy
                                .get_or_insert(full.audit_policy.clone().unwrap());
                        }
                        FieldSet::Restriction => {
                            event
                                .restriction
                                .get_or_insert(full.restriction.clone().unwrap());
                        }
                        FieldSet::Probe => {
                            event.probe.get_or_insert(full.probe.clone().unwrap());
                        }
                        FieldSet::Fim => {
                            event.fim.get_or_insert(full.fim.clone().unwrap());
                        }
                    }
                }
                // Label an event with the oldest version it fits, sometimes,
                // so 1.0 events are generated too.
                if label_oldest {
                    event.schema_version = event.min_version();
                }
                event
            },
        )
        .boxed()
}

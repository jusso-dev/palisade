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
        select(vec![
            SourceKind::OsCodeIntegrity,
            SourceKind::OsLegacyRuleCollection,
            SourceKind::OsSecurity,
            SourceKind::OsPowershell,
        ]),
        of(any::<u32>()),
        of(any::<u64>()),
        of(name()),
        of(guid()),
    )
        .prop_map(|(kind, event_id, record_id, channel, activity_id)| Source {
            kind,
            event_id,
            record_id,
            channel,
            activity_id,
        })
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
    )
        .prop_map(
            |(
                (event_type, event_id, action, outcome, severity, mode, description),
                (ts, mono, synced, skew, tenant, host),
                (seq, prev, labels, source),
                (user, policy, process, file, script, native, agent),
                (u2, p2, pr2, f2, s2, n2, a2),
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
                };
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
                    }
                }
                event
            },
        )
        .boxed()
}

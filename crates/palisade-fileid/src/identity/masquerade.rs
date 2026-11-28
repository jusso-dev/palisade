//! Renamed and masquerading binary detection.
//!
//! Rules and blocklists match on `OriginalFilename`, not on the on-disk
//! name, so a renamed protected binary is still caught by them. This
//! assessment adds visibility: it says why a file looks like it is
//! pretending to be something else, so alerting (#7) can surface it. It
//! never allows or blocks anything itself.
//!
//! Each check adds a fixed weight once, and the score is the sum, capped at
//! 100:
//!
//! | Reason | Weight | When |
//! |---|---|---|
//! | `known_binary_relocated` | 70 renamed, 40 moved only | `OriginalFilename` names a protected binary, its expected signer vouches for the file, and the on-disk name is not one of its names or the path is outside its expected folders |
//! | `protected_name_claimed` | 70 | `OriginalFilename` names a protected binary, but its expected signer does not vouch for the file |
//! | `signer_impersonation` | 60 | `CompanyName` or `ProductName` names a protected vendor, and that vendor's signer does not vouch for the file |
//! | `bidi_control` | 60 | a path component holds a bidirectional control character (such as the right-to-left override) |
//! | `double_extension` | 50 | a decoy document extension before an executable one (`invoice.pdf.exe`), in the file's name or a stream's |
//! | `alternate_data_stream` | 50 | the path names an alternate data stream of a file (`notes.txt:run.exe`) |
//! | `homoglyph` | 40 | a path component mixes Latin letters with characters that look like them |
//! | `extension_mismatch` | 30 | PE content behind an extension the OS does not load PE files under |
//! | `trailing_dot_or_space` | 30 | a path component ends with a dot or a space, which Win32 drops |
//! | `name_mismatch` | 20 | the on-disk name differs from `OriginalFilename` and `InternalName` |
//!
//! A check whose input was not computed (a tier that was not requested or
//! failed, or a context without known folders) is named in
//! [`Masquerade::unassessed`] instead of being read as clean.

#![forbid(unsafe_code)]

use crate::authenticode::TrustConfig;
use crate::fsctx::{KnownFolders, NormalizedPath, PathVariable, fold_case, normalize_win32};

use super::protected::{ExpectedDir, ProtectedBinary, ProtectedList, original_name_key};
use super::record::{Field, FileIdentity, Masquerade, MasqueradeReason, SigningStateKind};

/// Extensions the OS loads or runs PE images under. PE content under any
/// other extension is an `extension_mismatch`.
const PE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "com", "efi", "mui", "mun", "ax", "acm",
    "tsp", "ime", "winmd", "node", "pyd", "xll", "rll", "fon", "tlb", "olb",
];

/// Characters that render like a Latin letter: Cyrillic and Greek letters
/// from the Unicode confusables data, and the fullwidth Latin letters.
const CONFUSABLES: &[(char, char)] = &[
    ('\u{0430}', 'a'),
    ('\u{0435}', 'e'),
    ('\u{043e}', 'o'),
    ('\u{0440}', 'p'),
    ('\u{0441}', 'c'),
    ('\u{0443}', 'y'),
    ('\u{0445}', 'x'),
    ('\u{0455}', 's'),
    ('\u{0456}', 'i'),
    ('\u{0458}', 'j'),
    ('\u{04bb}', 'h'),
    ('\u{0501}', 'd'),
    ('\u{0410}', 'A'),
    ('\u{0412}', 'B'),
    ('\u{0415}', 'E'),
    ('\u{041a}', 'K'),
    ('\u{041c}', 'M'),
    ('\u{041d}', 'H'),
    ('\u{041e}', 'O'),
    ('\u{0420}', 'P'),
    ('\u{0421}', 'C'),
    ('\u{0422}', 'T'),
    ('\u{0425}', 'X'),
    ('\u{0405}', 'S'),
    ('\u{0406}', 'I'),
    ('\u{0408}', 'J'),
    ('\u{03bf}', 'o'),
    ('\u{03bd}', 'v'),
    ('\u{0391}', 'A'),
    ('\u{0392}', 'B'),
    ('\u{0395}', 'E'),
    ('\u{0396}', 'Z'),
    ('\u{0397}', 'H'),
    ('\u{0399}', 'I'),
    ('\u{039a}', 'K'),
    ('\u{039c}', 'M'),
    ('\u{039d}', 'N'),
    ('\u{039f}', 'O'),
    ('\u{03a1}', 'P'),
    ('\u{03a4}', 'T'),
    ('\u{03a5}', 'Y'),
    ('\u{03a7}', 'X'),
    // Palochka, dotless i, Armenian o.
    ('\u{04cf}', 'l'),
    ('\u{0131}', 'i'),
    ('\u{0585}', 'o'),
];

/// The Latin letter `c` looks like, if it is a confusable.
fn confusable(c: char) -> Option<char> {
    if let Some((_, latin)) = CONFUSABLES.iter().find(|(k, _)| *k == c) {
        return Some(*latin);
    }
    // Fullwidth A-Z and a-z.
    let code = u32::from(c);
    match code {
        0xff21..=0xff3a | 0xff41..=0xff5a => char::from_u32(code - 0xff21 + u32::from(b'A')),
        _ => None,
    }
}

/// Bidirectional formatting characters: embeddings, overrides, isolates and
/// marks.
const fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

fn code_point(c: char) -> String {
    format!("U+{:04X}", u32::from(c))
}

/// Assesses `id`. `trust` is the code-signing trust configuration `id` was
/// computed with, which says whether an expected signer can be recognised.
/// `folders` are the known folders of the machine the path is on, for the
/// location check; without them it is unassessed.
#[must_use]
pub fn assess(
    id: &FileIdentity,
    list: &ProtectedList,
    trust: &TrustConfig,
    folders: Option<&KnownFolders>,
) -> Masquerade {
    let mut m = Masquerade::default();
    let mut add = |reason: MasqueradeReason| {
        if !m
            .reasons
            .iter()
            .any(|r| std::mem::discriminant(r) == std::mem::discriminant(&reason))
        {
            m.reasons.push(reason);
        }
    };

    let raw_path = id.path.as_deref().or(id.name_hint.as_deref());
    if let Some(raw) = raw_path {
        unicode_checks(raw, &mut add);
    }

    let on_disk = id.name.file_name.as_deref();
    // A name written wholly or partly in lookalike characters that reads
    // as a protected binary's name (`һһ.exe` is caught only here: it has
    // no Latin letter to mix with).
    if let Some(name) = on_disk {
        let reduced: String = name.chars().map(|c| confusable(c).unwrap_or(c)).collect();
        if reduced != name
            && list.binaries_named(&reduced).next().is_some()
            && let Some(c) = name.chars().find(|c| confusable(*c).is_some())
        {
            add(MasqueradeReason::Homoglyph {
                component: name.to_owned(),
                code_point: code_point(c),
                looks_like: confusable(c).unwrap_or(c),
            });
        }
    }
    // Code identified, or run, from a named stream hides behind the host
    // file's name.
    if let (Some(host), Some(stream)) = (on_disk, id.name.stream.as_deref()) {
        add(MasqueradeReason::AlternateDataStream {
            host: host.to_owned(),
            stream: stream.to_owned(),
        });
    }
    let pe = id.pe.computed();
    let signing = id.signing_state.computed();
    // Not PE content (`not_applicable`) leaves nothing to check; a PE tier
    // that did not run leaves the checks open.
    if matches!(id.pe, Field::NotRequested | Field::Unavailable(_)) {
        m.unassessed.extend([
            "name_mismatch",
            "known_binary_relocated",
            "signer_impersonation",
        ]);
    }

    // Executable content behind a name that claims something else: #44's
    // verdict for every content kind, and, for a PE, any extension the OS
    // does not load PE images under (which #44 may call benign, such as
    // `.tmp`).
    let ext = id.name.extension.as_deref().unwrap_or_default();
    match (id.kind.computed(), on_disk) {
        (Some(k), Some(_)) => {
            // The real extension names another kind. A disguise that keeps
            // the right extension (`invoice.pdf.exe`, a bidi override) is
            // reported by its own reason instead.
            let content = match &k.script_kind {
                Some(script) => format!("script:{script}"),
                None => k.content_kind.clone(),
            };
            let deceptive = k.executable_content
                && matches!(k.mismatch_severity.as_str(), "suspicious" | "critical")
                && k.extension_kind != content;
            let pe_elsewhere =
                (pe.is_some() || k.content_kind == "pe") && !PE_EXTENSIONS.contains(&ext);
            if deceptive || pe_elsewhere {
                add(MasqueradeReason::ExtensionMismatch {
                    extension: ext.to_owned(),
                    content_kind: k.content_kind.clone(),
                });
            }
        }
        (None, Some(_)) => m.unassessed.push("extension_mismatch"),
        (_, None) => {}
    }

    if let Some(pe) = pe {
        // An upload without a name cannot be compared with its version
        // resource: the check is open, not passed.
        if on_disk.is_none() && pe.version.is_some() {
            m.unassessed.push("name_mismatch");
        }
        if let (Some(name), Some(v)) = (on_disk, pe.version.as_ref())
            && name_mismatch(
                name,
                v.original_file_name.as_deref(),
                v.internal_name.as_deref(),
            )
        {
            add(MasqueradeReason::NameMismatch {
                on_disk: name.to_owned(),
                original_file_name: v.original_file_name.clone(),
                internal_name: v.internal_name.clone(),
            });
        }

        let trusted_signer = signing
            .filter(|s| s.state == SigningStateKind::Trusted)
            .and_then(|s| s.signer.as_ref());
        // Whether the file's signer is known well enough to say it is not
        // the expected one. An unverified file may be catalog-signed by
        // the expected signer, so it is left unassessed.
        let trust_known = signing.is_some_and(|s| s.state != SigningStateKind::Unverified);
        // A file with no valid signature at all (unsigned, or every
        // signature invalid) cannot be anyone's protected binary, whatever
        // the trust configuration. A signed file can be judged only when
        // the policy can recognise the expected signer; an untrusted but
        // valid signature might be the expected signer's under a policy
        // that trusts it.
        let unsigned = signing.is_some_and(|s| {
            matches!(
                s.state,
                SigningStateKind::Unsigned | SigningStateKind::Invalid
            )
        });
        let judgeable =
            |signer: &super::protected::ExpectedSigner| unsigned || signer.checkable(trust);
        if let Some(v) = pe.version.as_ref() {
            if let Some(original) = v.original_file_name.as_deref() {
                let claimed: Vec<&ProtectedBinary> = list.binaries_named(original).collect();
                if !claimed.is_empty() {
                    m.claims_protected = Some(original.to_owned());
                    if !trust_known {
                        m.unassessed.push("known_binary_relocated");
                    } else if let Some(binary) = claimed
                        .iter()
                        .find(|b| trusted_signer.is_some_and(|s| b.signer.matches(s)))
                    {
                        let renamed = on_disk.is_some_and(|n| {
                            !binary
                                .file_names
                                .iter()
                                .any(|f| fold_case(f) == fold_case(n.trim_end_matches(['.', ' '])))
                        });
                        let moved = match located(id, binary, folders) {
                            Some(inside) => !inside,
                            None => {
                                if !binary.expected_dirs.is_empty() {
                                    m.unassessed.push("known_binary_location");
                                }
                                false
                            }
                        };
                        if renamed || moved {
                            add(MasqueradeReason::KnownBinaryRelocated {
                                binary: original.to_owned(),
                                renamed,
                                moved,
                            });
                        }
                    } else if !claimed.iter().any(|b| judgeable(&b.signer)) {
                        // Signed, but the policy gives no way to tell whether
                        // this is the expected signer (no well-known root
                        // table, say): neither a rename nor an impostor can be
                        // concluded.
                        m.unassessed.push("known_binary_relocated");
                    } else {
                        add(MasqueradeReason::ProtectedNameClaimed {
                            binary: original.to_owned(),
                        });
                    }
                }
            }
            if !list.vendors.is_empty() {
                if trust_known {
                    for (field, value) in [
                        ("company_name", v.company_name.as_deref()),
                        ("product_name", v.product_name.as_deref()),
                    ] {
                        let Some(value) = value else { continue };
                        for vendor in &list.vendors {
                            let claims = vendor.names.iter().find(|n| contains_word(value, n));
                            let vouched = trusted_signer.is_some_and(|s| vendor.signer.matches(s));
                            if claims.is_some() && !vouched && !judgeable(&vendor.signer) {
                                m.unassessed.push("signer_impersonation");
                                continue;
                            }
                            if let (Some(name), false) = (claims, vouched) {
                                add(MasqueradeReason::SignerImpersonation {
                                    vendor: name.clone(),
                                    field,
                                });
                            }
                        }
                    }
                } else if v.company_name.is_some() || v.product_name.is_some() {
                    m.unassessed.push("signer_impersonation");
                }
            }
        }
    }

    non_pe_claims(
        id,
        list,
        trust,
        &mut m.unassessed,
        &mut m.claims_protected,
        &mut add,
    );

    m.unassessed.sort_unstable();
    m.unassessed.dedup();
    m.score = score(&m.reasons);
    m
}

/// The claims a script, installer or package makes about who made it: a
/// protected binary's name in a script's signed metadata, and a protected
/// vendor in an installer's `Manufacturer` or `ProductName` or a package's
/// display names. Only a trusted signer the vendor expects backs them. Not
/// one of these formats, or a deep tier that did not run, leaves nothing to
/// check here; the trust tier not run leaves them open.
fn non_pe_claims(
    id: &FileIdentity,
    list: &ProtectedList,
    trust: &TrustConfig,
    unassessed: &mut Vec<&'static str>,
    claims_protected: &mut Option<String>,
    add: &mut impl FnMut(MasqueradeReason),
) {
    let signing = id.signing_state.computed();
    let trusted_signer = signing
        .filter(|s| s.state == SigningStateKind::Trusted)
        .and_then(|s| s.signer.as_ref());
    let trust_known = signing.is_some_and(|s| s.state != SigningStateKind::Unverified);
    let unsigned = signing.is_some_and(|s| {
        matches!(
            s.state,
            SigningStateKind::Unsigned | SigningStateKind::Invalid
        )
    });
    let judgeable = |signer: &super::protected::ExpectedSigner| unsigned || signer.checkable(trust);

    // An installer's or package's own record did not run (the deep tier
    // was not requested, or the content could not be read): its vendor
    // claims are open while there are vendors to check them against.
    let content = id.kind.computed().map(|k| k.content_kind.as_str());
    let installer = matches!(content, Some("msi" | "msp" | "mst" | "msm"));
    let package = matches!(
        content,
        Some("msix" | "appx" | "msix_bundle" | "appx_bundle")
    );
    if !list.vendors.is_empty()
        && ((installer && !id.installer.is_computed()) || (package && !id.package.is_computed()))
    {
        unassessed.push("signer_impersonation");
    }
    // A validly signed script whose record did not run: its signed
    // metadata may claim a protected binary, so that check is open.
    let signed = signing.is_some_and(|s| s.embedded == super::record::EmbeddedState::Valid);
    let script = id.kind.computed().is_some_and(|k| k.script_kind.is_some());
    if script && signed && !id.script.is_computed() {
        unassessed.push("known_binary_relocated");
    }

    // A script's signed metadata may name a protected binary: whoever
    // signed it, the script is not that binary, and only the binary's own
    // expected signer could vouch for the claim.
    let script_original = id
        .script
        .computed()
        .and_then(|s| s.signed_metadata.as_ref())
        .and_then(|m| m.original_filename.as_deref());
    if let Some(original) = script_original
        && list.binaries_named(original).next().is_some()
    {
        *claims_protected = Some(original.to_owned());
        add(MasqueradeReason::ProtectedNameClaimed {
            binary: original.to_owned(),
        });
    }

    let claims: Vec<(&'static str, &str)> = if let Some(i) = id.installer.computed() {
        [
            ("manufacturer", i.manufacturer.as_deref()),
            ("product_name", i.product_name.as_deref()),
        ]
        .into_iter()
        .filter_map(|(f, v)| v.map(|v| (f, v)))
        .collect()
    } else if let Some(p) = id.package.computed() {
        [
            (
                "publisher_display_name",
                p.publisher_display_name.as_deref(),
            ),
            ("display_name", p.display_name.as_deref()),
        ]
        .into_iter()
        .filter_map(|(f, v)| v.map(|v| (f, v)))
        .collect()
    } else {
        Vec::new()
    };
    // Only a claim that names a protected vendor needs a signer to back it.
    for (field, value) in claims {
        for vendor in &list.vendors {
            let Some(name) = vendor.names.iter().find(|n| contains_word(value, n)) else {
                continue;
            };
            let vouched = trusted_signer.is_some_and(|s| vendor.signer.matches(s));
            if vouched {
                continue;
            }
            if !trust_known {
                // It may be catalog-signed by the vendor.
                unassessed.push("signer_impersonation");
            } else if judgeable(&vendor.signer) {
                add(MasqueradeReason::SignerImpersonation {
                    vendor: name.clone(),
                    field,
                });
            } else {
                unassessed.push("signer_impersonation");
            }
        }
    }
}

/// The weight of each reason.
const fn weight(reason: &MasqueradeReason) -> u16 {
    match reason {
        MasqueradeReason::KnownBinaryRelocated { renamed: true, .. }
        | MasqueradeReason::ProtectedNameClaimed { .. } => 70,
        MasqueradeReason::SignerImpersonation { .. } | MasqueradeReason::BidiControl { .. } => 60,
        MasqueradeReason::DoubleExtension { .. } | MasqueradeReason::AlternateDataStream { .. } => {
            50
        }
        MasqueradeReason::KnownBinaryRelocated { .. } | MasqueradeReason::Homoglyph { .. } => 40,
        MasqueradeReason::ExtensionMismatch { .. }
        | MasqueradeReason::TrailingDotOrSpace { .. } => 30,
        MasqueradeReason::NameMismatch { .. } => 20,
    }
}

fn score(reasons: &[MasqueradeReason]) -> u8 {
    let total: u16 = reasons.iter().map(weight).sum();
    u8::try_from(total.min(100)).unwrap_or(100)
}

/// The Unicode and name-shape checks, over every component of `raw`.
fn unicode_checks(raw: &str, add: &mut impl FnMut(MasqueradeReason)) {
    // The drive is dropped from the whole path, and the default stream
    // suffix from the last component, as the file-type classifier (#44)
    // reads names.
    let mut components: Vec<&str> = super::record::without_drive(raw)
        .split(['\\', '/'])
        .filter(|c| !c.is_empty() && *c != "." && *c != ".." && *c != "?")
        .collect();
    // The last component is the host file's name and, for a named stream,
    // the stream's name too; every check runs on each.
    let mut names: Vec<&str> = Vec::new();
    if let Some(last) = components.pop() {
        let (host, stream) =
            super::record::split_stream(super::record::without_default_stream(last));
        names.extend(host);
        names.extend(stream);
        components.extend(names.iter().copied());
    }
    for component in &components {
        if let Some(c) = component.chars().find(|c| is_bidi_control(*c)) {
            add(MasqueradeReason::BidiControl {
                component: (*component).to_owned(),
                code_point: code_point(c),
            });
        }
        // Mixed scripts within one dot-separated label of the name: an
        // all-Cyrillic name with a Latin extension (`отчет.tar.gz`) is a
        // name, while `ex\u{0430}mple.exe` mixes them in one label.
        let mixed = component.split('.').find_map(|label| {
            if !label.chars().any(|c| c.is_ascii_alphabetic()) {
                return None;
            }
            label.chars().find_map(|c| confusable(c).map(|l| (c, l)))
        });
        if let Some((c, latin)) = mixed {
            add(MasqueradeReason::Homoglyph {
                component: (*component).to_owned(),
                code_point: code_point(c),
                looks_like: latin,
            });
        }
        if component.ends_with([' ', '.']) {
            add(MasqueradeReason::TrailingDotOrSpace {
                name: (*component).to_owned(),
            });
        }
    }
    for name in names {
        if double_extension(name) {
            add(MasqueradeReason::DoubleExtension {
                name: name.to_owned(),
            });
        }
    }
}

/// `invoice.pdf.exe`, `photo.jpg   .scr`, `report.txt.ps1` and the like:
/// the file-type classifier's own rule (#44), so the two never disagree.
fn double_extension(name: &str) -> bool {
    crate::filetype::is_double_extension(std::ffi::OsStr::new(name))
}

/// Whether `haystack` contains `needle` as whole words, ignoring case and
/// spacing.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let hay = crate::pe::NormalizedName::new(haystack);
    let needle = crate::pe::NormalizedName::new(needle);
    let (hay, needle) = (hay.folded(), needle.folded());
    if needle.is_empty() {
        return false;
    }
    hay.match_indices(needle).any(|(at, m)| {
        let before = hay.get(..at).and_then(|s| s.chars().next_back());
        let after = hay.get(at + m.len()..).and_then(|s| s.chars().next());
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// Whether the on-disk name differs from both version-resource names, after
/// the benign differences are taken out. `false` when there is nothing to
/// compare.
fn name_mismatch(on_disk: &str, original: Option<&str>, internal: Option<&str>) -> bool {
    let disk = stem_key(on_disk);
    // A name that is nothing but benign suffixes (`1234.exe`) is compared
    // whole, so stripping cannot hide a rename.
    let disk = if disk.is_empty() {
        plain_stem(on_disk)
    } else {
        disk
    };
    if disk.is_empty() {
        return false;
    }
    // Blank fields claim nothing and are ignored. A name that is nothing
    // but benign suffixes (`setup.exe`, `64.exe`) is compared whole, as the
    // on-disk name is.
    let claimed: Vec<String> = [original, internal]
        .into_iter()
        .flatten()
        .map(original_name_key)
        .filter(|n| !n.trim().is_empty())
        .map(|n| {
            let key = stem_key(&n);
            if key.is_empty() { plain_stem(&n) } else { key }
        })
        .filter(|k| !k.is_empty())
        .collect();
    if claimed.is_empty() {
        return false;
    }
    if claimed.contains(&disk) || claimed.contains(&plain_stem(on_disk)) {
        return false;
    }
    // The installer family: an installer renamed to another installer name
    // (`setup.exe` for `ProductInstaller.exe`). Both names must be
    // installer names, so a tool whose name merely contains an installer
    // word (`InstallUtil.exe`) is still caught.
    !(is_installer_name(on_disk)
        && [original, internal]
            .into_iter()
            .flatten()
            .map(original_name_key)
            .filter(|n| !n.trim().is_empty())
            .all(|n| is_installer_name(&n)))
}

/// The case-folded name without its extension.
fn plain_stem(name: &str) -> String {
    let folded = fold_case(name.trim().trim_end_matches(['.', ' ']));
    super::record::split_extension(&folded)
        .map_or(folded.as_str(), |(stem, _)| stem)
        .to_owned()
}

/// The case-folded name without its extension and without benign suffixes:
/// copy markers (` (1)`), architecture tags (`_x64`, `64`), version numbers
/// (`-1.2.3`, `v2`) and the installer words.
fn stem_key(name: &str) -> String {
    stem_parts(name).0
}

/// Whether `name` is an installer's name: the suffix rules removed an
/// installer word (`SETUP`, `INSTALL`, `INSTALLER`) from it, as in
/// `setup.exe`, `ProductInstaller.exe` or `product-setup_x64.exe`. A name
/// that only contains the word elsewhere (`InstallUtil.exe`), or that the
/// rules reduce to nothing without one (`64.exe`, `1234.exe`), is not.
fn is_installer_name(name: &str) -> bool {
    stem_parts(name).1
}

/// [`stem_key`], and whether an installer word was removed on the way.
fn stem_parts(name: &str) -> (String, bool) {
    let mut installer = false;
    let folded = fold_case(name.trim().trim_end_matches(['.', ' ']));
    let mut s = super::record::split_extension(&folded).map_or(folded.as_str(), |(stem, _)| stem);
    loop {
        let before = s;
        s = s.trim_end_matches([' ', '.', '_', '-']);
        if let Some(open) = s
            .strip_suffix(')')
            .and_then(|t| t.rfind('(').map(|i| (t, i)))
        {
            let (t, i) = open;
            if t.get(i + 1..)
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
            {
                s = t.get(..i).unwrap_or_default();
            }
        }
        for tag in ["AMD64", "ARM64", "WIN64", "WIN32", "X64", "X86", "64", "32"] {
            if let Some(t) = s.strip_suffix(tag) {
                s = t;
                break;
            }
        }
        let version_start = s
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_digit() || *c == '.' || *c == '_')
            .last()
            .map(|(i, _)| i);
        if let Some(i) = version_start
            && s.get(i..)
                .is_some_and(|v| v.bytes().any(|b| b.is_ascii_digit()))
        {
            s = s.get(..i).unwrap_or_default();
            s = s.strip_suffix('V').unwrap_or(s);
        }
        for word in ["INSTALLER", "INSTALL", "SETUP"] {
            if let Some(t) = s.strip_suffix(word) {
                s = t;
                installer = true;
                break;
            }
        }
        if s == before {
            break;
        }
    }
    (s.to_owned(), installer)
}

/// Whether the file is in one of `binary`'s expected folders. `None` when
/// that cannot be told: no known folders, no fully qualified Windows path,
/// or a binary whose location is not checked.
///
/// The path is the final path of the opened file when known, otherwise the
/// path as given, or as an uploader claimed it ([`super::identify_bytes`]):
/// the assessment is for visibility, so a claimed location is assessed as
/// claimed. Nothing here is used to match a path rule.
fn located(
    id: &FileIdentity,
    binary: &ProtectedBinary,
    folders: Option<&KnownFolders>,
) -> Option<bool> {
    let folders = folders?;
    if binary.expected_dirs.is_empty() {
        return None;
    }
    let info = id.fs.path.computed()?;
    let path = info.rule_path()?;
    let parent = path.parent()?.ok()?;
    // A folder that may still be an unexpanded 8.3 short name cannot be
    // compared; the location stays unassessed rather than "moved".
    if !parent.short_name_candidates().is_empty() {
        return None;
    }
    let parent_key = parent.case_folded();
    // Inside when any expected folder matches. Outside only when every
    // expected folder was resolved and ruled out: one that could not be
    // resolved (missing from the known folders, a short name) might be
    // where the file is, so the location stays unassessed.
    let mut all_resolved = true;
    for dir in &binary.expected_dirs {
        let bases = folders_for(folders, dir.variable);
        if bases.is_empty() {
            all_resolved = false;
        }
        for base in bases {
            match expected_key(base, dir) {
                Some(k) if k == parent_key => return Some(true),
                Some(_) => {}
                None => all_resolved = false,
            }
        }
    }
    all_resolved.then_some(false)
}

fn expected_key(base: &NormalizedPath, dir: &ExpectedDir) -> Option<String> {
    if !base.short_name_candidates().is_empty() {
        return None;
    }
    let mut text = base.to_win32_string();
    for part in &dir.below {
        if !text.ends_with('\\') {
            text.push('\\');
        }
        text.push_str(part);
    }
    normalize_win32(&text).ok().map(|p| p.case_folded())
}

fn folders_for(f: &KnownFolders, v: PathVariable) -> &[NormalizedPath] {
    match v {
        PathVariable::OsDrive => &f.os_drive,
        PathVariable::WinDir => &f.windir,
        PathVariable::System32 => &f.system32,
        PathVariable::ProgramFiles => &f.program_files,
        PathVariable::ProgramData => &f.program_data,
        PathVariable::UserProfile => &f.user_profile,
        PathVariable::AppData => &f.app_data,
        PathVariable::LocalAppData => &f.local_app_data,
        PathVariable::Temp => &f.temp,
        PathVariable::Removable | PathVariable::Hot | PathVariable::Network => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_confusables_are_known() {
        assert_eq!(confusable('\u{04cf}'), Some('l'));
        assert_eq!(confusable('\u{0131}'), Some('i'));
        assert_eq!(confusable('\u{0585}'), Some('o'));
    }

    #[test]
    fn mui_installer_names_count_as_installers() {
        // `SETUP.EXE.MUI` names the installer `setup.exe`: an installer
        // renamed to another installer name is not a mismatch.
        assert!(!name_mismatch(
            "product-setup.exe",
            Some("SETUP.EXE.MUI"),
            None
        ));
    }

    #[test]
    fn mui_original_names_compare_without_the_suffix() {
        // OS binaries whose `OriginalFilename` names their language
        // resource file (`NOTEPAD.EXE.MUI`) are not renamed: the `.MUI`
        // suffix comes off before the comparison, whatever its case.
        for (disk, original) in [
            ("notepad.exe", "NOTEPAD.EXE.MUI"),
            ("notepad.exe", "Notepad.exe.mui"),
            ("Notepad.EXE", "NOTEPAD.EXE.MUI"),
            ("explorer.exe", "EXPLORER.EXE.MUI"),
            ("shell32.dll", "SHELL32.DLL.MUI"),
        ] {
            assert!(
                !name_mismatch(disk, Some(original), None),
                "{disk} vs {original}"
            );
        }
        // The suffix does not hide a rename: a copy named otherwise is still
        // a mismatch, and only a trailing `.MUI` comes off.
        for (disk, original) in [
            ("calc.exe", "NOTEPAD.EXE.MUI"),
            ("notepad.exe", "NOTEPAD.MUI.EXE"),
            ("notepad.exe.mui", "CALC.EXE.MUI"),
        ] {
            assert!(
                name_mismatch(disk, Some(original), None),
                "{disk} vs {original}"
            );
        }
    }

    #[test]
    fn benign_name_differences() {
        for (disk, original) in [
            ("powershell.exe", "PowerShell.EXE"),
            ("tool-0.81.exe", "Tool.exe"),
            ("tool_x64.exe", "tool.exe"),
            ("tool64.exe", "tool.exe"),
            ("Tool (1).exe", "tool.exe"),
            ("toolv2.exe", "tool.exe"),
            ("setup.exe", "ProductInstaller.exe"),
            ("product-setup-1.2.exe", "product.exe"),
            ("shell32.dll", "SHELL32.DLL.MUI"),
        ] {
            assert!(
                !name_mismatch(disk, Some(original), None),
                "{disk} vs {original}"
            );
        }
        assert!(name_mismatch(
            "notepad.exe",
            Some("PowerShell.EXE"),
            Some("POWERSHELL")
        ));
        assert!(!name_mismatch(
            "powershell.exe",
            Some("other.exe"),
            Some("POWERSHELL")
        ));
        assert!(!name_mismatch("x.exe", None, None));
        // Digits alone are not a benign suffix of nothing.
        assert!(name_mismatch("1234.exe", Some("tool.exe"), None));
        // A blank field claims nothing; the other one is still compared.
        assert!(name_mismatch(
            "notepad.exe",
            Some("PowerShell.EXE"),
            Some("")
        ));
        assert!(name_mismatch("notepad.exe", Some(" "), Some("POWERSHELL")));
        assert!(!name_mismatch("notepad.exe", Some(""), Some("  ")));
        // A name the suffix rules reduce to nothing is compared whole.
        assert!(name_mismatch("svchost.exe", Some("setup.exe"), None));
        assert!(name_mismatch("notepad.exe", Some("64.exe"), None));
        assert!(!name_mismatch("setup.exe", Some("setup.exe"), None));
        // A tool whose name only contains an installer word is no installer.
        assert!(name_mismatch("setup.exe", Some("InstallUtil.exe"), None));
        assert!(!name_mismatch(
            "product-setup.exe",
            Some("ProductInstaller.exe"),
            None
        ));
        assert!(!name_mismatch(
            "product-setup_x64.exe",
            Some("setup.exe"),
            None
        ));
        // Names reduced to nothing by suffix rules are not installers.
        for (disk, original) in [
            ("setup.exe", "64.exe"),
            ("1234.exe", "ProductInstaller.exe"),
            ("9999.exe", "1234.exe"),
            ("x86.exe", "64.exe"),
            ("x64.exe", "setup.exe"),
            ("v2.exe", "1234.exe"),
        ] {
            assert!(
                name_mismatch(disk, Some(original), None),
                "{disk} vs {original}"
            );
        }
        assert!(is_installer_name("setup.exe"));
        assert!(is_installer_name("ProductInstaller.exe"));
        assert!(is_installer_name("product-setup_x64.exe"));
        assert!(!is_installer_name("InstallUtil.exe"));
        assert!(!is_installer_name("64.exe"));
        assert!(!is_installer_name("1234.exe"));
    }

    #[test]
    fn unicode_and_shape() {
        let mut found = Vec::new();
        unicode_checks("C:\\Users\\a\\invoice\u{202e}fdp.exe", &mut |r| {
            found.push(r)
        });
        assert!(
            matches!(found.as_slice(), [MasqueradeReason::BidiControl { code_point, .. }] if code_point == "U+202E")
        );

        found.clear();
        unicode_checks("C:\\t\\ex\u{0430}mple.exe", &mut |r| found.push(r));
        assert!(matches!(
            found.as_slice(),
            [MasqueradeReason::Homoglyph {
                looks_like: 'a',
                ..
            }]
        ));

        // A compound Latin extension on an all-Cyrillic name is not mixing.
        found.clear();
        unicode_checks(
            "C:\\t\\\u{043e}\u{0442}\u{0447}\u{0435}\u{0442}.tar.gz",
            &mut |r| found.push(r),
        );
        assert!(found.is_empty(), "{found:?}");
        found.clear();
        unicode_checks("C:\\t\\ex\u{0430}mple.tar.gz", &mut |r| found.push(r));
        assert!(matches!(
            found.as_slice(),
            [MasqueradeReason::Homoglyph { .. }]
        ));

        // An all-Cyrillic name is a name, not a homoglyph trick.
        found.clear();
        unicode_checks(
            "C:\\t\\\u{043e}\u{0442}\u{0447}\u{0435}\u{0442}.exe",
            &mut |r| found.push(r),
        );
        assert!(found.is_empty(), "{found:?}");

        found.clear();
        unicode_checks("C:\\t\\invoice.pdf   .exe", &mut |r| found.push(r));
        assert!(matches!(
            found.as_slice(),
            [MasqueradeReason::DoubleExtension { .. }]
        ));

        for name in [
            "invoice.pdf..exe",
            "invoice.pdf. .exe",
            "photos.zip.exe",
            "report.txt.ps1",
        ] {
            found.clear();
            unicode_checks(&format!("C:\\t\\{name}"), &mut |r| found.push(r));
            assert!(
                found
                    .iter()
                    .any(|r| matches!(r, MasqueradeReason::DoubleExtension { .. })),
                "{name}: {found:?}"
            );
        }
        found.clear();
        unicode_checks("C:\\t\\.pdf.exe", &mut |r| found.push(r));
        assert!(found.is_empty(), "{found:?}");

        // The drive is not a component, and a one-letter file is a file.
        found.clear();
        unicode_checks("C:\u{043e}\u{0442}\u{0447}\u{0435}\u{0442}.exe", &mut |r| {
            found.push(r)
        });
        assert!(found.is_empty(), "{found:?}");
        found.clear();
        unicode_checks("C:\\t\\run.exe. ::$DATA", &mut |r| found.push(r));
        assert!(
            matches!(
                found.as_slice(),
                [MasqueradeReason::TrailingDotOrSpace { .. }]
            ),
            "{found:?}"
        );

        found.clear();
        unicode_checks("C:\\t\\invoice.pdf.exe::$DATA", &mut |r| found.push(r));
        assert!(
            matches!(found.as_slice(), [MasqueradeReason::DoubleExtension { .. }]),
            "{found:?}"
        );

        found.clear();
        unicode_checks("C:\\t\\run.exe. ", &mut |r| found.push(r));
        assert!(matches!(
            found.as_slice(),
            [MasqueradeReason::TrailingDotOrSpace { .. }]
        ));

        found.clear();
        unicode_checks("C:\\t\\archive.tar.gz", &mut |r| found.push(r));
        unicode_checks("C:\\t\\v1.2.exe", &mut |r| found.push(r));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn fullwidth_letters_are_confusable() {
        assert_eq!(confusable('\u{ff41}'), Some('a'));
        assert_eq!(confusable('\u{ff3a}'), Some('Z'));
        assert_eq!(confusable('a'), None);
    }

    #[test]
    fn whole_word_vendor_match() {
        assert!(contains_word("Example  Org Corporation", "example org"));
        assert!(!contains_word("Examples Organisation", "Example Org"));
        assert!(!contains_word("anything", ""));
    }

    #[test]
    fn score_caps_at_100() {
        let reasons = vec![
            MasqueradeReason::ProtectedNameClaimed { binary: "a".into() },
            MasqueradeReason::BidiControl {
                component: "c".into(),
                code_point: "U+202E".into(),
            },
        ];
        assert_eq!(score(&reasons), 100);
        assert_eq!(score(&[]), 0);
    }
}

//! Imports, exports, driver classification, manifests, the elevation
//! heuristic and name normalisation (#45).

// Test code: fixture sizes are small constants, so narrowing casts cannot
// truncate, and helpers may unwrap, since a failure should fail loudly.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use common::*;
use palisade_fileid::pe::manifest::{MAX_DEPTH, MAX_MANIFEST_SIZE, parse_manifest};
use palisade_fileid::pe::{
    self, DriverSignal, ElevationReason, ExecutionLevel, ExportTarget, ImportedFunction,
    ManifestError, NormalizedName, PeInfo, WarningKind,
};
use proptest::prelude::*;

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;

fn put16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// One import: module name and functions (`Ok(name)` by name, `Err(n)` by
/// ordinal).
type Import<'a> = (&'a str, Vec<Result<&'a str, u16>>);

/// A section body holding an import table, for a section at `rva`.
fn import_section(rva: u32, imports: &[Import<'_>], pe32_plus: bool) -> Vec<u8> {
    let thunk = if pe32_plus { 8 } else { 4 };
    let descriptors = (imports.len() + 1) * 20;
    let mut out = vec![0_u8; descriptors];
    for (i, (module, functions)) in imports.iter().enumerate() {
        // Thunk array.
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let thunks_at = out.len();
        out.resize(thunks_at + (functions.len() + 1) * thunk, 0);
        for (j, f) in functions.iter().enumerate() {
            let slot = thunks_at + j * thunk;
            let value: u64 = match f {
                Ok(name) => {
                    while out.len() % 2 != 0 {
                        out.push(0);
                    }
                    let at = out.len();
                    out.extend_from_slice(&(j as u16).to_le_bytes());
                    out.extend_from_slice(name.as_bytes());
                    out.push(0);
                    u64::from(rva + at as u32)
                }
                Err(ordinal) => {
                    if pe32_plus {
                        (1 << 63) | u64::from(*ordinal)
                    } else {
                        (1 << 31) | u64::from(*ordinal)
                    }
                }
            };
            if pe32_plus {
                put64(&mut out, slot, value);
            } else {
                put32(&mut out, slot, value as u32);
            }
        }
        let name_at = out.len();
        out.extend_from_slice(module.as_bytes());
        out.push(0);
        let d = i * 20;
        put32(&mut out, d, rva + thunks_at as u32);
        put32(&mut out, d + 12, rva + name_at as u32);
        put32(&mut out, d + 16, rva + thunks_at as u32);
    }
    out
}

/// A section body holding an export table, for a section at `rva`.
/// `names` must be sorted; `forward` gives forwarder strings by index.
fn export_section(rva: u32, dll: &str, names: &[&str], forward: &[(usize, &str)]) -> Vec<u8> {
    let n = names.len();
    let mut out = vec![0_u8; 40];
    let functions_at = out.len();
    out.resize(functions_at + n * 4, 0);
    let names_at = out.len();
    out.resize(names_at + n * 4, 0);
    let ordinals_at = out.len();
    out.resize(ordinals_at + n * 2, 0);
    let dll_at = out.len();
    out.extend_from_slice(dll.as_bytes());
    out.push(0);
    for (i, name) in names.iter().enumerate() {
        let at = out.len();
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        put32(&mut out, names_at + i * 4, rva + at as u32);
        put16(&mut out, ordinals_at + i * 2, i as u16);
        // Inside .text (RVA 0x1000), so never mistaken for a forwarder.
        put32(&mut out, functions_at + i * 4, 0x1000 + (i as u32 % 0x100));
    }
    for (i, target) in forward {
        let at = out.len();
        out.extend_from_slice(target.as_bytes());
        out.push(0);
        put32(&mut out, functions_at + i * 4, rva + at as u32);
    }
    put32(&mut out, 12, rva + dll_at as u32);
    put32(&mut out, 16, 1); // Base
    put32(&mut out, 20, n as u32);
    put32(&mut out, 24, n as u32);
    put32(&mut out, 28, rva + functions_at as u32);
    put32(&mut out, 32, rva + names_at as u32);
    put32(&mut out, 36, rva + ordinals_at as u32);
    out
}

/// `builder` with an extra section holding `body`, and data directory
/// `index` pointing at the whole section.
fn with_directory(
    mut builder: PeBuilder,
    index: usize,
    body: impl FnOnce(u32) -> Vec<u8>,
) -> Vec<u8> {
    let section = builder.sections.len() + usize::from(builder.debug.is_some());
    assert!(builder.resources.is_empty(), "resources must come last");
    let rva = SECTION_ALIGNMENT * (section as u32 + 1);
    let data = body(rva);
    let size = data.len() as u32;
    builder = builder.section(
        ".idata",
        data,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    let mut image = builder.build();
    let at = builder.data_directory_offset(index);
    put32(&mut image, at, rva);
    put32(&mut image, at + 4, size);
    image
}

fn parse(image: &[u8]) -> PeInfo {
    pe::parse(image).unwrap()
}

// --- Imports. ----------------------------------------------------------------

#[test]
fn imports_are_read_pe32_plus_and_pe32() {
    for pe32_plus in [true, false] {
        let base = if pe32_plus {
            PeBuilder::default()
        } else {
            PeBuilder::pe32()
        };
        let image = with_directory(base, DIR_IMPORT, |rva| {
            import_section(
                rva,
                &[
                    (
                        "KERNEL32.dll",
                        vec![Ok("CreateFileW"), Ok("ReadFile"), Err(17)],
                    ),
                    ("USER32.dll", vec![Ok("MessageBoxW")]),
                ],
                pe32_plus,
            )
        });
        let info = parse(&image);
        assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
        let imports = info.imports.unwrap();
        assert!(!imports.truncated);
        assert_eq!(imports.function_count, 4);
        let names: Vec<_> = imports.modules.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["KERNEL32.dll", "USER32.dll"]);
        assert_eq!(
            imports.modules[0].functions,
            [
                ImportedFunction::Name {
                    name: "CreateFileW".into(),
                    hint: 0
                },
                ImportedFunction::Name {
                    name: "ReadFile".into(),
                    hint: 1
                },
                ImportedFunction::Ordinal(17),
            ]
        );
        assert!(imports.imports_module("kernel32.DLL"));
        assert!(!imports.imports_module("ntdll.dll"));
    }
}

#[test]
fn imported_functions_are_capped_at_ten_thousand() {
    let many: Vec<Result<&str, u16>> = (0..10_050_u16).map(Err).collect();
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        import_section(
            rva,
            &[("a.dll", many.clone()), ("ntoskrnl.exe", vec![Err(1)])],
            true,
        )
    });
    let imports = parse(&image).imports.unwrap();
    assert_eq!(imports.function_count, 10_000);
    assert!(imports.truncated);
    // A module past the cap is still known to be imported.
    assert!(imports.imports_module("ntoskrnl.exe"));
}

#[test]
fn an_unterminated_or_unmapped_import_table_is_reported() {
    let mut image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        import_section(rva, &[("a.dll", vec![Err(1)])], true)
    });
    // Point the directory at unmapped memory.
    let at = PeBuilder::default().data_directory_offset(DIR_IMPORT);
    put32(&mut image, at, 0x00f0_0000);
    let info = parse(&image);
    assert!(info.imports.is_none());
    assert!(info.parse_warnings.iter().any(|w| matches!(
        w.kind,
        WarningKind::DirectoryNotMapped(pe::DataDirectoryKind::Import)
    )));

    // A descriptor table filling its whole mapped section (so no zero fill
    // follows it) with no terminator.
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |_| {
        vec![0xff; SECTION_ALIGNMENT as usize]
    });
    let info = parse(&image);
    let imports = info.imports.unwrap();
    assert!(imports.truncated && imports.modules.is_empty());
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ImportTableTruncated)
    );
}

// --- Exports. ----------------------------------------------------------------

#[test]
fn exports_and_forwarders_are_read() {
    let names = [
        "CPlApplet",
        "DllGetClassObject",
        "DllRegisterServer",
        "Forwarded",
        "ServiceMain",
    ];
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        export_section(rva, "thing.dll", &names, &[(3, "OTHER.Target")])
    });
    let info = parse(&image);
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
    let exports = info.exports.unwrap();
    assert_eq!(exports.dll_name.as_deref(), Some("thing.dll"));
    assert_eq!(exports.exports.len(), 5);
    assert_eq!(exports.exports[3].name.as_deref(), Some("Forwarded"));
    assert_eq!(
        exports.exports[3].target,
        ExportTarget::Forwarder("OTHER.Target".into())
    );
    assert_eq!(exports.exports[0].ordinal, 1);
    assert_eq!(exports.forwarder_count(), 1);
    let n = exports.notable;
    assert!(n.cpl_applet && n.dll_register_server && n.dll_get_class_object && n.service_main);
}

#[test]
fn notable_exports_are_found_past_the_listing_cap() {
    // More names than are listed: the binary search still finds them.
    let mut names: Vec<String> = (0..10_100).map(|i| format!("A{i:05}")).collect();
    names.push("DllRegisterServer".into());
    names.sort();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        export_section(rva, "x.dll", &refs, &[])
    });
    let info = parse(&image);
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
    let exports = info.exports.unwrap();
    assert!(exports.truncated);
    assert_eq!(exports.exports.len(), pe::MAX_EXPORTS);
    assert!(exports.notable.dll_register_server);
    assert!(!exports.notable.cpl_applet);
}

// --- Drivers. ----------------------------------------------------------------

fn native(builder: PeBuilder) -> PeBuilder {
    PeBuilder {
        subsystem: 1,
        ..builder
    }
}

#[test]
fn kernel_drivers_are_classified() {
    let driver = with_directory(native(PeBuilder::default()), DIR_IMPORT, |rva| {
        import_section(
            rva,
            &[
                ("ntoskrnl.exe", vec![Ok("IoCreateDevice")]),
                ("HAL.dll", vec![Err(1)]),
            ],
            true,
        )
    });
    let info = parse(&driver);
    assert!(info.is_kernel_driver());
    assert_eq!(
        info.driver.signals,
        [
            DriverSignal::NativeSubsystem,
            DriverSignal::ImportsKernelModule("ntoskrnl.exe".into()),
            DriverSignal::ImportsKernelModule("hal.dll".into()),
        ]
    );

    // An INIT section alone, or IMAGE_FILE_SYSTEM, is a kernel signal.
    let init = native(PeBuilder::default()).section("INIT", vec![1], IMAGE_SCN_CNT_CODE);
    assert!(parse(&init.build()).is_kernel_driver());
    let system = PeBuilder {
        characteristics: 0x1022,
        ..native(PeBuilder::default())
    };
    assert!(parse(&system.build()).is_kernel_driver());
}

#[test]
fn native_user_mode_and_ordinary_dlls_are_not_drivers() {
    // A native program importing only ntdll.
    let native_app = with_directory(native(PeBuilder::default()), DIR_IMPORT, |rva| {
        import_section(rva, &[("ntdll.dll", vec![Ok("NtClose")])], true)
    });
    let info = parse(&native_app);
    assert!(!info.is_kernel_driver());
    assert_eq!(info.driver.signals, [DriverSignal::NativeSubsystem]);

    // A GUI DLL that imports a kernel module name is still not a driver.
    let dll = with_directory(PeBuilder::dll(), DIR_IMPORT, |rva| {
        import_section(rva, &[("ntoskrnl.exe", vec![Err(1)])], true)
    });
    assert!(!parse(&dll).is_kernel_driver());
    // INITDATA is not INIT.
    let initdata = native(PeBuilder::default()).section("INITDATA", vec![1], IMAGE_SCN_CNT_CODE);
    assert!(!parse(&initdata.build()).is_kernel_driver());
    assert!(!parse(&PeBuilder::default().build()).is_kernel_driver());
}

// --- Manifests. --------------------------------------------------------------

const ELEVATED: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:example:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Palisade.Test.Tool" version="1.2.3.4" processorArchitecture="amd64" publicKeyToken="0123456789abcdef"/>
  <trustInfo xmlns="urn:example:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:example:compatibility.v1"><application>
    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
  </application></compatibility>
  <application xmlns="urn:example:asm.v3"><windowsSettings>
    <autoElevate xmlns="urn:example:settings.2005">true</autoElevate>
    <dpiAware xmlns="urn:example:settings.2005">true/pm</dpiAware>
    <ws2016:dpiAwareness xmlns:ws2016="urn:example:settings.2016">PerMonitorV2</ws2016:dpiAwareness>
  </windowsSettings></application>
</assembly>"#;

fn with_manifest(xml: &[u8]) -> PeBuilder {
    PeBuilder {
        resources: vec![Leaf {
            type_id: 24,
            name_id: 1,
            lang: 0x0409,
            data: xml.to_vec(),
        }],
        ..PeBuilder::default()
    }
}

#[test]
fn manifest_settings_are_read() {
    let info = parse(&with_manifest(ELEVATED.as_bytes()).build());
    let m = info.manifest.as_ref().unwrap();
    assert_eq!(
        m.execution_level,
        Some(ExecutionLevel::RequireAdministrator)
    );
    assert_eq!(m.ui_access, Some(false));
    assert_eq!(m.auto_elevate, Some(true));
    assert_eq!(m.dpi_aware.as_deref(), Some("true/pm"));
    assert_eq!(m.dpi_awareness.as_deref(), Some("PerMonitorV2"));
    let id = m.identity.as_ref().unwrap();
    assert_eq!(id.name.as_deref(), Some("Palisade.Test.Tool"));
    assert_eq!(id.version.as_deref(), Some("1.2.3.4"));
    assert_eq!(id.processor_architecture.as_deref(), Some("amd64"));
    assert_eq!(id.public_key_token.as_deref(), Some("0123456789abcdef"));
    assert_eq!(m.supported_os.len(), 2);
    assert!(!m.truncated);
    let e = info.requires_elevation(Some("tool.exe"));
    assert!(e.requires_elevation);
    assert_eq!(e.reason, ElevationReason::RequireAdministrator);
}

#[test]
fn manifests_with_a_bom_entities_and_mixed_case_parse() {
    let mut xml = b"\xef\xbb\xbf".to_vec();
    xml.extend_from_slice(
        br#"<assembly><assemblyIdentity name="a&amp;b"/><trustInfo><security><requestedPrivileges><requestedExecutionLevel level=" RequireADMINISTRATOR "/></requestedPrivileges></security></trustInfo><application><windowsSettings><autoElevate>&#x74;rue</autoElevate><dpiAware>per &#x6d;onitor</dpiAware><dpiAwareness><![CDATA[PerMonitorV2]]></dpiAwareness></windowsSettings></application></assembly>"#,
    );
    let m = parse_manifest(&xml).unwrap();
    assert_eq!(
        m.execution_level,
        Some(ExecutionLevel::RequireAdministrator)
    );
    assert_eq!(m.auto_elevate, Some(true));
    // Spaces next to a reference survive; CDATA is read.
    assert_eq!(m.dpi_aware.as_deref(), Some("per monitor"));
    assert_eq!(m.dpi_awareness.as_deref(), Some("PerMonitorV2"));
    assert_eq!(m.identity.unwrap().name.as_deref(), Some("a&b"));
    let cdata = br#"<assembly><application><windowsSettings><autoElevate><![CDATA[ true ]]></autoElevate></windowsSettings></application></assembly>"#;
    assert_eq!(parse_manifest(cdata).unwrap().auto_elevate, Some(true));
}

/// A level inside requestedPrivileges, wrapped in an assembly.
fn level_manifest(level: &str) -> String {
    format!(
        r#"<assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel level="{level}"/></requestedPrivileges></security></trustInfo></assembly>"#
    )
}

#[test]
fn settings_count_only_at_their_place_in_the_schema() {
    // A dependency's identity is not the manifest's own, before or without
    // a root identity.
    let dep = r#"<dependency><dependentAssembly><assemblyIdentity name="Dep.Library" publicKeyToken="1111"/></dependentAssembly></dependency>"#;
    let m = parse_manifest(format!("<assembly>{dep}</assembly>").as_bytes()).unwrap();
    assert_eq!(m.identity, None);
    let m = parse_manifest(
        format!(r#"<assembly>{dep}<assemblyIdentity name="Own.App"/></assembly>"#).as_bytes(),
    )
    .unwrap();
    assert_eq!(m.identity.unwrap().name.as_deref(), Some("Own.App"));

    // A decoy level or autoElevate outside its place does not shadow the
    // real one, before or after it.
    let decoy = r#"<requestedExecutionLevel level="asInvoker"/><autoElevate>false</autoElevate>"#;
    let real = r#"<trustInfo><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="true"/></requestedPrivileges></security></trustInfo><application><windowsSettings><autoElevate>true</autoElevate></windowsSettings></application>"#;
    for xml in [
        format!("<assembly>{decoy}{real}</assembly>"),
        format!("<assembly>{real}{decoy}</assembly>"),
        format!("<assembly><other>{decoy}</other>{real}</assembly>"),
    ] {
        let m = parse_manifest(xml.as_bytes()).unwrap();
        assert_eq!(
            m.execution_level,
            Some(ExecutionLevel::RequireAdministrator),
            "{xml}"
        );
        assert_eq!(
            (m.ui_access, m.auto_elevate),
            (Some(true), Some(true)),
            "{xml}"
        );
    }
    // Text in an element nested inside a setting is not the setting.
    let nested = r#"<assembly><application><windowsSettings><autoElevate><x>true</x></autoElevate></windowsSettings></application></assembly>"#;
    assert_eq!(
        parse_manifest(nested.as_bytes()).unwrap().auto_elevate,
        None
    );
    // The first requestedExecutionLevel decides, even without a level.
    let first = r#"<assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel uiAccess="true"/><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>"#;
    let m = parse_manifest(first.as_bytes()).unwrap();
    assert_eq!((m.execution_level, m.ui_access), (None, Some(true)));
}

#[test]
fn padding_cannot_push_a_value_out() {
    let padded = format!("{}requireAdministrator", " ".repeat(5_000));
    let m = parse_manifest(level_manifest(&padded).as_bytes()).unwrap();
    assert_eq!(
        m.execution_level,
        Some(ExecutionLevel::RequireAdministrator)
    );
    let refs = "&#x20;".repeat(5_000);
    let xml = format!(
        "<assembly><application><windowsSettings><autoElevate>{refs}true</autoElevate></windowsSettings></application></assembly>"
    );
    assert_eq!(
        parse_manifest(xml.as_bytes()).unwrap().auto_elevate,
        Some(true)
    );
}

#[test]
fn hostile_manifests_are_rejected() {
    let doctype = br#"<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "xxxxxxxx"><!ENTITY y "&x;&x;&x;">]><assembly>&y;</assembly>"#;
    assert_eq!(parse_manifest(doctype), Err(ManifestError::DocType));
    let deep = format!(
        "{}{}",
        "<a>".repeat(MAX_DEPTH + 1),
        "</a>".repeat(MAX_DEPTH + 1)
    );
    assert_eq!(parse_manifest(deep.as_bytes()), Err(ManifestError::TooDeep));
    // A self-closing element one level too deep is too deep too.
    let deep_empty = format!(
        "{}<b/>{}",
        "<a>".repeat(MAX_DEPTH),
        "</a>".repeat(MAX_DEPTH)
    );
    assert_eq!(
        parse_manifest(deep_empty.as_bytes()),
        Err(ManifestError::TooDeep)
    );
    let big = vec![b' '; MAX_MANIFEST_SIZE + 1];
    assert_eq!(
        parse_manifest(&big),
        Err(ManifestError::TooLarge(MAX_MANIFEST_SIZE + 1))
    );
    assert_eq!(
        parse_manifest(b"\xff\xfe<\0a\0/\0>\0"),
        Err(ManifestError::NotUtf8)
    );
    let many = "<x/>".repeat(pe::manifest::MAX_ELEMENTS);
    assert_eq!(
        parse_manifest(format!("<assembly>{many}</assembly>").as_bytes()),
        Err(ManifestError::TooManyElements)
    );

    // Not well formed, anywhere: every one is an error, never a partial or
    // empty manifest.
    for bad in [
        &b""[..],
        b"not xml",
        b"<assembly><x>",
        b"<assembly><autoElevate>true",
        b"<a></b>",
        b"<a/><b/>",
        b"<assembly><autoElevate>&boom;</autoElevate></assembly>",
        br#"<assembly x="&boom;"></assembly>"#,
        br#"<assembly><requestedExecutionLevel level="asInvoker" x="&boom;"/></assembly>"#,
        br#"<assembly><q a="1" a="2"/></assembly>"#,
        br#"<assembly><q NOT_XML/></assembly>"#,
        b"<assembly/>trailing",
    ] {
        assert!(
            matches!(parse_manifest(bad), Err(ManifestError::Xml(_))),
            "{:?}: {:?}",
            String::from_utf8_lossy(bad),
            parse_manifest(bad)
        );
    }

    // A bad manifest is a warning, not a parse failure.
    let info = parse(&with_manifest(doctype).build());
    assert!(info.manifest.is_none());
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::Manifest(ManifestError::DocType))
    );
}

#[test]
fn a_bad_process_manifest_is_not_replaced_by_a_decoy() {
    // ID 1 is what the OS reads to start the process. If it does not parse
    // here (UTF-16), a UTF-8 decoy at ID 2 must not stand in for it.
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(
        level_manifest("requireAdministrator")
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    let decoy = level_manifest("asInvoker");
    let image = PeBuilder {
        resources: vec![
            Leaf {
                type_id: 24,
                name_id: 1,
                lang: 0x0409,
                data: utf16,
            },
            Leaf {
                type_id: 24,
                name_id: 2,
                lang: 0x0409,
                data: decoy.clone().into_bytes(),
            },
        ],
        ..PeBuilder::default()
    }
    .build();
    let info = parse(&image);
    assert_eq!((info.manifest.as_ref(), info.manifest_id), (None, Some(1)));
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::Manifest(ManifestError::NotUtf8))
    );
    // A DLL with only an ID 2 manifest reports it, and says which it was.
    let image = PeBuilder {
        resources: vec![Leaf {
            type_id: 24,
            name_id: 2,
            lang: 0x0409,
            data: decoy.into_bytes(),
        }],
        ..PeBuilder::dll()
    }
    .build();
    let info = parse(&image);
    assert_eq!(info.manifest_id, Some(2));
    assert_eq!(
        info.manifest.unwrap().execution_level,
        Some(ExecutionLevel::AsInvoker)
    );
}

#[test]
fn limits_bound_the_work() {
    let many: String = (0..100)
        .map(|i| format!(r#"<supportedOS Id="{i}"/>"#))
        .collect();
    let xml = format!(
        "<assembly><compatibility><application>{many}</application></compatibility></assembly>"
    );
    let m = parse_manifest(xml.as_bytes()).unwrap();
    assert_eq!(m.supported_os.len(), pe::manifest::MAX_SUPPORTED_OS);
    assert!(m.truncated);
    let long = "x".repeat(5000);
    let m = parse_manifest(
        format!(r#"<assembly><assemblyIdentity name="{long}"/></assembly>"#).as_bytes(),
    )
    .unwrap();
    assert_eq!(
        m.identity.unwrap().name.unwrap().len(),
        pe::manifest::MAX_VALUE_LEN
    );
}

proptest! {
    /// Arbitrary bytes never panic the manifest parser.
    #[test]
    fn manifest_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let _ = parse_manifest(&bytes);
    }
}

// --- The elevation heuristic. ---------------------------------------------------

#[test]
fn elevation_heuristic() {
    let plain = parse(&PeBuilder::default().build());
    let e = plain.requires_elevation(Some("MySetup.exe"));
    assert!(e.requires_elevation);
    assert_eq!(e.reason, ElevationReason::InstallerFileName("setup"));
    let e = plain.requires_elevation(Some("notepad.exe"));
    assert_eq!(
        (e.requires_elevation, e.reason),
        (false, ElevationReason::None)
    );

    // Version info mentioning installation.
    let version = VersionSpec {
        fixed: Some(fixed_info((1, 0, 0, 0), (1, 0, 0, 0))),
        tables: vec![(
            "040904B0",
            vec![string("FileDescription", "Product Installer")],
        )],
        translations: vec![(0x0409, 0x04b0)],
    };
    let info = parse(&with_version(&version).build());
    let e = info.requires_elevation(Some("tool.exe"));
    assert_eq!(
        e.reason,
        ElevationReason::InstallerVersionInfo("FileDescription")
    );

    // asInvoker in a manifest overrides the name heuristics.
    let invoker = level_manifest("asInvoker");
    let info = parse(&with_manifest(invoker.as_bytes()).build());
    let e = info.requires_elevation(Some("setup.exe"));
    assert_eq!(
        (e.requires_elevation, e.reason),
        (false, ElevationReason::ManifestAsInvoker)
    );
    let highest = level_manifest("highestAvailable");
    let e = parse(&with_manifest(highest.as_bytes()).build()).requires_elevation(None);
    assert_eq!(e.reason, ElevationReason::HighestAvailable);
    // An unknown level is not asInvoker: the installer heuristics apply.
    let odd = level_manifest("elevateMaybe");
    let info = parse(&with_manifest(odd.as_bytes()).build());
    let e = info.requires_elevation(Some("setup.exe"));
    assert_eq!(
        (e.requires_elevation, e.reason),
        (true, ElevationReason::InstallerFileName("setup"))
    );
    let e = info.requires_elevation(Some("tool.exe"));
    assert_eq!(
        e.reason,
        ElevationReason::UnknownLevel("elevateMaybe".into())
    );
}

// --- Name normalisation. ---------------------------------------------------------

#[test]
fn names_are_normalised_and_folded() {
    let n = NormalizedName::new("  Cmd   Line\tTool \0\0");
    assert_eq!(n.original(), "  Cmd   Line\tTool \0\0");
    assert_eq!(n.normalized(), "Cmd Line Tool");
    assert_eq!(n.folded(), "CMD LINE TOOL");
    assert!(n.matches("cmd line tool"));
    // NFC: a decomposed é matches the precomposed one.
    assert!(NormalizedName::new("Caf\u{0065}\u{0301}").matches("CAFÉ"));
    // Simple folding only: ß does not become SS.
    assert!(!NormalizedName::new("straße").matches("STRASSE"));
    assert_eq!(NormalizedName::new("\0\0").normalized(), "");
    assert_eq!(NormalizedName::new("a\0b").normalized(), "a");
}

// --- Round 2: imports and exports against crafted tables. -----------------

/// An export section with `entries` of `(name bytes, ordinal index)` in
/// name-table order, `functions` slots, and the slot RVAs given.
fn raw_export_section(rva: u32, entries: &[(Vec<u8>, u16)], functions: &[u32]) -> Vec<u8> {
    let mut out = vec![0_u8; 40];
    let functions_at = out.len();
    for f in functions {
        out.extend_from_slice(&f.to_le_bytes());
    }
    let names_at = out.len();
    out.resize(names_at + entries.len() * 4, 0);
    let ordinals_at = out.len();
    out.resize(ordinals_at + entries.len() * 2, 0);
    for (i, (name, ordinal)) in entries.iter().enumerate() {
        let at = out.len();
        out.extend_from_slice(name);
        out.push(0);
        put32(&mut out, names_at + i * 4, rva + at as u32);
        put16(&mut out, ordinals_at + i * 2, *ordinal);
    }
    put32(&mut out, 16, 1);
    put32(&mut out, 20, functions.len() as u32);
    put32(&mut out, 24, entries.len() as u32);
    put32(&mut out, 28, rva + functions_at as u32);
    put32(&mut out, 32, rva + names_at as u32);
    put32(&mut out, 36, rva + ordinals_at as u32);
    out
}

fn exports_of(entries: &[(Vec<u8>, u16)], functions: &[u32]) -> PeInfo {
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        raw_export_section(rva, entries, functions)
    });
    parse(&image)
}

#[test]
fn long_and_empty_export_names_hide_nothing() {
    // Sorted as the loader expects: "", a 600-byte C++ name, then the
    // notable ones. A crafted name at the search midpoint must not hide
    // them, and must not end the listing.
    let long = [b"?".as_slice(), &[b'x'; 600]].concat();
    let names: Vec<Vec<u8>> = vec![
        Vec::new(),
        long.clone(),
        b"CPlApplet".to_vec(),
        b"DllGetClassObject".to_vec(),
        b"DllRegisterServer".to_vec(),
        b"ServiceMain".to_vec(),
    ];
    let entries: Vec<_> = names.iter().cloned().zip(0..).collect();
    let info = exports_of(&entries, &[0x1000; 6]);
    let e = info.exports.unwrap();
    assert!(e.notable.cpl_applet && e.notable.dll_get_class_object);
    assert!(e.notable.dll_register_server && e.notable.service_main);
    assert_eq!(e.exports.len(), 6, "{:?}", e.exports);
    let listed = e.exports[1].name.as_ref().unwrap();
    assert_eq!(listed.len(), pe::MAX_NAME_LEN);
    assert!(e.truncated, "a cut name marks the listing truncated");
    assert_eq!(e.exports[0].name.as_deref(), Some(""));
}

#[test]
fn the_lookup_uses_the_loader_midpoint() {
    // Unsorted: the loader's inclusive search probes index 0 first and finds
    // DllRegisterServer, so it is exported.
    let entries = vec![(b"DllRegisterServer".to_vec(), 0), (b"AAA".to_vec(), 1)];
    let e = exports_of(&entries, &[0x1000, 0x1010]).exports.unwrap();
    assert!(e.notable.dll_register_server);
}

#[test]
fn ordinals_past_the_function_table_are_rejected() {
    // Two slots; the second name points at index 5.
    let entries = vec![(b"Good".to_vec(), 0), (b"Bogus".to_vec(), 5)];
    let info = exports_of(&entries, &[0x1000, 0x1010]);
    let e = info.exports.as_ref().unwrap();
    assert!(e.exports.iter().all(|x| x.name.as_deref() != Some("Bogus")));
    assert!(e.truncated);
    let warns = info
        .parse_warnings
        .iter()
        .filter(|w| w.kind == WarningKind::ExportTableMalformed)
        .count();
    assert_eq!(warns, 1);
    // A notable name past the table is not found either.
    let entries = vec![(b"DllRegisterServer".to_vec(), 9)];
    let e = exports_of(&entries, &[0x1000]).exports.unwrap();
    assert!(!e.notable.dll_register_server);
}

#[test]
fn unnamed_exports_are_listed_by_ordinal() {
    // Three slots, one named; slot 1 is unused (RVA 0).
    let entries = vec![(b"Named".to_vec(), 2)];
    let e = exports_of(&entries, &[0x1000, 0, 0x1020]).exports.unwrap();
    let summary: Vec<_> = e
        .exports
        .iter()
        .map(|x| (x.name.clone(), x.ordinal))
        .collect();
    assert_eq!(summary, [(Some("Named".into()), 3), (None, 1)]);
}

#[test]
fn an_unmapped_export_directory_is_reported() {
    let mut image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        raw_export_section(rva, &[], &[])
    });
    let at = PeBuilder::dll().data_directory_offset(DIR_EXPORT);
    put32(&mut image, at, 0x00f0_0000);
    let info = parse(&image);
    assert!(info.exports.is_none());
    assert!(info.parse_warnings.iter().any(|w| matches!(
        w.kind,
        WarningKind::DirectoryNotMapped(pe::DataDirectoryKind::Export)
    )));
}

#[test]
fn bad_descriptors_and_thunks_warn_once() {
    // Build the table by hand: four descriptors, then a terminator.
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        let mut out = vec![0_u8; 5 * 20];
        let name_at = out.len();
        out.extend_from_slice(b"ok.dll\0");
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let thunks_at = out.len();
        out.resize(thunks_at + 16, 0);
        put64(&mut out, thunks_at, (1 << 63) | 7);
        for d in 0..3 {
            // Name RVA unmapped, IAT present: malformed, not the end.
            put32(&mut out, d * 20 + 12, 0x00f0_0000);
            put32(&mut out, d * 20 + 16, rva + thunks_at as u32);
        }
        // A good name with an unmapped thunk array.
        put32(&mut out, 3 * 20 + 12, rva + name_at as u32);
        put32(&mut out, 3 * 20 + 16, 0x00f0_0000);
        out
    });
    let info = parse(&image);
    let imports = info.imports.as_ref().unwrap();
    assert!(imports.truncated);
    assert!(imports.imports_module("OK.DLL"));
    assert_eq!(imports.modules.len(), 1);
    assert_eq!(imports.modules[0].function_count, 0);
    let warns = info
        .parse_warnings
        .iter()
        .filter(|w| w.kind == WarningKind::ImportTableMalformed)
        .count();
    assert_eq!(warns, 1, "{:?}", info.parse_warnings);
}

#[test]
fn module_names_are_bounded_in_memory() {
    // Many distinct long names: the total kept stays under the byte cap.
    let names: Vec<String> = (0..3000)
        .map(|i| format!("{i:04}{}", "m".repeat(500)))
        .collect();
    let imports: Vec<Import<'_>> = names.iter().map(|n| (n.as_str(), vec![Err(1)])).collect();
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        import_section(rva, &imports, true)
    });
    let info = parse(&image);
    let i = info.imports.unwrap();
    let kept: usize = i.all_module_names.iter().map(String::len).sum();
    assert!(kept <= pe::MAX_MODULE_NAME_BYTES);
    assert!(i.truncated);
}

#[test]
fn the_import_table_stops_where_the_loader_does() {
    // A descriptor with a name but no import address table ends the table,
    // as it does for the loader, even if it is not all zeros.
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        let mut body = import_section(
            rva,
            &[("a.dll", vec![Err(1)]), ("b.dll", vec![Err(2)])],
            true,
        );
        // Zero b.dll's FirstThunk and OriginalFirstThunk, keep its name.
        put32(&mut body, 20, 0);
        put32(&mut body, 20 + 16, 0);
        put32(&mut body, 20 + 4, 0xdead_beef); // TimeDateStamp set
        body
    });
    let info = parse(&image);
    let imports = info.imports.unwrap();
    assert_eq!(imports.modules.len(), 1);
    assert!(!imports.truncated);
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
}

#[test]
fn the_first_thunk_is_used_when_there_is_no_lookup_table() {
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        let mut body = import_section(rva, &[("a.dll", vec![Ok("Fn")])], true);
        put32(&mut body, 0, 0); // OriginalFirstThunk
        body
    });
    let imports = parse(&image).imports.unwrap();
    assert_eq!(
        imports.modules[0].functions,
        [ImportedFunction::Name {
            name: "Fn".into(),
            hint: 0
        }]
    );
}

// --- Round 3. -----------------------------------------------------------------

#[test]
fn name_reads_are_bounded() {
    // 10,000 export names all pointing at one long run with no NUL: each
    // read stops after MAX_NAME_LEN + 1 bytes, so this is quick, and every
    // name is reported as cut, not dropped.
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        let n = 10_000;
        let mut out = vec![0_u8; 40];
        let functions_at = out.len();
        out.resize(functions_at + n * 4, 0);
        let names_at = out.len();
        out.resize(names_at + n * 4, 0);
        let ordinals_at = out.len();
        out.resize(ordinals_at + n * 2, 0);
        let run_at = out.len();
        out.extend(std::iter::repeat_n(b'A', 400_000));
        for i in 0..n {
            put32(&mut out, functions_at + i * 4, 0x1000);
            put32(&mut out, names_at + i * 4, rva + run_at as u32);
            put16(&mut out, ordinals_at + i * 2, i as u16);
        }
        put32(&mut out, 20, n as u32);
        put32(&mut out, 24, n as u32);
        put32(&mut out, 28, rva + functions_at as u32);
        put32(&mut out, 32, rva + names_at as u32);
        put32(&mut out, 36, rva + ordinals_at as u32);
        out.push(0);
        out
    });
    let started = std::time::Instant::now();
    let info = parse(&image);
    let elapsed = started.elapsed();
    let e = info.exports.unwrap();
    assert_eq!(e.exports.len(), 10_000);
    assert!(
        e.exports
            .iter()
            .all(|x| x.name.as_ref().unwrap().len() == pe::MAX_NAME_LEN)
    );
    assert!(e.truncated);
    // Scanning the whole run each time would read 4 GB; bounded reads take
    // a few milliseconds. Generous, so slow CI runners still pass.
    assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
}

#[test]
fn a_name_ending_at_the_raw_data_is_terminated_by_the_zero_fill() {
    // The section's raw data ends exactly at the end of a name with no NUL
    // in the file; the loader maps zeros after it, so the name is complete.
    let names = [b"AAAA".to_vec(), b"CPlApplet".to_vec(), b"ZZ".to_vec()];
    let mut b = PeBuilder::dll();
    let section = b.sections.len();
    let rva = SECTION_ALIGNMENT * (section as u32 + 1);
    let entries: Vec<_> = names.iter().cloned().zip(0..).collect();
    let mut body = raw_export_section(rva, &entries, &[0x1000; 3]);
    body.pop(); // the NUL after "ZZ": it now ends the raw data
    let size = body.len() as u32;
    let raw = size.div_ceil(0x200) * 0x200;
    // Fill the rest of the raw data with non-zero bytes after "ZZ", and
    // make the raw size end right after it.
    b = b.section(
        ".edata",
        body,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    b.sections.last_mut().unwrap().virtual_size = Some(raw + 0x1000);
    let mut image = b.build();
    let at = b.data_directory_offset(DIR_EXPORT);
    put32(&mut image, at, rva);
    put32(&mut image, at + 4, size);
    // Shrink SizeOfRawData to end at "ZZ", so the NUL is in the zero fill.
    let header = PeBuilder::dll().section_table_offset() + section * 40;
    put32(&mut image, header + 16, size);
    let info = parse(&image);
    let e = info.exports.unwrap();
    assert_eq!(
        e.exports
            .iter()
            .filter_map(|x| x.name.as_deref())
            .collect::<Vec<_>>(),
        ["AAAA", "CPlApplet", "ZZ"]
    );
    assert!(e.notable.cpl_applet);
}

#[test]
fn unused_export_slots_are_not_exports() {
    // A name whose slot holds RVA 0 is not an export, and not notable.
    let entries = vec![(b"DllRegisterServer".to_vec(), 0), (b"Real".to_vec(), 1)];
    let info = exports_of(&entries, &[0, 0x1010]);
    let e = info.exports.unwrap();
    assert!(!e.notable.dll_register_server);
    assert_eq!(
        e.exports
            .iter()
            .filter_map(|x| x.name.as_deref())
            .collect::<Vec<_>>(),
        ["Real"]
    );
}

#[test]
fn exactly_the_caps_are_not_truncated() {
    let many: Vec<Result<&str, u16>> = (0..10_000_u16).map(Err).collect();
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        import_section(rva, &[("a.dll", many.clone())], true)
    });
    let i = parse(&image).imports.unwrap();
    assert_eq!(i.function_count, 10_000);
    assert!(!i.truncated);

    let names: Vec<String> = (0..10_000).map(|i| format!("F{i:05}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        export_section(rva, "x.dll", &refs, &[])
    });
    let e = parse(&image).exports.unwrap();
    assert_eq!(e.exports.len(), 10_000);
    assert!(!e.truncated);
}

#[test]
fn a_cut_forwarder_is_reported_and_a_bad_slot_hides_nothing() {
    let long = format!("M.{}", "f".repeat(700));
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        export_section(rva, "x.dll", &["Fwd"], &[(0, long.as_str())])
    });
    let e = parse(&image).exports.unwrap();
    assert!(e.truncated);
    assert!(
        matches!(&e.exports[0].target, ExportTarget::Forwarder(f) if f.len() == pe::MAX_NAME_LEN)
    );

    // Unnamed slots: a bad one (pointing at an unmapped forwarder string
    // inside the directory is hard to build, so use an unreadable slot
    // past the backed data) does not stop the listing.
    let entries: Vec<(Vec<u8>, u16)> = Vec::new();
    let e = exports_of(&entries, &[0x1000, 0x1010, 0x1020])
        .exports
        .unwrap();
    assert_eq!(e.exports.len(), 3);
}

#[test]
fn a_kernel_import_cannot_be_hidden_by_padding() {
    // Enough long names to exhaust MAX_MODULE_NAME_BYTES, then ntoskrnl.
    let names: Vec<String> = (0..2_100)
        .map(|i| format!("{i:04}{}", "m".repeat(508)))
        .collect();
    let mut imports: Vec<Import<'_>> = names.iter().map(|n| (n.as_str(), vec![Err(1)])).collect();
    imports.push(("ntoskrnl.exe", vec![Err(1)]));
    let image = with_directory(
        PeBuilder {
            subsystem: 1,
            ..PeBuilder::default()
        },
        DIR_IMPORT,
        |rva| import_section(rva, &imports, true),
    );
    let info = parse(&image);
    let i = info.imports.as_ref().unwrap();
    assert!(i.truncated, "the name cap was reached");
    assert!(i.imports_module("NTOSKRNL.EXE"));
    assert_eq!(i.kernel_modules, ["ntoskrnl.exe"]);
    assert!(info.is_kernel_driver());
    // A listed module is always found too.
    assert!(i.imports_module(&i.modules[2_050].name));
}

#[test]
fn padding_before_a_comment_cdata_or_reference_is_dropped() {
    let pad = " ".repeat(5_000);
    for tail in ["<!-- x -->true", "<![CDATA[true]]>", "&#x74;rue"] {
        let xml = format!(
            "<assembly><application><windowsSettings><autoElevate>{pad}{tail}</autoElevate></windowsSettings></application></assembly>"
        );
        assert_eq!(
            parse_manifest(xml.as_bytes()).unwrap().auto_elevate,
            Some(true),
            "{tail}"
        );
    }
    // A huge single text value is bounded, not buffered whole.
    let big = "x".repeat(200_000);
    let xml = format!(
        "<assembly><application><windowsSettings><dpiAware>{big}</dpiAware></windowsSettings></application></assembly>"
    );
    assert_eq!(
        parse_manifest(xml.as_bytes())
            .unwrap()
            .dpi_aware
            .unwrap()
            .len(),
        pe::manifest::MAX_VALUE_LEN
    );
}

#[test]
fn names_are_case_sensitive_and_prefixed_attributes_are_not_the_schema() {
    // A prefixed or case-variant attribute is a different attribute; the
    // real `level` decides.
    for attrs in [
        r#"xmlns:x="urn:d" x:level="asInvoker" level="requireAdministrator" x:uiAccess="false" uiAccess="true""#,
        r#"LEVEL="asInvoker" level="requireAdministrator" UIACCESS="false" uiAccess="true""#,
        r#"level="requireAdministrator" LEVEL="asInvoker" uiAccess="true" x:uiAccess="false" xmlns:x="urn:d""#,
    ] {
        let xml = format!(
            r#"<assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel {attrs}/></requestedPrivileges></security></trustInfo></assembly>"#
        );
        let m = parse_manifest(xml.as_bytes()).unwrap();
        assert_eq!(
            m.execution_level,
            Some(ExecutionLevel::RequireAdministrator),
            "{attrs}"
        );
        assert_eq!(m.ui_access, Some(true), "{attrs}");
    }
    // A case-variant element is a different element.
    let xml = format!(
        "<assembly><TRUSTINFO><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\"/></requestedPrivileges></security></TRUSTINFO>{}</assembly>",
        r#"<trustInfo><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator"/></requestedPrivileges></security></trustInfo>"#
    );
    assert_eq!(
        parse_manifest(xml.as_bytes()).unwrap().execution_level,
        Some(ExecutionLevel::RequireAdministrator)
    );
}

#[test]
fn invalid_names_are_rejected() {
    for bad in [
        &b"<></>"[..],
        b"< />",
        br#"<assembly == "1"/>"#,
        br#"<assembly><a="&boom;"/></assembly>"#,
        br#"<assembly><1a/></assembly>"#,
        br#"<assembly><q 1x="1"/></assembly>"#,
    ] {
        assert!(
            matches!(parse_manifest(bad), Err(ManifestError::Xml(_))),
            "{:?}: {:?}",
            String::from_utf8_lossy(bad),
            parse_manifest(bad)
        );
    }
}

#[test]
fn the_first_text_setting_wins_however_it_is_written() {
    let settings = |inner: &str| {
        format!(
            "<assembly><application><windowsSettings>{inner}</windowsSettings></application></assembly>"
        )
    };
    let m = parse_manifest(
        settings("<autoElevate>bogus</autoElevate><autoElevate>true</autoElevate>").as_bytes(),
    )
    .unwrap();
    assert_eq!(m.auto_elevate, None);
    let m = parse_manifest(settings("<dpiAware/><dpiAware>true</dpiAware>").as_bytes()).unwrap();
    assert_eq!(m.dpi_aware.as_deref(), Some(""));
    let m = parse_manifest(settings("<dpiAware></dpiAware><dpiAware>true</dpiAware>").as_bytes())
        .unwrap();
    assert_eq!(m.dpi_aware.as_deref(), Some(""));
}

#[test]
fn only_the_process_manifest_decides_elevation() {
    // An EXE named setup.exe with only an ID 2 manifest saying asInvoker:
    // the OS does not read ID 2 at process creation, so the installer
    // heuristic still applies.
    let image = PeBuilder {
        resources: vec![Leaf {
            type_id: 24,
            name_id: 2,
            lang: 0x0409,
            data: level_manifest("asInvoker").into_bytes(),
        }],
        ..PeBuilder::default()
    }
    .build();
    let info = parse(&image);
    assert_eq!(info.manifest_id, Some(2));
    let e = info.requires_elevation(Some("setup.exe"));
    assert_eq!(
        (e.requires_elevation, e.reason),
        (true, ElevationReason::InstallerFileName("setup"))
    );
}

// --- Round 4. -----------------------------------------------------------------

/// The `.edata` image of `exports_of`, and the file offset where its
/// section's raw data starts.
fn export_image(entries: &[(Vec<u8>, u16)], functions: &[u32]) -> (Vec<u8>, usize) {
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        raw_export_section(rva, entries, functions)
    });
    let info = parse(&image);
    let start = info.sections.last().unwrap().pointer_to_raw_data as usize;
    (image, start)
}

#[test]
fn a_name_cut_by_the_end_of_the_file_is_not_complete() {
    // "DllRegisterServerExtra", and the file ends right after
    // "DllRegisterServer": the raw data the header declares runs on, so
    // this is a truncated file, not zero fill. Nothing matches.
    let entries = vec![(b"DllRegisterServerExtra".to_vec(), 0)];
    let (image, _) = export_image(&entries, &[0x1000]);
    let pos = image
        .windows(22)
        .position(|w| w == b"DllRegisterServerExtra")
        .unwrap();
    let cut = &image[..pos + 17];
    let info = pe::parse(cut).unwrap();
    let e = info.exports.as_ref().unwrap();
    assert!(!e.notable.dll_register_server);
    assert!(
        e.exports
            .iter()
            .all(|x| x.name.as_deref() != Some("DllRegisterServer"))
    );
    assert!(e.truncated);
}

#[test]
fn a_name_starting_in_the_zero_fill_is_empty() {
    // Two names: "" in the zero-filled tail (past the raw data), then
    // "DllRegisterServer". The empty name sorts first, as for the loader.
    let entries = vec![(b"X".to_vec(), 0), (b"DllRegisterServer".to_vec(), 1)];
    let mut b = PeBuilder::dll();
    let section = b.sections.len();
    let rva = SECTION_ALIGNMENT * (section as u32 + 1);
    let mut body = raw_export_section(rva, &entries, &[0x1000, 0x1010]);
    let size = body.len() as u32;
    // Point the first name past the raw data, into the zero fill.
    let names_at = 40 + 2 * 4;
    let zero_rva = rva + 0x800;
    body[names_at..names_at + 4].copy_from_slice(&zero_rva.to_le_bytes());
    b = b.section(
        ".edata",
        body,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    b.sections.last_mut().unwrap().virtual_size = Some(0x1000);
    let mut image = b.build();
    let at = b.data_directory_offset(DIR_EXPORT);
    put32(&mut image, at, rva);
    put32(&mut image, at + 4, size);
    let e = parse(&image).exports.unwrap();
    assert_eq!(e.exports[0].name.as_deref(), Some(""));
    assert!(e.notable.dll_register_server);
}

#[test]
fn a_short_export_address_table_is_reported() {
    // No names, and NumberOfFunctions far past what the section holds.
    let (mut image, start) = export_image(&[], &[0x1000]);
    put32(&mut image, start + 20, 50_000);
    let info = parse(&image);
    assert!(info.exports.as_ref().unwrap().truncated);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ExportTableMalformed)
    );
}

#[test]
fn the_export_module_name_is_checked() {
    // Name RVA unmapped: a warning, no name.
    let (mut image, start) = export_image(&[(b"F".to_vec(), 0)], &[0x1000]);
    put32(&mut image, start + 12, 0x00f0_0000);
    let info = parse(&image);
    assert_eq!(info.exports.as_ref().unwrap().dll_name, None);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ExportTableMalformed)
    );
    // A long module name is cut and marked.
    let long = "d".repeat(800);
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        export_section(rva, &long, &["F"], &[])
    });
    let e = parse(&image).exports.unwrap();
    assert_eq!(e.dll_name.unwrap().len(), pe::MAX_NAME_LEN);
    assert!(e.truncated);
}

#[test]
fn a_cut_value_is_never_a_keyword() {
    let pad = " ".repeat(2_000);
    let attr = format!("true{pad}invalid");
    let xml = format!(
        r#"<assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator{pad}x" uiAccess="{attr}"/></requestedPrivileges></security></trustInfo><application><windowsSettings><autoElevate>true{pad}invalid</autoElevate><dpiAware>per monitor{pad}x</dpiAware></windowsSettings></application></assembly>"#
    );
    let m = parse_manifest(xml.as_bytes()).unwrap();
    assert_eq!(m.ui_access, None);
    assert_eq!(m.auto_elevate, None);
    assert!(matches!(m.execution_level, Some(ExecutionLevel::Other(_))));
    // The value is cut where it no longer fits: whitespace that cannot be
    // kept is not, so what remains is the prefix, never a padded keyword.
    assert_eq!(m.dpi_aware.as_deref(), Some("per monitor"));
}

#[test]
fn qualified_names_must_be_valid() {
    // `<:trustInfo>` is not a valid name; it must not pass as `trustInfo`.
    let shadow = r#"<assembly><:trustInfo><security><requestedPrivileges><requestedExecutionLevel level="asInvoker"/></requestedPrivileges></security></:trustInfo></assembly>"#;
    assert!(matches!(
        parse_manifest(shadow.as_bytes()),
        Err(ManifestError::Xml(_))
    ));
    for bad in [
        "<assembly:/>",
        "<x:1bad/>",
        "<a:b:c/>",
        r#"<assembly :="1"/>"#,
        r#"<assembly a:="1"/>"#,
        "<\u{00a0}/>",
        "<a\u{00a0}b/>",
    ] {
        assert!(
            matches!(parse_manifest(bad.as_bytes()), Err(ManifestError::Xml(_))),
            "{bad}"
        );
    }
    // Valid prefixed and non-ASCII names still parse.
    for good in [
        r#"<x:assembly xmlns:x="urn:e"/>"#,
        "<assemblé/>",
        "<a.b-c_d/>",
    ] {
        assert!(parse_manifest(good.as_bytes()).is_ok(), "{good}");
    }
}

#[test]
fn declarations_instructions_comments_and_characters_are_checked() {
    for bad in [
        &b"<?xml NOT_VALID?><assembly/>"[..],
        br#"<?xml version="2.0"?><assembly/>"#,
        br#"<?xml version="1.0" encoding="UTF-16"?><assembly/>"#,
        br#"<assembly/><?xml version="1.0"?>"#,
        br#"<assembly><?xml version="1.0"?></assembly>"#,
        b"<? ?><assembly/>",
        b"<assembly><!-- a--b --></assembly>",
        b"<assembly><!-- \x01 --></assembly>",
        b"<assembly>\x01</assembly>",
        b"<assembly><![CDATA[\x02]]></assembly>",
        b"<assembly><application><windowsSettings><dpiAware>&#x1;</dpiAware></windowsSettings></application></assembly>",
        br#"<assembly a="&#x1;"/>"#,
    ] {
        assert!(
            parse_manifest(bad).is_err(),
            "{:?}: {:?}",
            String::from_utf8_lossy(bad),
            parse_manifest(bad)
        );
    }
    for good in [
        &br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><assembly/>"#[..],
        b"<?xml version='1.0'?><!-- c --><?app data?><assembly><!-- c --></assembly>",
        b"<assembly>\t\r\n</assembly>",
    ] {
        assert!(
            parse_manifest(good).is_ok(),
            "{:?}",
            String::from_utf8_lossy(good)
        );
    }
}

// --- Round 5. -----------------------------------------------------------------

fn settings(inner: &str) -> String {
    format!(
        "<assembly><application><windowsSettings>{inner}</windowsSettings></application></assembly>"
    )
}

#[test]
fn a_cut_is_detected_whatever_the_character_width() {
    // A 2-, 3- and 4-byte character straddling the 1 KiB boundary, as text
    // and as a character reference: always cut, never `true`.
    for (spaces, ch) in [(1_020, "é"), (1_019, "€"), (1_018, "𝄞"), (1_020, "&#xe9;")] {
        let pad = " ".repeat(spaces);
        let xml = settings(&format!("<autoElevate>true{pad}{ch}invalid</autoElevate>"));
        assert_eq!(
            parse_manifest(xml.as_bytes()).unwrap().auto_elevate,
            None,
            "{ch}"
        );
    }
    // Trailing padding alone is not a cut: the value is still `true`.
    for spaces in [1_021, 5_000] {
        let pad = " ".repeat(spaces);
        let xml = settings(&format!("<autoElevate>true{pad}</autoElevate>"));
        assert_eq!(
            parse_manifest(xml.as_bytes()).unwrap().auto_elevate,
            Some(true),
            "{spaces}"
        );
    }
    // Text that fits exactly is kept whole and not cut.
    let exact = "x".repeat(pe::manifest::MAX_VALUE_LEN);
    let m = parse_manifest(settings(&format!("<dpiAware>{exact}</dpiAware>")).as_bytes()).unwrap();
    assert_eq!(m.dpi_aware.unwrap().len(), pe::manifest::MAX_VALUE_LEN);
}

#[test]
fn only_xml_whitespace_is_whitespace() {
    // U+00A0 is text in XML: outside the root it is an error, and around a
    // keyword it makes the value something else.
    for bad in ["\u{a0}<assembly/>", "<assembly/>\u{a0}"] {
        assert!(
            matches!(parse_manifest(bad.as_bytes()), Err(ManifestError::Xml(_))),
            "{bad:?}"
        );
    }
    let m = parse_manifest(level_manifest("\u{a0}asInvoker").as_bytes()).unwrap();
    assert!(matches!(m.execution_level, Some(ExecutionLevel::Other(_))));
    let m = parse_manifest(settings("<autoElevate>\u{a0}true</autoElevate>").as_bytes()).unwrap();
    assert_eq!(m.auto_elevate, None);
    // Tabs, CR and LF are whitespace.
    let m =
        parse_manifest(settings("<autoElevate>\t\r\ntrue\r\n</autoElevate>").as_bytes()).unwrap();
    assert_eq!(m.auto_elevate, Some(true));
}

#[test]
fn start_tags_and_declarations_are_checked_in_full() {
    for bad in [
        r#"<assembly b="1"c="2"/>"#,
        r#"<assembly b="1<2"/>"#,
        r#"<assembly b=1/>"#,
        r#"<assembly b/>"#,
        "<assembly>x]]>y</assembly>",
        r#"<?xml version="1.0" encoding="UTF-8" NOT ?><assembly/>"#,
        r#"<?xml version="1.0" version="1.0"?><assembly/>"#,
        r#"<?xml encoding="UTF-8" version="1.0"?><assembly/>"#,
        r#"<?xml version="1.0" standalone="maybe"?><assembly/>"#,
        "<?xml version=\"1.0\"\u{1}?><assembly/>",
        r#"<?xml?><assembly/>"#,
    ] {
        assert!(
            parse_manifest(bad.as_bytes()).is_err(),
            "{bad}: {:?}",
            parse_manifest(bad.as_bytes())
        );
    }
    for good in [
        r#"<assembly  b = "1"	c='2' />"#,
        r#"<?xml version="1.0" standalone="no"?><assembly/>"#,
        r#"<?xml version='1.0' encoding='utf-8' standalone='yes' ?><assembly/>"#,
    ] {
        assert!(
            parse_manifest(good.as_bytes()).is_ok(),
            "{good}: {:?}",
            parse_manifest(good.as_bytes())
        );
    }
}

#[test]
fn line_ends_in_text_are_normalised() {
    let m = parse_manifest(settings("<dpiAware>a\r\nb\rc</dpiAware>").as_bytes()).unwrap();
    assert_eq!(m.dpi_aware.as_deref(), Some("a\nb\nc"));
}

#[test]
fn oversized_export_tables_are_reported() {
    // NumberOfFunctions beyond both the scan cap and the file: still
    // malformed, though the cap is below what the file holds.
    let functions = vec![0x1000_u32; 70_000];
    let (mut image, start) = export_image(&[], &functions);
    put32(&mut image, start + 20, 100_000);
    let info = parse(&image);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ExportTableMalformed)
    );
    // NumberOfNames past the listing cap and past the file.
    let names: Vec<(Vec<u8>, u16)> = (0..10_050)
        .map(|i| (format!("N{i:05}").into_bytes(), 0))
        .collect();
    let (mut image, start) = export_image(&names, &[0x1000]);
    put32(&mut image, start + 24, 1_000_000);
    let info = parse(&image);
    assert!(info.exports.as_ref().unwrap().truncated);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ExportTableMalformed)
    );
}

// --- Review follow-up: loader parity at the edges. ---------------------------

/// An image whose last section holds `body`, with data directory `index`
/// at `dir_offset..dir_offset + dir_size` inside it. The section's
/// `SizeOfRawData` is cut to `raw_len` and its `VirtualSize` is large, so
/// everything past `raw_len` is zero fill in memory. The file bytes past
/// `raw_len` are `0xff`, so a parser that reads them instead of the zero
/// fill fails.
fn zero_fill_image(
    builder: PeBuilder,
    index: usize,
    body: impl FnOnce(u32) -> Vec<u8>,
    dir: (u32, u32),
    raw_len: u32,
) -> Vec<u8> {
    let section = builder.sections.len();
    let rva = SECTION_ALIGNMENT * (section as u32 + 1);
    let mut data = body(rva);
    data.truncate(raw_len as usize);
    data.resize(0x400, 0xff);
    let mut b = builder.section(
        ".idata",
        data,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    b.sections.last_mut().unwrap().virtual_size = Some(0x2000);
    let mut image = b.build();
    let at = b.data_directory_offset(index);
    put32(&mut image, at, rva + dir.0);
    put32(&mut image, at + 4, dir.1);
    let header = b.section_table_offset() + section * 40;
    put32(&mut image, header + 16, raw_len);
    image
}

/// One PE32+ import of `a.dll`, ordinal 7, laid out as thunks, name, then
/// the descriptor table (descriptor 0, then the terminator).
fn tail_import_table(rva: u32) -> Vec<u8> {
    let mut out = vec![0_u8; 64];
    put64(&mut out, 0, (1 << 63) | 7);
    out[16..22].copy_from_slice(b"a.dll\0");
    put32(&mut out, 24, rva);
    put32(&mut out, 24 + 12, rva + 16);
    put32(&mut out, 24 + 16, rva);
    out
}

#[test]
fn an_import_terminator_in_the_zero_fill_ends_the_table() {
    // The raw data ends right after descriptor 0, so the terminator is in
    // the zero-filled tail: in memory it is all zeros.
    let image = zero_fill_image(
        PeBuilder::default(),
        DIR_IMPORT,
        tail_import_table,
        (24, 40),
        44,
    );
    let info = parse(&image);
    let i = info.imports.as_ref().unwrap();
    assert_eq!(i.modules.len(), 1);
    assert_eq!(i.modules[0].functions, [ImportedFunction::Ordinal(7)]);
    assert!(!i.truncated);
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);

    // The same bytes, but the file ends there while the header declares
    // more raw data: a truncated file, not zero fill.
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        let mut out = tail_import_table(rva);
        out.resize(0x200, 0xff);
        out
    });
    let at = DIR_IMPORT;
    let start = parse(&image).sections.last().unwrap().pointer_to_raw_data as usize;
    let mut image = image[..start + 44].to_vec();
    let dir = PeBuilder::default().data_directory_offset(at);
    put32(&mut image, dir, SECTION_ALIGNMENT * 2 + 24);
    put32(&mut image, dir + 4, 40);
    let info = pe::parse(&image).unwrap();
    assert!(info.imports.as_ref().unwrap().truncated);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ImportTableTruncated),
        "{:?}",
        info.parse_warnings
    );
}

/// Descriptor 0, the terminator, `a.dll`, then one PE32+ ordinal thunk
/// at offset 48, ending at offset 56.
fn tail_thunk_table(rva: u32) -> Vec<u8> {
    let mut out = vec![0_u8; 64];
    put32(&mut out, 12, rva + 40);
    put32(&mut out, 16, rva + 48);
    out[40..46].copy_from_slice(b"a.dll\0");
    put64(&mut out, 48, (1 << 63) | 7);
    out
}

#[test]
fn a_null_thunk_in_the_zero_fill_ends_the_list() {
    let image = zero_fill_image(
        PeBuilder::default(),
        DIR_IMPORT,
        tail_thunk_table,
        (0, 40),
        56,
    );
    let info = parse(&image);
    let i = info.imports.as_ref().unwrap();
    assert_eq!(i.modules[0].functions, [ImportedFunction::Ordinal(7)]);
    assert!(!i.truncated);
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);

    // A thunk straddling the end of the raw data reads its high half from
    // the zero fill: here it is the null thunk itself.
    let image = zero_fill_image(
        PeBuilder::default(),
        DIR_IMPORT,
        |rva| {
            let mut out = tail_thunk_table(rva);
            put64(&mut out, 56, 0);
            out
        },
        (0, 40),
        60,
    );
    let info = parse(&image);
    assert!(!info.imports.as_ref().unwrap().truncated);

    // A file that ends there while declaring more raw data has no
    // terminator.
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        let mut out = tail_thunk_table(rva);
        out.resize(0x200, 0xff);
        out
    });
    let start = parse(&image).sections.last().unwrap().pointer_to_raw_data as usize;
    let info = pe::parse(&image[..start + 56]).unwrap();
    assert!(info.imports.as_ref().unwrap().truncated);
}

#[test]
fn a_cut_module_name_never_matches_exactly() {
    // 512 `a` and `.dll`: the kept prefix is not the module's name.
    let long = format!("{}.dll", "a".repeat(pe::MAX_NAME_LEN));
    let exact = format!("{}.sys", "b".repeat(pe::MAX_NAME_LEN - 4));
    let imports: Vec<Import<'_>> = vec![
        (long.as_str(), vec![Err(1)]),
        (exact.as_str(), vec![Err(1)]),
    ];
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |rva| {
        import_section(rva, &imports, true)
    });
    let info = parse(&image);
    let i = info.imports.as_ref().unwrap();
    assert!(i.modules[0].name_cut);
    assert_eq!(i.modules[0].name.len(), pe::MAX_NAME_LEN);
    assert!(!i.imports_module(&"a".repeat(pe::MAX_NAME_LEN)));
    assert!(!i.all_module_names.iter().any(|n| n.starts_with('a')));
    assert!(i.truncated);
    // A complete name of exactly 512 bytes still matches.
    assert_eq!(exact.len(), pe::MAX_NAME_LEN);
    assert!(!i.modules[1].name_cut);
    assert!(i.imports_module(&exact.to_uppercase()));
}

#[test]
fn an_export_table_at_rva_zero_is_not_read_from_the_headers() {
    // AddressOfFunctions = 0, and a name pointing at slot 15: RVA 60 is
    // `e_lfanew` in the DOS header, never an export.
    let entries = vec![(b"DllRegisterServer".to_vec(), 15)];
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        let mut body = raw_export_section(rva, &entries, &[0x1000; 16]);
        put32(&mut body, 28, 0);
        body
    });
    let info = parse(&image);
    let e = info.exports.as_ref().unwrap();
    assert!(e.exports.is_empty(), "{:?}", e.exports);
    assert!(!e.notable.dll_register_server);
    assert!(e.truncated);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ExportTableMalformed)
    );
}

#[test]
fn a_forwarder_must_end_inside_the_export_directory() {
    let target = "OTHER.Target";
    let body = |rva| export_section(rva, "x.dll", &["Fwd"], &[(0, target)]);
    let full = body(SECTION_ALIGNMENT * 2);
    let start = (full.len() - target.len() - 1) as u32;
    for (size, malformed) in [
        // Only the first byte of the string is inside the directory.
        (start + 1, true),
        // The NUL is the directory's last byte.
        (start + target.len() as u32 + 1, false),
    ] {
        let image = zero_fill_image(
            PeBuilder::dll(),
            DIR_EXPORT,
            body,
            (0, size),
            full.len() as u32,
        );
        let info = parse(&image);
        let e = info.exports.as_ref().unwrap();
        assert!(
            matches!(&e.exports[0].target, ExportTarget::Forwarder(f) if f == target),
            "{:?}",
            e.exports
        );
        assert_eq!(e.truncated, malformed, "{size}");
        assert_eq!(
            info.parse_warnings
                .iter()
                .any(|w| w.kind == WarningKind::ExportTableMalformed),
            malformed,
            "{:?}",
            info.parse_warnings
        );
    }
}

#[test]
fn named_slots_past_the_listing_are_not_reported_as_unnamed() {
    // 10,001 names, each for its own slot. Name 5 cannot be read, and name
    // 10,000 is past the listing cap: neither slot is an unnamed export.
    let n = pe::MAX_EXPORTS + 1;
    let entries: Vec<(Vec<u8>, u16)> = (0..n)
        .map(|i| (format!("N{i:05}").into_bytes(), i as u16))
        .collect();
    let functions = vec![0x1000_u32; n];
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        let mut body = raw_export_section(rva, &entries, &functions);
        let names_at = 40 + n * 4;
        put32(&mut body, names_at + 5 * 4, 0x00f0_0000);
        body
    });
    let e = parse(&image).exports.unwrap();
    assert!(e.truncated);
    assert_eq!(e.exports.len(), pe::MAX_EXPORTS - 1);
    assert!(e.exports.iter().all(|x| x.name.is_some()), "unnamed listed");

    // If the ordinal table is not all in the file, no slot is known to be
    // unnamed, so none is listed as one.
    let entries = vec![(b"A".to_vec(), 0)];
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        let mut body = raw_export_section(rva, &entries, &[0x1000, 0x1010]);
        put32(&mut body, 24, 0x10_0000); // NumberOfNames
        body
    });
    let e = parse(&image).exports.unwrap();
    assert!(
        e.exports.iter().all(|x| x.name.is_some()),
        "{:?}",
        e.exports
    );
}

#[test]
fn a_bad_unnamed_slot_between_good_ones_hides_nothing() {
    // The middle slot is a forwarder RVA inside the (large) directory, but
    // past the section, so its string cannot be read.
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        raw_export_section(rva, &[], &[0x1000, rva + 0x8_0000, 0x1020])
    });
    let mut image = image;
    let dir = PeBuilder::dll().data_directory_offset(DIR_EXPORT);
    put32(&mut image, dir + 4, 0x10_0000);
    let info = parse(&image);
    let e = info.exports.as_ref().unwrap();
    let ordinals: Vec<u32> = e.exports.iter().map(|x| x.ordinal).collect();
    assert_eq!(ordinals, [1, 3]);
    assert!(
        info.parse_warnings
            .iter()
            .any(|w| w.kind == WarningKind::ExportTableMalformed)
    );
}

#[test]
fn xml_1_1_and_a_second_byte_order_mark_are_rejected() {
    // XML 1.1 reads NEL as a line end, so this would be `true` there; it is
    // rejected rather than read by the XML 1.0 rules.
    let xml = format!(
        "<?xml version=\"1.1\"?>{}",
        settings("<autoElevate>\u{85}true</autoElevate>")
    );
    assert!(parse_manifest(xml.as_bytes()).is_err());
    assert!(parse_manifest(br#"<?xml version="1.1"?><assembly/>"#).is_err());

    let mut one = b"\xef\xbb\xbf".to_vec();
    one.extend_from_slice(b"<assembly/>");
    assert!(parse_manifest(&one).is_ok());
    let mut two = b"\xef\xbb\xbf\xef\xbb\xbf".to_vec();
    two.extend_from_slice(b"<assembly/>");
    assert!(parse_manifest(&two).is_err());
}

#[test]
fn a_prefix_parse_skips_imports_exports_and_the_driver_verdict() {
    // A native driver importing ntoskrnl.exe, with its import table in the
    // last section, so every cut before the end of the file splits or
    // drops it.
    let imports: Vec<Import<'_>> = vec![("ntoskrnl.exe", vec![Ok("IoCreateDevice")])];
    let image = with_directory(native(PeBuilder::default()), DIR_IMPORT, |rva| {
        import_section(rva, &imports, true)
    });
    let full = parse(&image);
    assert!(full.is_kernel_driver());
    let headers_end = full.sections.last().unwrap().header_offset as usize + 40;
    for cut in headers_end..image.len() {
        let info = pe::parse_prefix(&image[..cut], image.len() as u64).unwrap();
        assert!(
            info.imports.is_none() && info.exports.is_none(),
            "cut {cut:#x}"
        );
        assert!(info.manifest.is_none() && info.manifest_id.is_none());
        assert_eq!(info.driver, pe::DriverClass::default(), "cut {cut:#x}");
        assert!(
            info.parse_warnings.is_empty(),
            "cut {cut:#x}: {:?}",
            info.parse_warnings
        );
    }
    // The whole file as the prefix reads them, as a full parse does.
    let info = pe::parse_prefix(&image, image.len() as u64).unwrap();
    assert_eq!(info.imports, full.imports);
    assert_eq!(info.driver, full.driver);

    // Exports too.
    let image = with_directory(PeBuilder::dll(), DIR_EXPORT, |rva| {
        export_section(rva, "x.dll", &["DllRegisterServer"], &[])
    });
    let info = pe::parse_prefix(&image[..image.len() - 1], image.len() as u64).unwrap();
    assert!(info.exports.is_none());
    assert!(info.parse_warnings.is_empty(), "{:?}", info.parse_warnings);
}

#[test]
fn an_empty_setting_is_empty_however_it_is_written() {
    for xml in [
        settings("<dpiAware/><dpiAwareness/>"),
        settings("<dpiAware></dpiAware><dpiAwareness></dpiAwareness>"),
    ] {
        let m = parse_manifest(xml.as_bytes()).unwrap();
        assert_eq!(m.dpi_aware.as_deref(), Some(""), "{xml}");
        assert_eq!(m.dpi_awareness.as_deref(), Some(""), "{xml}");
    }
}

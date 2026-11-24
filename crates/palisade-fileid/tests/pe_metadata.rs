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

    // A descriptor table filling its section with no terminator.
    let image = with_directory(PeBuilder::default(), DIR_IMPORT, |_| vec![0xff; 0x200]);
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
        br#"<assembly><requestedExecutionLevel level="RequireADMINISTRATOR"/><autoElevate>&#x74;rue</autoElevate><assemblyIdentity name="a&amp;b"/></assembly>"#,
    );
    let m = parse_manifest(&xml).unwrap();
    assert_eq!(
        m.execution_level,
        Some(ExecutionLevel::RequireAdministrator)
    );
    assert_eq!(m.auto_elevate, Some(true));
    assert_eq!(m.identity.unwrap().name.as_deref(), Some("a&b"));
}

#[test]
fn hostile_manifests_are_rejected() {
    let doctype = br#"<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "xxxxxxxx"><!ENTITY y "&x;&x;&x;">]><assembly>&y;</assembly>"#;
    assert_eq!(parse_manifest(doctype), Err(ManifestError::DocType));
    let undefined = b"<assembly><autoElevate>&boom;</autoElevate></assembly>";
    assert!(matches!(
        parse_manifest(undefined),
        Err(ManifestError::Xml(_))
    ));
    let deep = format!(
        "{}{}",
        "<a>".repeat(MAX_DEPTH + 1),
        "</a>".repeat(MAX_DEPTH + 1)
    );
    assert_eq!(parse_manifest(deep.as_bytes()), Err(ManifestError::TooDeep));
    let big = vec![b' '; MAX_MANIFEST_SIZE + 1];
    assert_eq!(
        parse_manifest(&big),
        Err(ManifestError::TooLarge(MAX_MANIFEST_SIZE + 1))
    );
    assert_eq!(
        parse_manifest(b"\xff\xfe<\0a\0/\0>\0"),
        Err(ManifestError::NotUtf8)
    );
    assert!(matches!(
        parse_manifest(b"<a></b>"),
        Err(ManifestError::Xml(_))
    ));

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
fn limits_bound_the_work() {
    let many: String = (0..100)
        .map(|i| format!(r#"<supportedOS Id="{i}"/>"#))
        .collect();
    let m = parse_manifest(format!("<a>{many}</a>").as_bytes()).unwrap();
    assert_eq!(m.supported_os.len(), pe::manifest::MAX_SUPPORTED_OS);
    assert!(m.truncated);
    let long = "x".repeat(5000);
    let m =
        parse_manifest(format!(r#"<a><assemblyIdentity name="{long}"/></a>"#).as_bytes()).unwrap();
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
    let invoker = br#"<assembly><requestedExecutionLevel level="asInvoker"/></assembly>"#;
    let info = parse(&with_manifest(invoker).build());
    let e = info.requires_elevation(Some("setup.exe"));
    assert_eq!(
        (e.requires_elevation, e.reason),
        (false, ElevationReason::ManifestAsInvoker)
    );
    let highest = br#"<assembly><requestedExecutionLevel level="highestAvailable"/></assembly>"#;
    let e = parse(&with_manifest(highest).build()).requires_elevation(None);
    assert_eq!(e.reason, ElevationReason::HighestAvailable);
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
}

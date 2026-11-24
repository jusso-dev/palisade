//! Content-based file type detection (#44).
//!
//! Every fixture is built byte by byte here or by `common::PeBuilder`; no
//! third-party binaries are checked in.

#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

mod common;

use std::ffi::OsStr;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use common::*;
use palisade_fileid::filetype::{
    self, CLASSIFIER_VERSION, Classification, Confidence, DotNetKind, ExtensionKind, FileKind,
    HEAD_LEN, HybridKind, MAX_COM_SIZE, MAX_TARGETED_READ, MismatchSeverity, ParseError, PeSubKind,
    ScriptKind, TextEncoding,
};
use proptest::prelude::*;

fn classify(data: &[u8], name: Option<&str>) -> Classification {
    filetype::classify_bytes(data, name.map(OsStr::new))
}

fn kind(data: &[u8], name: Option<&str>) -> FileKind {
    classify(data, name).content_kind
}

fn put16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// PE fixtures
// ---------------------------------------------------------------------------

/// Adds a data section built by `body(rva)` and points the given data
/// directories (index, offset within the section, size) into it.
fn pe_with(mut b: PeBuilder, body: impl Fn(u32) -> Vec<u8>, dirs: &[(usize, u32, u32)]) -> Vec<u8> {
    let rva = SECTION_ALIGNMENT * (b.sections.len() as u32 + 1);
    b = b.section(
        ".data",
        body(rva),
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    );
    let mut image = b.build();
    for &(index, offset, size) in dirs {
        let at = b.data_directory_offset(index);
        put32(&mut image, at, rva + offset);
        put32(&mut image, at + 4, size);
    }
    image
}

/// An import table importing from each of `modules`.
fn imports<'a>(modules: &'a [&'a str]) -> impl Fn(u32) -> Vec<u8> + 'a {
    move |rva| {
        let mut out = vec![0_u8; 0x400];
        for (i, module) in modules.iter().enumerate() {
            let name_at = 0x200 + i * 0x20;
            out[name_at..name_at + module.len()].copy_from_slice(module.as_bytes());
            put32(&mut out, i * 20 + 12, rva + name_at as u32);
            put32(&mut out, i * 20 + 16, rva + 0x380);
        }
        out
    }
}

/// An export table naming each of `names`.
fn exports<'a>(names: &'a [&'a str]) -> impl Fn(u32) -> Vec<u8> + 'a {
    move |rva| {
        let mut out = vec![0_u8; 0x400];
        put32(&mut out, 24, names.len() as u32);
        put32(&mut out, 32, rva + 0x100);
        for (i, name) in names.iter().enumerate() {
            let at = 0x200 + i * 0x20;
            out[at..at + name.len()].copy_from_slice(name.as_bytes());
            put32(&mut out, 0x100 + i * 4, rva + at as u32);
        }
        out
    }
}

/// Exports at 0, and a resource root with one named type at 0x400.
fn exports_and_named_resource(
    names: &'static [&'static str],
    ty: &'static str,
) -> impl Fn(u32) -> Vec<u8> {
    move |rva| {
        let mut out = exports(names)(rva);
        out.resize(0x800, 0);
        let root = 0x400;
        put16(&mut out, root + 12, 1);
        put32(&mut out, root + 16, 0x8000_0000 | 0x100);
        put32(&mut out, root + 20, 0x8000_0000 | 0x200);
        let s = root + 0x100;
        put16(&mut out, s, ty.len() as u16);
        for (i, unit) in ty.encode_utf16().enumerate() {
            put16(&mut out, s + 2 + 2 * i, unit);
        }
        out
    }
}

fn pe_details(data: &[u8], name: Option<&str>) -> palisade_fileid::filetype::PeDetails {
    let c = classify(data, name);
    assert_eq!(c.content_kind, FileKind::Pe, "{c:?}");
    c.pe.unwrap()
}

#[test]
fn pe_exe_and_dll() {
    let exe = PeBuilder::default().build();
    let d = pe_details(&exe, None);
    assert_eq!(d.sub_kind, PeSubKind::Exe);
    assert!(!d.is_dll && !d.incomplete);
    assert_eq!(
        pe_details(&PeBuilder::pe32().build(), None).sub_kind,
        PeSubKind::Exe
    );
    let dll = PeBuilder {
        entry_point: 0x1000,
        ..PeBuilder::dll()
    }
    .build();
    assert_eq!(pe_details(&dll, None).sub_kind, PeSubKind::Dll);
}

#[test]
fn pe_screen_saver_needs_its_name() {
    let exe = PeBuilder::default().build();
    let c = classify(&exe, Some("bubbles.SCR"));
    assert_eq!(c.pe.unwrap().sub_kind, PeSubKind::Scr);
    assert!(c.extension_assisted && !c.mismatch);
    assert_eq!(pe_details(&exe, Some("bubbles")).sub_kind, PeSubKind::Exe);
}

#[test]
fn pe_resource_only() {
    let mut b = PeBuilder::dll();
    b.sections[0].characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    assert_eq!(
        pe_details(&b.build(), None).sub_kind,
        PeSubKind::ResourceOnly
    );
    // An entry point makes it a DLL again.
    b.entry_point = 0x1000;
    assert_eq!(pe_details(&b.build(), None).sub_kind, PeSubKind::Dll);
}

#[test]
fn pe_drivers() {
    // Native subsystem importing from the kernel.
    let native = PeBuilder {
        subsystem: 1,
        ..PeBuilder::default()
    };
    let sys = pe_with(
        native.clone(),
        imports(&["ntoskrnl.exe", "HAL.dll"]),
        &[(1, 0, 40)],
    );
    let d = pe_details(&sys, Some("x.sys"));
    assert_eq!(d.sub_kind, PeSubKind::Driver);
    assert!(d.imports_kernel && !d.incomplete);
    assert!(!classify(&sys, Some("x.sys")).mismatch);

    // A kernel-mode framework library.
    let wdf = pe_with(
        PeBuilder::default(),
        imports(&["WDFLDR.SYS"]),
        &[(1, 0, 20)],
    );
    assert_eq!(pe_details(&wdf, None).sub_kind, PeSubKind::Driver);

    // Native subsystem importing only from ntdll: a native user-mode
    // program, not a driver.
    let smss = pe_with(native.clone(), imports(&["ntdll.dll"]), &[(1, 0, 20)]);
    assert_eq!(pe_details(&smss, None).sub_kind, PeSubKind::Exe);

    // Native subsystem with no imports at all is taken to be a driver.
    assert_eq!(
        pe_details(&native.build(), None).sub_kind,
        PeSubKind::Driver
    );

    // WDM_DRIVER set.
    let wdm = PeBuilder {
        dll_characteristics: 0x2000,
        ..PeBuilder::default()
    };
    assert_eq!(pe_details(&wdm.build(), None).sub_kind, PeSubKind::Driver);
}

/// The full-file parser's driver verdict (#45) and the sub-kind agree: a
/// native image with an `INIT` section or `IMAGE_FILE_SYSTEM` is a driver
/// even when it also imports from `ntdll.dll`, and neither signal makes a
/// non-native image one.
#[test]
fn pe_drivers_agree_with_the_parser() {
    let native = PeBuilder {
        subsystem: 1,
        ..PeBuilder::default()
    };
    let init = native.clone().section(
        "INIT",
        vec![0xc3; 0x40],
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    );
    let system = PeBuilder {
        characteristics: native.characteristics | 0x1000,
        ..native.clone()
    };
    let user_init = PeBuilder::default().section(
        "INIT",
        vec![0xc3; 0x40],
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    );
    for (builder, driver) in [
        (init, true),
        (system, true),
        (native, false),
        (user_init, false),
    ] {
        let image = pe_with(builder, imports(&["ntdll.dll"]), &[(1, 0, 20)]);
        let info = palisade_fileid::pe::parse(&image).unwrap();
        assert_eq!(info.is_kernel_driver(), driver, "{:?}", info.driver);
        let d = pe_details(&image, None);
        assert!(!d.incomplete);
        assert_eq!(d.sub_kind == PeSubKind::Driver, driver, "{d:?}");
    }
}

/// The import table ends at the first descriptor with no name or no import
/// address table, as the loader and `pe::PeInfo::imports` read it. A kernel
/// module named in or after that terminator is never imported.
#[test]
fn pe_import_table_stops_where_the_loader_does() {
    // Descriptors: (name, FirstThunk) pairs; a name of `None` is RVA 0.
    type Descriptor = (Option<&'static str>, bool);
    let table = |entries: &'static [Descriptor]| {
        move |rva: u32| {
            let mut out = vec![0_u8; 0x400];
            for (i, (module, thunks)) in entries.iter().enumerate() {
                if let Some(module) = module {
                    let at = 0x200 + i * 0x20;
                    out[at..at + module.len()].copy_from_slice(module.as_bytes());
                    put32(&mut out, i * 20 + 12, rva + at as u32);
                }
                if *thunks {
                    put32(&mut out, i * 20 + 16, rva + 0x380);
                }
                // A set time stamp, so no descriptor is all zeros.
                put32(&mut out, i * 20 + 4, 0xdead_beef);
            }
            out
        }
    };
    let native = PeBuilder {
        subsystem: 1,
        ..PeBuilder::default()
    };
    let cases: [(PeBuilder, &[Descriptor], PeSubKind); 4] = [
        // A kernel module in a terminator with no import address table.
        (
            PeBuilder::default(),
            &[(Some("kernel32.dll"), true), (Some("ntoskrnl.exe"), false)],
            PeSubKind::Exe,
        ),
        // A kernel module after a terminator with no name.
        (
            PeBuilder::default(),
            &[(None, true), (Some("ntoskrnl.exe"), true)],
            PeSubKind::Exe,
        ),
        // A native image importing from ntdll, then a decoy kernel import.
        (
            native.clone(),
            &[(Some("ntdll.dll"), true), (Some("hal.dll"), false)],
            PeSubKind::Exe,
        ),
        // A native image whose only "import" of ntdll is a terminator: it
        // imports nothing, so it is a driver.
        (native, &[(Some("ntdll.dll"), false)], PeSubKind::Driver),
    ];
    for (builder, entries, sub_kind) in cases {
        let image = pe_with(builder, table(entries), &[(1, 0, 20)]);
        let info = palisade_fileid::pe::parse(&image).unwrap();
        let d = pe_details(&image, None);
        assert_eq!(d.sub_kind, sub_kind, "{entries:?}: {d:?}");
        assert!(!d.incomplete && !d.imports_kernel, "{entries:?}: {d:?}");
        // The parser reads the same table: no kernel module import. (The
        // last case is a driver here by #44's native-subsystem rule, which
        // needs no kernel signal; the parser's verdict does.)
        assert!(!info.is_kernel_driver(), "{entries:?}: {:?}", info.driver);
        assert!(
            !info
                .driver
                .signals
                .iter()
                .any(|s| matches!(s, palisade_fileid::pe::DriverSignal::ImportsKernelModule(_))),
            "{entries:?}: {:?}",
            info.driver
        );
    }
}

/// A PE whose header bytes run to the end of the file (here, one cut off
/// just after its section table, so its import table is past the end) is
/// classified from its headers alone: the result matches the same headers
/// in a longer file, and is a PE whose directory reads were incomplete.
#[test]
fn pe_headers_to_the_end_of_the_file() {
    let native = PeBuilder {
        subsystem: 1,
        ..PeBuilder::default()
    };
    let full = pe_with(native.clone(), imports(&["ntoskrnl.exe"]), &[(1, 0, 20)]);
    let table_end = native.section_table_offset() + 2 * 40;
    let cut = &full[..table_end];
    let d = pe_details(cut, None);
    assert!(d.incomplete && !d.imports_kernel, "{d:?}");
    // One more byte makes it a prefix of a longer file; same answer.
    assert_eq!(pe_details(&full[..=table_end], None), d);
}

#[test]
fn pe_efi() {
    for subsystem in 10..=13 {
        let b = PeBuilder {
            subsystem,
            ..PeBuilder::default()
        };
        assert_eq!(pe_details(&b.build(), None).sub_kind, PeSubKind::Efi);
    }
}

#[test]
fn pe_control_panel_item() {
    let cpl = pe_with(
        PeBuilder {
            entry_point: 0x1000,
            ..PeBuilder::dll()
        },
        exports(&["CPlApplet"]),
        &[(0, 0, 40)],
    );
    let d = pe_details(&cpl, Some("desk.cpl"));
    assert_eq!(d.sub_kind, PeSubKind::Cpl);
    assert!(d.exports_cpl_applet);
    // An executable exporting it is not one.
    let exe = pe_with(PeBuilder::default(), exports(&["CPlApplet"]), &[(0, 0, 40)]);
    assert_eq!(pe_details(&exe, None).sub_kind, PeSubKind::Exe);
}

#[test]
fn pe_activex_control() {
    let dll = PeBuilder {
        entry_point: 0x1000,
        ..PeBuilder::dll()
    };
    let ocx = pe_with(
        dll.clone(),
        exports_and_named_resource(&["DllCanUnloadNow", "DllRegisterServer"], "TYPELIB"),
        &[(0, 0, 40), (2, 0x400, 0x400)],
    );
    let d = pe_details(&ocx, None);
    assert_eq!(d.sub_kind, PeSubKind::Ocx);
    assert!(d.exports_dll_register_server && d.has_type_library);
    let c = classify(&ocx, Some("grid.ocx"));
    assert!(!c.mismatch);

    // Registration without a type library is a plain DLL; a DLL renamed to
    // `.ocx` is a benign mismatch.
    let plain = pe_with(
        dll,
        exports_and_named_resource(&["DllRegisterServer"], "REGISTRY"),
        &[(0, 0, 40), (2, 0x400, 0x400)],
    );
    let c = classify(&plain, Some("grid.ocx"));
    assert_eq!(c.pe.unwrap().sub_kind, PeSubKind::Dll);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Benign);
}

#[test]
fn pe_dot_net() {
    let clr = |flags: u32| {
        move |_rva: u32| {
            let mut out = vec![0_u8; 0x48];
            put32(&mut out, 0, 0x48);
            put32(&mut out, 0x10, flags);
            out
        }
    };
    let il = pe_with(PeBuilder::default(), clr(1), &[(14, 0, 0x48)]);
    assert_eq!(pe_details(&il, None).dot_net, Some(DotNetKind::IlOnly));
    let mixed = pe_with(PeBuilder::default(), clr(0x10), &[(14, 0, 0x48)]);
    assert_eq!(pe_details(&mixed, None).dot_net, Some(DotNetKind::Mixed));
    // A CLR directory pointing nowhere.
    let mut broken = PeBuilder::default().build();
    let at = PeBuilder::default().data_directory_offset(14);
    put32(&mut broken, at, 0x00f0_0000);
    put32(&mut broken, at + 4, 0x48);
    let d = pe_details(&broken, None);
    assert_eq!(d.dot_net, Some(DotNetKind::Unknown));
    assert!(d.incomplete);
    assert_eq!(
        pe_details(&PeBuilder::default().build(), None).dot_net,
        None
    );
}

#[test]
fn pe_hybrid_layouts() {
    let config = |_rva: u32| {
        let mut out = vec![0_u8; 0x140];
        put32(&mut out, 0, 0x140);
        out[0xc8..0xd0].copy_from_slice(&0x1_4000_2000_u64.to_le_bytes());
        out
    };
    let arm64 = PeBuilder {
        machine: 0xaa64,
        ..PeBuilder::default()
    };
    let x = pe_with(arm64.clone(), config, &[(10, 0, 0x140)]);
    assert_eq!(pe_details(&x, None).hybrid, Some(HybridKind::Arm64X));
    assert_eq!(pe_details(&arm64.build(), None).hybrid, None);
    let amd64 = pe_with(PeBuilder::default(), config, &[(10, 0, 0x140)]);
    assert_eq!(pe_details(&amd64, None).hybrid, Some(HybridKind::Arm64Ec));
    // A load configuration too small to hold the pointer.
    let small = |_rva: u32| {
        let mut out = vec![0_u8; 0x140];
        put32(&mut out, 0, 0x70);
        out[0xc8..0xd0].copy_from_slice(&1_u64.to_le_bytes());
        out
    };
    let small = pe_with(PeBuilder::default(), small, &[(10, 0, 0x140)]);
    assert_eq!(pe_details(&small, None).hybrid, None);
    for (machine, want) in [
        (0xa64e, HybridKind::Arm64X),
        (0xa641, HybridKind::Arm64Ec),
        (0x3a64, HybridKind::Chpe),
    ] {
        let b = PeBuilder {
            machine,
            ..PeBuilder::default()
        };
        assert_eq!(pe_details(&b.build(), None).hybrid, Some(want));
    }
}

#[test]
fn pe_header_past_the_head() {
    // `e_lfanew` beyond the 64 KiB head is read with a targeted read.
    let image = PeBuilder::default().build();
    let shift = 0x2_0000;
    let mut moved = vec![0_u8; image.len() + shift];
    moved[..0x40].copy_from_slice(&image[..0x40]);
    put32(&mut moved, 0x3c, (E_LFANEW + shift) as u32);
    moved[E_LFANEW + shift..0x400 + shift].copy_from_slice(&image[E_LFANEW..0x400]);
    // Section data is not needed to classify.
    let c = classify(&moved, None);
    assert_eq!(c.content_kind, FileKind::Pe, "{c:?}");
}

#[test]
fn broken_pe_headers_stay_executable() {
    let mut image = PeBuilder::default().build();
    put16(&mut image, OPT_OFFSET, 0x999);
    let c = classify(&image, None);
    assert_eq!(c.content_kind, FileKind::Mz16);
    assert!(matches!(c.parse_error, Some(ParseError::Pe(_))));
    assert!(c.is_executable_content());

    // `e_lfanew` past the end of the file: a plain DOS program.
    let mut far = PeBuilder::default().build();
    put32(&mut far, 0x3c, 0x0200_0000);
    assert_eq!(kind(&far, None), FileKind::Mz16);
    // Past the 1 MiB limit, inside the file.
    let mut huge = vec![0_u8; 0x0010_0100];
    huge[..2].copy_from_slice(b"MZ");
    put32(&mut huge, 0x3c, 0x0010_0004);
    huge[0x0010_0004..0x0010_0008].copy_from_slice(b"PE\0\0");
    let c = classify(&huge, None);
    assert_eq!(c.content_kind, FileKind::Mz16);
    assert!(matches!(c.parse_error, Some(ParseError::Pe(_))));

    // Every truncation still gives an executable kind, never a panic.
    for len in 28..image.len().min(0x500) {
        assert!(
            classify(&image[..len], None).is_executable_content(),
            "len {len}"
        );
    }
}

#[test]
fn older_mz_formats() {
    let mut dos = vec![0_u8; 0x80];
    dos[..2].copy_from_slice(b"MZ");
    assert_eq!(kind(&dos, None), FileKind::Mz16);
    for (sig, want) in [
        (b"NE", FileKind::Ne16),
        (b"LE", FileKind::Le),
        (b"LX", FileKind::Lx),
    ] {
        let mut image = dos.clone();
        put32(&mut image, 0x3c, 0x40);
        image[0x40..0x42].copy_from_slice(sig);
        assert_eq!(kind(&image, None), want);
        assert!(want.is_executable_content());
    }
    // Too short to be a DOS header.
    assert_eq!(kind(b"MZ", None), FileKind::Text);
    // Text that starts with `MZ`: its "header size" does not fit.
    let text = b"MZ is a pair of initials, and this is a plain note about them.\n";
    assert_eq!(kind(text, None), FileKind::Text);
    assert!(!classify(text, Some("a.txt")).mismatch);
}

// ---------------------------------------------------------------------------
// Compound files
// ---------------------------------------------------------------------------

/// A minimal version 3 compound file: header, then one directory sector
/// whose first entry is the root storage with `clsid`.
fn cfb(clsid: [u8; 16]) -> Vec<u8> {
    let mut out = vec![0_u8; 1024];
    out[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    put16(&mut out, 0x18, 0x3e);
    put16(&mut out, 0x1a, 3);
    put16(&mut out, 0x1c, 0xfffe);
    put16(&mut out, 0x1e, 9);
    put16(&mut out, 0x20, 6);
    put32(&mut out, 0x30, 0);
    let entry = 512;
    for (i, unit) in "Root Entry".encode_utf16().enumerate() {
        put16(&mut out, entry + 2 * i, unit);
    }
    put16(&mut out, entry + 0x40, 22);
    out[entry + 0x42] = 5;
    out[entry + 0x50..entry + 0x60].copy_from_slice(&clsid);
    out
}

fn installer_clsid(d1: u32) -> [u8; 16] {
    let mut g = [0_u8; 16];
    g[..4].copy_from_slice(&d1.to_le_bytes());
    g[8] = 0xc0;
    g[15] = 0x46;
    g
}

#[test]
fn installers_by_clsid() {
    assert_eq!(
        kind(&cfb(installer_clsid(0x000c_1084)), None),
        FileKind::Msi
    );
    assert_eq!(
        kind(&cfb(installer_clsid(0x000c_1086)), None),
        FileKind::Msp
    );
    assert_eq!(
        kind(&cfb(installer_clsid(0x000c_1082)), None),
        FileKind::Mst
    );
    let msm = classify(&cfb(installer_clsid(0x000c_1084)), Some("module.msm"));
    assert_eq!(msm.content_kind, FileKind::Msm);
    assert!(msm.extension_assisted && !msm.mismatch);
    // An installer database named `.msm` is fine either way.
    assert!(!classify(&cfb(installer_clsid(0x000c_1084)), Some("a.msi")).mismatch);
    let other = classify(&cfb([7; 16]), None);
    assert_eq!(other.content_kind, FileKind::OtherCfb);
    assert!(!other.flags.macro_capable_container && !other.is_executable_content());
}

#[test]
fn office_documents_are_flagged() {
    let doc = classify(&cfb(installer_clsid(0x0002_0906)), Some("letter.doc"));
    assert_eq!(doc.content_kind, FileKind::OtherCfb);
    assert!(doc.flags.macro_capable_container);
    assert!(!doc.mismatch);
}

#[test]
fn version_4_compound_file() {
    let v3 = cfb(installer_clsid(0x000c_1084));
    let mut v4 = vec![0_u8; 4096 * 2];
    v4[..512].copy_from_slice(&v3[..512]);
    put16(&mut v4, 0x1a, 4);
    put16(&mut v4, 0x1e, 12);
    v4[4096..4096 + 128].copy_from_slice(&v3[512..640]);
    assert_eq!(kind(&v4, None), FileKind::Msi);
}

#[test]
fn broken_compound_files() {
    let good = cfb(installer_clsid(0x000c_1084));
    let mut bad_order = good.clone();
    put16(&mut bad_order, 0x1c, 0xfeff);
    let c = classify(&bad_order, None);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::OtherCfb, Some(ParseError::CfbHeader))
    );
    let mut bad_sector = good.clone();
    put32(&mut bad_sector, 0x30, 0xffff_fffe);
    assert_eq!(
        classify(&bad_sector, None).parse_error,
        Some(ParseError::CfbDirectory)
    );
    let mut bad_type = good.clone();
    bad_type[512 + 0x42] = 1;
    assert_eq!(
        classify(&bad_type, None).parse_error,
        Some(ParseError::CfbDirectory)
    );
    let c = classify(&good[..600], None);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::OtherCfb, Some(ParseError::CfbDirectory))
    );
    let mut far = good;
    put32(&mut far, 0x30, 0x00ff_ffff);
    assert_eq!(
        classify(&far, None).parse_error,
        Some(ParseError::CfbDirectory)
    );
}

// ---------------------------------------------------------------------------
// ZIP containers
// ---------------------------------------------------------------------------

/// A stored (uncompressed) ZIP archive of empty entries, after `prefix`.
fn zip(prefix: &[u8], names: &[&str]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    let mut central = Vec::new();
    for name in names {
        let local = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&local.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let dir_at = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(names.len() as u16).to_le_bytes());
    out.extend_from_slice(&(names.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&dir_at.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// A ZIP whose structure readers could read differently: the reason is
/// reported, and the file is treated as possibly executable.
#[track_caller]
fn assert_fails_closed(c: &Classification, want: ParseError) {
    assert_eq!(c.parse_error.as_ref(), Some(&want), "{c:?}");
    assert!(c.is_executable_content(), "{c:?}");
}

#[test]
fn zip_containers_by_entries() {
    let package = zip(b"", &["AppxManifest.xml", "AppxSignature.p7x", "app.exe"]);
    let c = classify(&package, None);
    assert_eq!(c.content_kind, FileKind::Msix);
    assert!(c.flags.package_signature_present && c.is_executable_content());
    let c = classify(&package, Some("app.appx"));
    assert_eq!(c.content_kind, FileKind::Appx);
    assert!(c.extension_assisted && !c.mismatch);
    assert!(!classify(&package, Some("app.msix")).mismatch);

    let unsigned = classify(&zip(b"", &["appxmanifest.xml"]), None);
    assert_eq!(unsigned.content_kind, FileKind::Msix);
    assert!(!unsigned.flags.package_signature_present);

    let bundle = zip(
        b"",
        &[
            "AppxMetadata/AppxBundleManifest.xml",
            "AppxSignature.p7x",
            "AppxManifest.xml",
        ],
    );
    assert_eq!(kind(&bundle, None), FileKind::MsixBundle);
    assert_eq!(kind(&bundle, Some("x.appxbundle")), FileKind::AppxBundle);

    assert_eq!(
        kind(&zip(b"", &["META-INF/MANIFEST.MF", "a.class"]), None),
        FileKind::Jar
    );
    assert_eq!(kind(&zip(b"", &["readme.txt"]), None), FileKind::Zip);
    assert_eq!(kind(&zip(b"", &[]), None), FileKind::Zip);
    // A manifest in a subfolder does not count.
    assert_eq!(
        kind(&zip(b"", &["sub/AppxManifest.xml"]), None),
        FileKind::Zip
    );

    let docm = classify(
        &zip(b"", &["[Content_Types].xml", "word/vbaProject.bin"]),
        Some("a.docm"),
    );
    assert_eq!(docm.content_kind, FileKind::Zip);
    assert!(docm.flags.macro_capable_container && !docm.is_executable_content());
}

#[test]
fn python_zip_applications() {
    let app = zip(b"#!/usr/bin/env python3\n", &["__main__.py", "lib.py"]);
    let c = classify(&app, None);
    assert_eq!(
        c.content_kind,
        FileKind::Script(ScriptKind::Python),
        "{c:?}"
    );
    assert!(c.flags.python_zipapp);
    let plain = zip(b"", &["__main__.py"]);
    assert_eq!(kind(&plain, None), FileKind::Zip);
    let c = classify(&plain, Some("tool.pyz"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Python));
    assert!(c.flags.python_zipapp && c.extension_assisted);
    // A shebang in front of a ZIP without `__main__.py` is text.
    let other = zip(b"#!/bin/sh\n", &["x"]);
    assert!(!classify(&other, None).flags.python_zipapp);
    // Behind a shebang, an archive that is not a clean zip application is
    // the script the shebang names, even if it lists `__main__.py`.
    let base = zip(b"#!/bin/sh\n", &["__main__.py"]);
    let end = base.len() - 22;
    let dir = u32::from_le_bytes(base[end + 16..end + 20].try_into().unwrap()) as usize;
    let mut uncounted = base.clone();
    put16(&mut uncounted, end + 8, 0);
    put16(&mut uncounted, end + 10, 0);
    let mut overflowing = base;
    put16(&mut overflowing, dir + 32, 500);
    for data in [uncounted, overflowing] {
        let c = classify(&data, Some("install.sh"));
        assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Shell), "{c:?}");
        assert!(!c.flags.python_zipapp && !c.mismatch, "{c:?}");
    }
    // Behind a shebang, an ambiguous archive is still a script.
    for names in [&["__main__.py"][..], &["x"]] {
        let mut junk = zip(b"#!/usr/bin/env python3\n", names);
        junk.push(b'X');
        let c = classify(&junk, Some("tool.pdf"));
        assert!(matches!(c.content_kind, FileKind::Script(_)), "{c:?}");
        assert!(c.is_executable_content());
    }
}

#[test]
fn zip_with_comment_and_zip64() {
    // An archive comment.
    let mut commented = zip(b"", &["AppxManifest.xml"]);
    let comment = b"built by hand";
    let n = commented.len();
    put16(&mut commented, n - 2, comment.len() as u16);
    commented.extend_from_slice(comment);
    let c = classify(&commented, None);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Msix, None));
    // A comment holding another end record: readers that take the last
    // signature take that one, so the layout is ambiguous.
    let mut decoy = zip(b"", &["AppxManifest.xml"]);
    let comment = b"PK\x05\x06decoy-decoy-decoy-decoy";
    let n = decoy.len();
    put16(&mut decoy, n - 2, comment.len() as u16);
    decoy.extend_from_slice(comment);
    assert_fails_closed(&classify(&decoy, None), ParseError::ZipDirectoryAmbiguous);

    // ZIP64: the end record's fields are all 0xFF and the real values are in
    // the ZIP64 end record.
    let base = zip(b"", &["META-INF/MANIFEST.MF"]);
    let end = base.len() - 22;
    let count = 1_u64;
    let size = u64::from(u32::from_le_bytes(
        base[end + 12..end + 16].try_into().unwrap(),
    ));
    let offset = u64::from(u32::from_le_bytes(
        base[end + 16..end + 20].try_into().unwrap(),
    ));
    let mut z64 = base[..end].to_vec();
    let record_at = z64.len() as u64;
    z64.extend_from_slice(b"PK\x06\x06");
    z64.extend_from_slice(&44_u64.to_le_bytes());
    z64.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z64.extend_from_slice(&count.to_le_bytes());
    z64.extend_from_slice(&count.to_le_bytes());
    z64.extend_from_slice(&size.to_le_bytes());
    z64.extend_from_slice(&offset.to_le_bytes());
    z64.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    z64.extend_from_slice(&record_at.to_le_bytes());
    z64.extend_from_slice(&1_u32.to_le_bytes());
    z64.extend_from_slice(
        b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\0",
    );
    assert_eq!(kind(&z64, None), FileKind::Jar);
}

#[test]
fn broken_zip_archives() {
    let good = zip(b"", &["AppxManifest.xml"]);
    // No end record.
    let c = classify(&good[..good.len() - 22], None);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::Zip, Some(ParseError::ZipDirectoryMissing))
    );
    // A directory size larger than the space before the end record: the
    // recorded offset and the end-relative start disagree.
    let mut big = good.clone();
    let end = big.len() - 22;
    put32(&mut big, end + 12, 0x7fff_ffff);
    assert_fails_closed(&classify(&big, None), ParseError::ZipDirectoryAmbiguous);
    // Both the size and the offset wrong.
    put32(&mut big, end + 16, 3);
    assert_fails_closed(&classify(&big, None), ParseError::ZipDirectoryAmbiguous);
    // A corrupt directory entry signature: not an entry, so readers that
    // stop there and readers that skip on see different entries.
    let mut sig = good.clone();
    let dir = u32::from_le_bytes(sig[end + 16..end + 20].try_into().unwrap()) as usize;
    sig[dir + 1] = b'X';
    assert_fails_closed(&classify(&sig, None), ParseError::ZipDirectoryAmbiguous);
    // A name running off the end of the directory.
    let mut name = good.clone();
    put16(&mut name, dir + 28, 0x7000);
    assert_fails_closed(&classify(&name, None), ParseError::ZipDirectoryMalformed);
    // Disk numbers other than 0 (a spanned archive).
    let mut spanned = good.clone();
    put16(&mut spanned, end + 4, 1);
    assert_fails_closed(&classify(&spanned, None), ParseError::ZipDirectoryAmbiguous);
    // The two entry counts disagree.
    let mut counts = good;
    put16(&mut counts, end + 8, 2);
    assert_fails_closed(&classify(&counts, None), ParseError::ZipDirectoryAmbiguous);
}

// ---------------------------------------------------------------------------
// Other magic numbers
// ---------------------------------------------------------------------------

fn lnk() -> Vec<u8> {
    let mut out = vec![0_u8; 0x4c];
    put32(&mut out, 0, 0x4c);
    out[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    out
}

fn iso(id: &[u8; 5]) -> Vec<u8> {
    let mut out = vec![0_u8; 0x9800];
    out[0x8000] = if id == b"CD001" { 1 } else { 0 };
    out[0x8001..0x8006].copy_from_slice(id);
    out[0x8006] = 1;
    out
}

#[test]
fn fixed_magic_numbers() {
    let cases: Vec<(Vec<u8>, FileKind)> = vec![
        (b"MSCF\0\0\0\0\x10\0\0\0".to_vec(), FileKind::Cab),
        (b"ITSF\x03\0\0\0".to_vec(), FileKind::Chm),
        (lnk(), FileKind::Lnk),
        (iso(b"CD001"), FileKind::Iso),
        (iso(b"BEA01"), FileKind::Iso),
        (
            vec![0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4],
            FileKind::SevenZip,
        ),
        (b"Rar!\x1a\x07\x00\xcf".to_vec(), FileKind::Rar),
        (b"Rar!\x1a\x07\x01\x00\x33".to_vec(), FileKind::Rar),
        (vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0], FileKind::Gzip),
        (b"\x7fELF\x02\x01\x01".to_vec(), FileKind::Elf),
        (vec![0xfe, 0xed, 0xfa, 0xce, 0, 0], FileKind::MachO),
        (vec![0xfe, 0xed, 0xfa, 0xcf, 0, 0], FileKind::MachO),
        (vec![0xce, 0xfa, 0xed, 0xfe, 0, 0], FileKind::MachO),
        (vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0], FileKind::MachO),
        (vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2], FileKind::MachO),
        (vec![0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 2], FileKind::MachO),
    ];
    for (data, want) in cases {
        let c = classify(&data, None);
        assert_eq!(c.content_kind, want, "{data:02x?}");
        assert_eq!(c.confidence, Confidence::High);
        assert!(c.parse_error.is_none());
        // Cut inside the magic: never the same kind.
        if want != FileKind::Iso && want != FileKind::Lnk {
            assert_ne!(kind(&data[..2], None), want);
        }
    }
    let lnk = lnk();
    assert_ne!(kind(&lnk[..19], None), FileKind::Lnk);
    let mut not_lnk = lnk.clone();
    not_lnk[10] ^= 1;
    assert_ne!(kind(&not_lnk, None), FileKind::Lnk);
    assert_ne!(kind(&iso(b"CD001")[..0x8006], None), FileKind::Iso);
    let mut bad_type = iso(b"BEA01");
    bad_type[0x8000] = 1;
    assert_ne!(kind(&bad_type, None), FileKind::Iso);
    assert_ne!(
        kind(b"ITSF is four letters, then text.\n", None),
        FileKind::Chm
    );
}

#[test]
fn python_bytecode() {
    let mut pyc = vec![0_u8; 32];
    put16(&mut pyc, 0, 3495);
    pyc[2..4].copy_from_slice(b"\r\n");
    assert_eq!(kind(&pyc, None), FileKind::Script(ScriptKind::Python));
    put32(&mut pyc, 4, 9);
    assert_ne!(kind(&pyc, None), FileKind::Script(ScriptKind::Python));
    // Old magic values need the name.
    let mut old = vec![0_u8; 32];
    put16(&mut old, 0, 62211);
    old[2..4].copy_from_slice(b"\r\n");
    put32(&mut old, 4, 0x5f00_0000);
    assert_ne!(kind(&old, None), FileKind::Script(ScriptKind::Python));
    let c = classify(&old, Some("m.pyc"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Python));
    assert!(c.extension_assisted);
    // Modern bytecode is recognised without the name.
    put32(&mut pyc, 4, 0);
    assert!(!classify(&pyc, Some("m.pyc")).extension_assisted);
}

// ---------------------------------------------------------------------------
// Text and scripts
// ---------------------------------------------------------------------------

const POWERSHELL: &str = "[CmdletBinding()]\nparam([string]$Path)\n$items = Get-ChildItem -Path $Path -ErrorAction Stop\n$items | ForEach-Object { Write-Output $_.Name }\n";
const BATCH: &str =
    "@echo off\r\nsetlocal\r\nset /a count=1\r\nif errorlevel 1 goto :fail\r\nexit /b 0\r\n";
const VBSCRIPT: &str = "Option Explicit\r\nDim shell\r\nSet shell = CreateObject(\"WScript.Shell\")\r\nWScript.Echo \"hi\"\r\nIf x Then\r\nEnd If\r\n";
const JSCRIPT: &str = "var shell = new ActiveXObject(\"WScript.Shell\");\nvar f = function (a) { return a === 1; };\n";
const HTA: &str = "<html><head><HTA:Application id=\"app\" /></head><body></body></html>";

fn utf16le(s: &str, bom: bool) -> Vec<u8> {
    let mut out = if bom { vec![0xff, 0xfe] } else { Vec::new() };
    out.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

#[test]
fn scripts_from_content() {
    let ps = classify(POWERSHELL.as_bytes(), None);
    assert_eq!(ps.content_kind, FileKind::Script(ScriptKind::PowerShell));
    assert_eq!(ps.confidence, Confidence::Medium);
    assert!(ps.heuristic && !ps.extension_assisted);
    assert_eq!(
        kind(BATCH.as_bytes(), None),
        FileKind::Script(ScriptKind::Batch)
    );
    assert_eq!(
        kind(VBSCRIPT.as_bytes(), None),
        FileKind::Script(ScriptKind::VbScript)
    );
    assert_eq!(
        kind(JSCRIPT.as_bytes(), None),
        FileKind::Script(ScriptKind::JScript)
    );
    let hta = classify(HTA.as_bytes(), None);
    assert_eq!(
        (hta.content_kind, hta.confidence),
        (FileKind::Hta, Confidence::High)
    );
    assert_eq!(
        kind(b"just some words, nothing more.\n", None),
        FileKind::Text
    );
}

#[test]
fn definite_markers() {
    let cases: &[(&str, FileKind)] = &[
        (
            "#!/usr/bin/env python3\nprint(1)\n",
            FileKind::Script(ScriptKind::Python),
        ),
        (
            "#!/bin/bash\necho hi\n",
            FileKind::Script(ScriptKind::Shell),
        ),
        ("#!/usr/bin/perl -w\n", FileKind::Script(ScriptKind::Perl)),
        ("#!/usr/bin/env ruby\n", FileKind::Script(ScriptKind::Ruby)),
        (
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\X]\r\n",
            FileKind::Reg,
        ),
        ("REGEDIT4\r\n", FileKind::Reg),
        (
            "<html>\n<?php echo 1; ?>",
            FileKind::Script(ScriptKind::Php),
        ),
        (
            "<?XML version=\"1.0\"?><scriptlet><registration progid=\"x\"/></scriptlet>",
            FileKind::Script(ScriptKind::Wsc),
        ),
        (
            "<component><registration/><script language=\"JScript\"></script></component>",
            FileKind::Script(ScriptKind::Wsc),
        ),
        (
            "<job id=\"a\"><script language=\"VBScript\">x</script></job>",
            FileKind::Script(ScriptKind::Wsf),
        ),
        (
            "<xsl:stylesheet xmlns:msxsl=\"urn:x\"><msxsl:script language=\"JScript\"/></xsl:stylesheet>",
            FileKind::Script(ScriptKind::Xsl),
        ),
        (
            "<?xml version=\"1.0\"?><PCSettings><SearchableContent><ApplicationInformation><DeepLink>x</DeepLink></ApplicationInformation></SearchableContent></PCSettings>",
            FileKind::Script(ScriptKind::SettingContent),
        ),
        (
            "[Version]\r\nSignature=\"$Windows NT$\"\r\n",
            FileKind::Script(ScriptKind::Inf),
        ),
    ];
    for (text, want) in cases {
        let c = classify(text.as_bytes(), None);
        assert_eq!(c.content_kind, *want, "{text}");
        assert_eq!(c.confidence, Confidence::High, "{text}");
        assert!(c.is_executable_content());
    }
    // A stylesheet without script is text.
    assert_eq!(
        kind(b"<xsl:stylesheet></xsl:stylesheet>", None),
        FileKind::Text
    );
}

#[test]
fn hta_by_name_needs_html() {
    let page = b"<html><body><script>var a = 1;</script></body></html>";
    let c = classify(page, Some("app.hta"));
    assert_eq!(c.content_kind, FileKind::Hta);
    assert!(c.extension_assisted && !c.mismatch);
    assert_ne!(kind(page, None), FileKind::Hta);
    // `.hta` with non-HTML text is not an HTML application by content.
    let c = classify(b"plain words\n", Some("app.hta"));
    assert_eq!(c.content_kind, FileKind::Text);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Benign);
}

#[test]
fn encodings_and_signature_blocks() {
    let mut bom8 = vec![0xef, 0xbb, 0xbf];
    bom8.extend_from_slice(HTA.as_bytes());
    let c = classify(&bom8, None);
    assert_eq!(
        (c.content_kind, c.text_encoding),
        (FileKind::Hta, Some(TextEncoding::Utf8Bom))
    );
    let c = classify(&utf16le(POWERSHELL, true), None);
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::PowerShell));
    assert_eq!(c.text_encoding, Some(TextEncoding::Utf16Le));
    let c = classify(&utf16le(HTA, false), None);
    assert_eq!(
        (c.content_kind, c.text_encoding),
        (FileKind::Hta, Some(TextEncoding::Utf16LeNoBom))
    );
    let mut be = vec![0xfe, 0xff];
    be.extend("REGEDIT4\r\n".encode_utf16().flat_map(u16::to_be_bytes));
    assert_eq!(kind(&be, None), FileKind::Reg);
    let mut u32le = vec![0xff, 0xfe, 0, 0];
    u32le.extend("#!/bin/sh\n".chars().flat_map(|c| (c as u32).to_le_bytes()));
    let c = classify(&u32le, None);
    assert_eq!(
        (c.content_kind, c.text_encoding),
        (
            FileKind::Script(ScriptKind::Shell),
            Some(TextEncoding::Utf32Le)
        )
    );

    // A signature block marker settles the language.
    let signed = "Write-Host hi\r\n# SIG # Begin signature block\r\n# MIIa\r\n# SIG # End signature block\r\n";
    let c = classify(signed.as_bytes(), None);
    assert_eq!(
        (c.content_kind, c.confidence),
        (FileKind::Script(ScriptKind::PowerShell), Confidence::High)
    );
    assert!(c.flags.script_signature_block);
    let vbs = "x = 1\r\n'' SIG '' Begin signature block\r\n";
    assert_eq!(
        kind(vbs.as_bytes(), None),
        FileKind::Script(ScriptKind::VbScript)
    );

    // The marker is found in the tail of a long file, past the head.
    let mut long = "Write-Host hi\r\n".repeat(HEAD_LEN / 8).into_bytes();
    long.extend_from_slice(b"# SIG # Begin signature block\r\n");
    let c = classify(&long, None);
    assert!(c.flags.script_signature_block);
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::PowerShell));
    let mut long16 = utf16le(&"x\r\n".repeat(HEAD_LEN / 4), true);
    long16.extend(utf16le("// SIG // Begin signature block\r\n", false));
    let c = classify(&long16, None);
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::JScript));

    let encoded = classify(b"#@~^XAAAAA==abcdef^#~@", Some("a.vbe"));
    assert_eq!(encoded.content_kind, FileKind::Script(ScriptKind::VbScript));
    assert!(encoded.flags.encoded_script);
    assert_eq!(
        kind(b"#@~^XAAAAA==abcdef^#~@", Some("a.jse")),
        FileKind::Script(ScriptKind::JScript)
    );
}

#[test]
fn extension_decides_weak_script_guesses() {
    // Plain text in a script's name is that script.
    let c = classify(b"echo hello\r\n", Some("run.cmd"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Batch));
    assert!(c.heuristic && c.extension_assisted && !c.mismatch);
    assert_eq!(c.confidence, Confidence::Low);
    // A keyword guess of another language does not override the name.
    let c = classify(VBSCRIPT.as_bytes(), Some("a.js"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::JScript));
    assert!(!c.mismatch);
    // A definite marker does.
    let c = classify(b"#!/usr/bin/env python3\n", Some("a.js"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Python));
    assert_eq!(c.mismatch_severity, MismatchSeverity::Benign);
    for ext in ["bat", "cmd", "vbs", "js"] {
        let name = format!("x.{ext}");
        assert!(
            matches!(kind(b"a\nb\n", Some(&name)), FileKind::Script(_)),
            "{ext}"
        );
    }
}

#[test]
fn binary_noise_is_unknown() {
    let noise: Vec<u8> = (0..4096_u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let c = classify(&noise, None);
    assert_eq!(c.content_kind, FileKind::Unknown);
    assert!(!c.mismatch && !c.is_executable_content());
    assert_eq!(
        classify(&noise, Some("photo.jpg")).mismatch_severity,
        MismatchSeverity::None
    );
    let empty = classify(b"", Some("x.exe"));
    assert_eq!(
        (empty.content_kind, empty.mismatch),
        (FileKind::Unknown, false)
    );
    assert_eq!(empty.file_size, 0);
}

#[test]
fn dos_com_programs() {
    let code: Vec<u8> = (0..512_u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let c = classify(&code, Some("EDIT.COM"));
    assert_eq!(c.content_kind, FileKind::Com);
    assert!(c.heuristic && c.extension_assisted && !c.mismatch);
    assert!(c.is_executable_content());
    assert_eq!(kind(&code, None), FileKind::Unknown);
    let sized = |len: usize| -> Vec<u8> { code.iter().copied().cycle().take(len).collect() };
    let c = classify(&sized(MAX_COM_SIZE as usize + 1), Some("a.com"));
    assert_eq!(c.content_kind, FileKind::Unknown);
    assert!(!c.mismatch);
    assert_eq!(
        kind(&sized(MAX_COM_SIZE as usize), Some("a.com")),
        FileKind::Com
    );
    // Text named `.com` is a DOS program too: the system would run it.
    assert_eq!(kind(b"hello\n", Some("a.com")), FileKind::Com);
    // Recognised magic wins over the name.
    assert_eq!(kind(b"MSCF\0\0\0\0", Some("a.com")), FileKind::Cab);
    let pe = classify(&PeBuilder::default().build(), Some("a.com"));
    assert_eq!((pe.content_kind, pe.mismatch), (FileKind::Pe, false));
}

// ---------------------------------------------------------------------------
// The issue's acceptance corpus
// ---------------------------------------------------------------------------

#[test]
fn renamed_files_are_mismatches() {
    let pe = PeBuilder::default().build();
    for name in ["invoice.pdf", "notes.txt", "cat.jpg"] {
        let c = classify(&pe, Some(name));
        assert_eq!(c.content_kind, FileKind::Pe);
        assert_eq!(c.extension_kind, ExtensionKind::Inert);
        assert!(c.mismatch);
        assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious, "{name}");
    }
    let msi = classify(&cfb(installer_clsid(0x000c_1084)), Some("readme.txt"));
    assert_eq!(msi.content_kind, FileKind::Msi);
    assert_eq!(msi.mismatch_severity, MismatchSeverity::Suspicious);
    let script = classify(POWERSHELL.as_bytes(), Some("holiday.jpg"));
    assert_eq!(
        script.content_kind,
        FileKind::Script(ScriptKind::PowerShell)
    );
    assert_eq!(script.mismatch_severity, MismatchSeverity::Suspicious);

    for name in [
        "invoice.pdf.exe",
        "invoice\u{202E}fdp.exe",
        "a\u{202E}gpj.scr",
    ] {
        let c = classify(&pe, Some(name));
        assert_eq!(c.mismatch_severity, MismatchSeverity::Critical, "{name}");
        assert!(c.flags.name_bidi_control || c.flags.name_double_extension);
    }
    // A bidi control on inert content is not a mismatch.
    let c = classify(b"hello\n", Some("a\u{202E}txt.txt"));
    assert!(c.flags.name_bidi_control && !c.mismatch);

    // A PE behind an unknown name is benign; text named `.exe` too.
    assert_eq!(
        classify(&pe, Some("setup.tmp")).mismatch_severity,
        MismatchSeverity::Benign
    );
    assert_eq!(
        classify(b"hello\n", Some("x.exe")).mismatch_severity,
        MismatchSeverity::Benign
    );
    // Matching names.
    assert!(!classify(&pe, Some("app.exe")).mismatch);
    assert!(!classify(&pe, None).mismatch);
    assert_eq!(
        classify(&pe, Some("C:\\dir\\APP.EXE")).extension.as_deref(),
        Some("exe")
    );
}

#[test]
fn security_baseline_types_from_content_alone() {
    let dll = PeBuilder {
        entry_point: 0x1000,
        ..PeBuilder::dll()
    };
    let ocx = pe_with(
        dll.clone(),
        exports_and_named_resource(&["DllRegisterServer"], "TYPELIB"),
        &[(0, 0, 40), (2, 0x400, 0x400)],
    );
    let cpl = pe_with(dll.clone(), exports(&["CPlApplet"]), &[(0, 0, 40)]);
    // exe, dll, ocx, cpl, ps1, msi, msp, mst, chm, hta: no name at all.
    let pe_cases = [
        (PeBuilder::default().build(), PeSubKind::Exe),
        (dll.build(), PeSubKind::Dll),
        (ocx, PeSubKind::Ocx),
        (cpl, PeSubKind::Cpl),
    ];
    for (image, want) in pe_cases {
        assert_eq!(pe_details(&image, None).sub_kind, want);
    }
    assert_eq!(
        kind(POWERSHELL.as_bytes(), None),
        FileKind::Script(ScriptKind::PowerShell)
    );
    assert_eq!(
        kind(&cfb(installer_clsid(0x000c_1084)), None),
        FileKind::Msi
    );
    assert_eq!(
        kind(&cfb(installer_clsid(0x000c_1086)), None),
        FileKind::Msp
    );
    assert_eq!(
        kind(&cfb(installer_clsid(0x000c_1082)), None),
        FileKind::Mst
    );
    assert_eq!(kind(b"ITSF\x03\0\0\0", None), FileKind::Chm);
    assert_eq!(kind(HTA.as_bytes(), None), FileKind::Hta);
    // bat, cmd, vbs, js: content heuristics, which the extension may assist.
    assert_eq!(
        kind(BATCH.as_bytes(), None),
        FileKind::Script(ScriptKind::Batch)
    );
    assert_eq!(
        kind(VBSCRIPT.as_bytes(), None),
        FileKind::Script(ScriptKind::VbScript)
    );
    assert_eq!(
        kind(JSCRIPT.as_bytes(), None),
        FileKind::Script(ScriptKind::JScript)
    );
    // com has no magic; the issue's rule needs the extension.
    assert_eq!(
        kind(&[0xb4, 0x4c, 0xcd, 0x21], Some("x.com")),
        FileKind::Com
    );
}

#[test]
fn every_result_carries_the_version() {
    for data in [&b""[..], b"x", b"MZ", &PeBuilder::default().build()] {
        assert_eq!(classify(data, None).classifier_version, CLASSIFIER_VERSION);
    }
}

#[test]
fn executable_content_kinds() {
    let runs = [
        FileKind::Pe,
        FileKind::Ne16,
        FileKind::Le,
        FileKind::Lx,
        FileKind::Mz16,
        FileKind::Com,
        FileKind::Msi,
        FileKind::Msp,
        FileKind::Mst,
        FileKind::Msm,
        FileKind::Msix,
        FileKind::Appx,
        FileKind::MsixBundle,
        FileKind::AppxBundle,
        FileKind::Jar,
        FileKind::Chm,
        FileKind::Hta,
        FileKind::Lnk,
        FileKind::Reg,
        FileKind::Script(ScriptKind::Batch),
        FileKind::Script(ScriptKind::SettingContent),
    ];
    for k in runs {
        assert!(k.is_executable_content(), "{k:?}");
    }
    for k in [
        FileKind::OtherCfb,
        FileKind::Cab,
        FileKind::Zip,
        FileKind::Iso,
        FileKind::SevenZip,
        FileKind::Rar,
        FileKind::Gzip,
        FileKind::Text,
        FileKind::Unknown,
    ] {
        assert!(!k.is_executable_content(), "{k:?}");
    }
}

// ---------------------------------------------------------------------------
// Bounded reads and hostile readers
// ---------------------------------------------------------------------------

/// A reader over `len` virtual bytes, produced by `byte(offset)`, that
/// counts every byte it returns.
struct Virtual<F> {
    len: u64,
    pos: u64,
    byte: F,
    read: u64,
}

impl<F: Fn(u64) -> u8> Read for Virtual<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.len.saturating_sub(self.pos)).min(buf.len() as u64) as usize;
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = (self.byte)(self.pos + i as u64);
        }
        self.pos += n as u64;
        self.read += n as u64;
        Ok(n)
    }
}

impl<F> Seek for Virtual<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => self.len.checked_add_signed(d).unwrap(),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).unwrap(),
        };
        Ok(self.pos)
    }
}

const READ_BOUND: u64 = (HEAD_LEN + MAX_TARGETED_READ) as u64;

#[test]
fn large_sparse_files_are_read_in_bounded_amounts() {
    const GIB: u64 = 1 << 30;
    // Zeros, text and a ZIP-looking prefix, each 1 GiB long.
    let zero = |_| 0;
    let script = POWERSHELL.as_bytes();
    let text = |o: u64| script[(o % script.len() as u64) as usize];
    let zipish = |o: u64| if o < 4 { b"PK\x03\x04"[o as usize] } else { 0 };
    let mut a = Virtual {
        len: GIB,
        pos: 0,
        byte: zero,
        read: 0,
    };
    assert_eq!(
        filetype::classify(&mut a, None).content_kind,
        FileKind::Unknown
    );
    assert!(a.read <= READ_BOUND);
    let mut b = Virtual {
        len: GIB,
        pos: 0,
        byte: text,
        read: 0,
    };
    assert!(matches!(
        filetype::classify(&mut b, None).content_kind,
        FileKind::Script(_)
    ));
    assert!(b.read <= READ_BOUND);
    let mut c = Virtual {
        len: GIB,
        pos: 0,
        byte: zipish,
        read: 0,
    };
    let r = filetype::classify(&mut c, None);
    assert_eq!(
        (r.content_kind, r.parse_error),
        (FileKind::Zip, Some(ParseError::ZipDirectoryMissing))
    );
    assert!(c.read <= READ_BOUND);
    assert_eq!(r.file_size, GIB);
}

/// Classifies `data` through a counting reader, checks the read bound and
/// returns the result.
fn classify_counted(data: &[u8], name: Option<&str>) -> Classification {
    let mut reader = Virtual {
        len: data.len() as u64,
        pos: 0,
        byte: |o: u64| data[o as usize],
        read: 0,
    };
    let c = filetype::classify(&mut reader, name.map(OsStr::new));
    assert!(reader.read <= READ_BOUND, "read {}", reader.read);
    c
}

#[test]
fn zip_directory_byte_cap() {
    // 70 entries of 64 KiB each (a long comment): over the 4 MiB byte cap
    // long before the 65,536-entry cap. Without the byte cap, the read
    // would go over the targeted read budget instead.
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(64, 0);
    let dir_at = data.len();
    let count = 70_u16;
    for _ in 0..count {
        data.extend(dir_entry(b"a", 0, 65_489));
    }
    let size = data.len() - dir_at;
    assert!(size > filetype::MAX_ZIP_DIRECTORY);
    data.extend(end_record(count, size as u32, dir_at as u32, b""));
    let c = classify_counted(&data, None);
    assert_eq!(c.content_kind, FileKind::Zip);
    assert_fails_closed(&c, ParseError::ZipDirectoryTruncated);
}

/// A consistent ZIP64 archive of `count` directory entries named `a`.
fn zip64_of(count: u64) -> Vec<u8> {
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(64, 0);
    let dir_at = data.len() as u64;
    let entry = dir_entry(b"a", 0, 0);
    for _ in 0..count {
        data.extend_from_slice(&entry);
    }
    let size = data.len() as u64 - dir_at;
    let record_at = data.len() as u64;
    data.extend_from_slice(b"PK\x06\x06");
    data.extend_from_slice(&44_u64.to_le_bytes());
    data.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&count.to_le_bytes());
    data.extend_from_slice(&count.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data.extend_from_slice(&dir_at.to_le_bytes());
    data.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    data.extend_from_slice(&record_at.to_le_bytes());
    data.extend_from_slice(&1_u32.to_le_bytes());
    data.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    data.extend_from_slice(&[0xff; 12]);
    data.extend_from_slice(&[0, 0]);
    data
}

#[test]
fn zip_directory_entry_cap() {
    // One entry more than the cap, in a consistent ZIP64 archive whose
    // directory (about 3 MiB) is under the byte cap: without the entry
    // cap, it would read cleanly.
    let over = zip64_of(filetype::MAX_ZIP_ENTRIES as u64 + 1);
    assert!(over.len() < filetype::MAX_ZIP_DIRECTORY);
    let c = classify_counted(&over, None);
    assert_eq!(c.content_kind, FileKind::Zip);
    assert_fails_closed(&c, ParseError::ZipDirectoryTruncated);
    // At the cap it is read cleanly, so the cap, not the layout, is what
    // is reported above.
    let at = classify_counted(&zip64_of(filetype::MAX_ZIP_ENTRIES as u64), None);
    assert_eq!((at.content_kind, at.parse_error), (FileKind::Zip, None));
}

#[test]
fn reader_errors_are_reported() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    impl Seek for Failing {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Ok(100)
        }
    }
    let c = filetype::classify(&mut Failing, Some(OsStr::new("a.exe")));
    assert_eq!(c.content_kind, FileKind::Unknown);
    assert_eq!(
        c.parse_error,
        Some(ParseError::Io(io::ErrorKind::PermissionDenied))
    );
    assert!(!c.mismatch);
}

#[test]
fn classify_reads_a_real_file() {
    let dir = std::env::temp_dir().join(format!("palisade-filetype-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("report.pdf");
    std::fs::write(&path, PeBuilder::default().build()).unwrap();
    let mut file = std::fs::File::open(&path).unwrap();
    let c = filetype::classify(&mut file, Some(path.as_os_str()));
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(c.content_kind, FileKind::Pe);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
}

// ---------------------------------------------------------------------------
// Review regressions
// ---------------------------------------------------------------------------

#[test]
fn null_directory_rvas_are_absent() {
    // A CLR or load configuration directory at RVA 0 with a size would
    // map to the DOS header. It is absent, as the loader treats it.
    let mut image = PeBuilder::default().build();
    let b = PeBuilder::default();
    put32(&mut image, b.data_directory_offset(14) + 4, 0x48);
    put32(&mut image, b.data_directory_offset(10) + 4, 0x140);
    let d = pe_details(&image, None);
    assert_eq!(d.dot_net, None);
    assert_eq!(d.hybrid, None);

    // A null name pointer in an import descriptor and a null name table
    // in the export directory are not read from the DOS header. A
    // descriptor with no name ends the table, as it does for the loader.
    let null_name = |_rva: u32| {
        let mut out = vec![0_u8; 0x400];
        put32(&mut out, 16, 0x1234);
        out
    };
    let d = pe_details(
        &pe_with(PeBuilder::default(), null_name, &[(1, 0, 40)]),
        None,
    );
    assert!(!d.incomplete && !d.imports_kernel);
    let null_names = |_rva: u32| {
        let mut out = vec![0_u8; 0x400];
        put32(&mut out, 24, 3);
        out
    };
    let d = pe_details(
        &pe_with(PeBuilder::default(), null_names, &[(0, 0, 40)]),
        None,
    );
    assert!(d.incomplete);
}

#[test]
fn truncated_directories_are_incomplete() {
    // An export directory cut by the end of its section's raw data: it
    // starts 20 bytes before the end of the 0x200-byte raw data.
    let full = |_rva: u32| vec![0_u8; 0x200];
    let image = pe_with(PeBuilder::default(), full, &[(0, 0x1ec, 40)]);
    assert!(pe_details(&image, None).incomplete);

    // A long user-mode module name ending in `.sys` past 64 bytes is not a
    // kernel import.
    let long = format!("{}.sys.dll", "x".repeat(70));
    let modules = [long.as_str()];
    let d = pe_details(
        &pe_with(PeBuilder::default(), imports(&modules), &[(1, 0, 40)]),
        None,
    );
    assert_eq!(d.sub_kind, PeSubKind::Exe);
    assert!(!d.imports_kernel);

    // An empty resource root at the very end of its section's raw data
    // is complete.
    let image = pe_with(PeBuilder::default(), full, &[(2, 0x1f0, 16)]);
    let d = pe_details(&image, None);
    assert!(!d.incomplete && !d.has_type_library);
}

#[test]
fn pe32_hybrid_pointer() {
    let config = |_rva: u32| {
        let mut out = vec![0_u8; 0x100];
        put32(&mut out, 0, 0xc0);
        put32(&mut out, 0x7c, 0x0040_2000);
        out
    };
    let chpe = pe_with(PeBuilder::pe32(), config, &[(10, 0, 0xc0)]);
    assert_eq!(pe_details(&chpe, None).hybrid, Some(HybridKind::Chpe));
}

/// Rewrites `zip`'s end records as ZIP64 with an extensible data sector of
/// `extra` bytes, optionally behind `prefix` bytes so the locator's offset
/// is off.
fn zip64(names: &[&str], extra: usize, prefix: usize) -> Vec<u8> {
    let base = zip(&vec![b' '; prefix], names);
    let end = base.len() - 22;
    let size = u64::from(u32::from_le_bytes(
        base[end + 12..end + 16].try_into().unwrap(),
    ));
    let offset = u64::from(u32::from_le_bytes(
        base[end + 16..end + 20].try_into().unwrap(),
    ));
    let count = names.len() as u64;
    let mut z = base[..end].to_vec();
    // The locator's offset is as written without the prefix.
    let record_at = (z.len() - prefix) as u64;
    z.extend_from_slice(b"PK\x06\x06");
    z.extend_from_slice(&(44 + extra as u64).to_le_bytes());
    z.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&count.to_le_bytes());
    z.extend_from_slice(&count.to_le_bytes());
    z.extend_from_slice(&size.to_le_bytes());
    z.extend_from_slice(&(offset - prefix as u64).to_le_bytes());
    z.extend(std::iter::repeat_n(0xab_u8, extra));
    z.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    z.extend_from_slice(&record_at.to_le_bytes());
    z.extend_from_slice(&1_u32.to_le_bytes());
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\0");
    z
}

#[test]
fn zip64_extensible_data_and_prefixes() {
    let c = classify(&zip64(&["AppxManifest.xml"], 0, 0), None);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Msix, None));
    // Extensible data, or a prefix that shifts every recorded offset: some
    // readers find the ZIP64 record and directory, others do not.
    for (extra, prefix) in [(37, 0), (300, 0), (0, 512), (64, 512)] {
        let mut data = zip64(&["AppxManifest.xml"], extra, prefix);
        // Make the prefix start with a local file header signature so the
        // file is sniffed as a ZIP, as a self-extracting archive's would
        // through its stub.
        data[..4].copy_from_slice(b"PK\x03\x04");
        assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
    }
    // A prefix whose offsets were adjusted for it is a normal archive.
    let mut stub = vec![0_u8; 512];
    stub[..4].copy_from_slice(b"PK\x03\x04");
    let c = classify(&zip(&stub, &["AppxManifest.xml"]), None);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Msix, None));
    // A sentinel size with no ZIP64 record.
    let mut base = zip(b"", &["AppxManifest.xml"]);
    let end = base.len() - 22;
    put32(&mut base, end + 12, 0xffff_ffff);
    assert_fails_closed(&classify(&base, None), ParseError::ZipDirectoryMalformed);
    // Sentinels in both fields, and no ZIP64 record.
    put32(&mut base, end + 16, 0xffff_ffff);
    assert_fails_closed(&classify(&base, None), ParseError::ZipDirectoryMalformed);
    // Backslash separators.
    assert_eq!(
        kind(&zip(b"", &["AppxMetadata\\AppxBundleManifest.xml"]), None),
        FileKind::MsixBundle
    );
}

#[test]
fn binary_padding_does_not_hide_scripts() {
    let pad = |text: &str, tail: &[u8]| {
        let mut out = text.as_bytes().to_vec();
        out.extend_from_slice(tail);
        out
    };
    let cases: [(&str, FileKind); 4] = [
        ("#!/bin/sh\necho hi\n", FileKind::Script(ScriptKind::Shell)),
        (HTA, FileKind::Hta),
        ("Windows Registry Editor Version 5.00\r\n", FileKind::Reg),
        (
            "<job><script>WScript.Echo 1</script></job>",
            FileKind::Script(ScriptKind::Wsf),
        ),
    ];
    for (text, want) in cases {
        for tail in [&b"\0"[..], b"\x01\x02\x03\x04\x05", &[0xff; 64]] {
            let c = classify(&pad(text, tail), None);
            assert_eq!(c.content_kind, want, "{text:?} + {tail:?}");
            assert!(c.is_executable_content());
        }
    }
    // A self-extracting shell script with a binary payload.
    let mut sfx = b"#!/bin/sh\ntail -c +100 \"$0\" | tar x\nexit 0\n".to_vec();
    sfx.extend((0..4096_u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
    assert_eq!(kind(&sfx, None), FileKind::Script(ScriptKind::Shell));
    // A script followed by zeros is found by its keywords.
    let c = classify(&pad(BATCH, b"\0\0\0"), None);
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Batch));
    assert!(c.heuristic && !c.extension_assisted);
    let c = classify(&pad(BATCH, b"\0"), Some("run.cmd.txt"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Batch));
    assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
    // A script name with unrecognised binary content fails closed as that
    // script.
    let c = classify(b"echo\0\x01\x02", Some("run.cmd"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Batch));
    assert!(c.extension_assisted);
    assert_eq!(
        kind(b"echo\0\x01\x02", Some("run.cmd.txt")),
        FileKind::Unknown
    );
    // A signature block in binary content.
    let c = classify(&pad("\0\0# SIG # Begin signature block\r\n", b""), None);
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::PowerShell));
}

#[test]
fn understated_zip_entry_counts_do_not_hide_entries() {
    for names in [
        &["META-INF/MANIFEST.MF"][..],
        &["readme.txt", "META-INF/MANIFEST.MF"],
    ] {
        for declared in [0_u16, 1, 3] {
            if usize::from(declared) == names.len() {
                continue;
            }
            let mut data = zip(b"", names);
            let end = data.len() - 22;
            put16(&mut data, end + 8, declared);
            put16(&mut data, end + 10, declared);
            let c = classify(&data, None);
            // Every entry is still noted, and readers that trust the count
            // disagree with those that trust the size.
            assert_eq!(c.content_kind, FileKind::Jar, "{names:?} {declared}");
            assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
        }
    }
    // A trailing digital signature record inside the directory: readers
    // differ on whether to skip it.
    let data = zip(b"", &["META-INF/MANIFEST.MF"]);
    let end = data.len() - 22;
    let size = u32::from_le_bytes(data[end + 12..end + 16].try_into().unwrap());
    let mut signed = data[..end].to_vec();
    signed.extend_from_slice(b"PK\x05\x05\x02\0ab");
    signed.extend_from_slice(&data[end..]);
    let end = signed.len() - 22;
    put32(&mut signed, end + 12, size + 8);
    let c = classify(&signed, None);
    assert_eq!(c.content_kind, FileKind::Jar);
    assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn markers_behind_binary_bytes() {
    let cases: [(&[u8], FileKind); 6] = [
        (b"<!-- \0 --><html><HTA:APPLICATION/></html>", FileKind::Hta),
        (
            b"<!-- \xa9 --><?php system($x); ?>\0",
            FileKind::Script(ScriptKind::Php),
        ),
        (
            b"\0<scriptlet><registration/></scriptlet>",
            FileKind::Script(ScriptKind::Wsc),
        ),
        (
            b"\x01\x02<job><script>x</script></job>",
            FileKind::Script(ScriptKind::Wsf),
        ),
        (
            b"\0\0#@~^AAAA==abc^#~@",
            FileKind::Script(ScriptKind::VbScript),
        ),
        (
            b"\0\0# SIG # Begin signature block\r\n",
            FileKind::Script(ScriptKind::PowerShell),
        ),
    ];
    for (data, want) in cases {
        let c = classify(data, None);
        assert_eq!(c.content_kind, want, "{data:?}");
        assert!(c.is_executable_content());
    }
    let c = classify(b"\0\0#@~^AAAA==abc^#~@", None);
    assert!(c.flags.encoded_script);
    let c = classify(b"\0\0# SIG # Begin signature block\r\n", None);
    assert!(c.flags.script_signature_block);
    // HTML with binary bytes under an `.hta` name, and binary content
    // under an `.hta` name.
    let c = classify(
        b"<html><script>x()</script></html>\0",
        Some("invoice.pdf.hta"),
    );
    assert_eq!(c.content_kind, FileKind::Hta);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Critical);
    let noise: Vec<u8> = (0..512_u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    assert_eq!(kind(&noise, Some("a.hta")), FileKind::Hta);
    // A shebang must still start the file.
    assert_ne!(
        kind(b"\0#!/bin/sh\n", None),
        FileKind::Script(ScriptKind::Shell)
    );
}

#[test]
fn scripts_with_a_planted_descriptor_stay_scripts() {
    let plant = |body: &[u8]| {
        let mut out = body.repeat(0x9000 / body.len() + 1);
        out.truncate(0x9800);
        out[0x8000..0x8007].copy_from_slice(b"\x01CD001\x01");
        out
    };
    let batch = plant(b"echo hi\r\nexit /b 0\r\n");
    let c = classify(&batch, Some("evil.bat"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Batch));
    assert!(!c.mismatch);
    assert_eq!(
        classify(&batch, Some("invoice.pdf.ps1")).mismatch_severity,
        MismatchSeverity::Critical
    );
    assert_eq!(
        kind(&plant(POWERSHELL.as_bytes()), None),
        FileKind::Script(ScriptKind::PowerShell)
    );
    assert_eq!(
        kind(
            &plant(b"<html><script>x()</script></html>\n"),
            Some("a.hta")
        ),
        FileKind::Hta
    );
    // A real disc image with a signed script past the system area stays
    // a disc image.
    let mut disc = iso(b"CD001");
    disc.extend_from_slice(b"# SIG # Begin signature block\r\n");
    assert_eq!(kind(&disc, None), FileKind::Iso);
}

/// A minimal ZIP64 tail for `zip(b"", names)`: ZIP64 end record and
/// locator, then a 32-bit end record with the given fields.
fn zip64_hidden(
    names: &[&str],
    count32: u16,
    size32: u32,
    offset32: u32,
    locator: bool,
) -> Vec<u8> {
    let base = zip(b"", names);
    let end = base.len() - 22;
    let size = u64::from(u32::from_le_bytes(
        base[end + 12..end + 16].try_into().unwrap(),
    ));
    let offset = u64::from(u32::from_le_bytes(
        base[end + 16..end + 20].try_into().unwrap(),
    ));
    let count = names.len() as u64;
    let mut z = base[..end].to_vec();
    let record_at = z.len() as u64;
    z.extend_from_slice(b"PK\x06\x06");
    z.extend_from_slice(&44_u64.to_le_bytes());
    z.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&count.to_le_bytes());
    z.extend_from_slice(&count.to_le_bytes());
    z.extend_from_slice(&size.to_le_bytes());
    z.extend_from_slice(&offset.to_le_bytes());
    if locator {
        z.extend_from_slice(b"PK\x06\x07\0\0\0\0");
        z.extend_from_slice(&record_at.to_le_bytes());
        z.extend_from_slice(&1_u32.to_le_bytes());
    } else {
        z.extend_from_slice(&[0; 20]);
    }
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    z.extend_from_slice(&count32.to_le_bytes());
    z.extend_from_slice(&count32.to_le_bytes());
    z.extend_from_slice(&size32.to_le_bytes());
    z.extend_from_slice(&offset32.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z
}

#[test]
fn zip64_records_are_used_without_sentinels() {
    let names = ["__main__.py"];
    let base = zip(b"", &names);
    let end = base.len() - 22;
    let size = u32::from_le_bytes(base[end + 12..end + 16].try_into().unwrap());
    let offset = u32::from_le_bytes(base[end + 16..end + 20].try_into().unwrap());
    // Real values in both records.
    let both = zip64_hidden(&names, 1, size, offset, true);
    let c = classify(&both, Some("app.pyz"));
    assert_eq!(
        (c.content_kind, c.parse_error.clone()),
        (FileKind::Script(ScriptKind::Python), None)
    );
    // A zeroed 32-bit record in front of a real ZIP64 directory: readers
    // that use the 32-bit fields see an empty archive.
    let zeroed = zip64_hidden(&names, 0, 0, 0, true);
    let c = classify(&zeroed, Some("invoice.pdf.pyz"));
    assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Critical);
    // A ZIP64 end record with no locator, ending where the locator would.
    let jar = zip64_hidden(&["META-INF/MANIFEST.MF"], 0, 0, 0, false);
    assert_fails_closed(&classify(&jar, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn entries_after_a_digital_signature_record_are_seen() {
    let data = zip(b"", &["readme.txt"]);
    let end = data.len() - 22;
    let size = u32::from_le_bytes(data[end + 12..end + 16].try_into().unwrap());
    // A signature record, then another entry after it.
    let mut hidden = data[..end].to_vec();
    hidden.extend_from_slice(b"PK\x05\x05\0\0");
    let extra = zip(b"", &["META-INF/MANIFEST.MF"]);
    let e2 = extra.len() - 22;
    let dir2 = u32::from_le_bytes(extra[e2 + 16..e2 + 20].try_into().unwrap()) as usize;
    hidden.extend_from_slice(&extra[dir2..e2]);
    let added = (6 + e2 - dir2) as u32;
    hidden.extend_from_slice(&data[end..]);
    let e = hidden.len() - 22;
    put32(&mut hidden, e + 12, size + added);
    // Readers that walk past the record see the entry after it; readers
    // that stop there do not.
    assert_fails_closed(&classify(&hidden, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn zero_padding_cannot_fake_utf16() {
    // Eight-bit markers after a run of `A\0` pairs.
    let fake = |marker: &[u8]| {
        let mut out = b"<!--".to_vec();
        out.extend(b" \0".repeat(250));
        out.extend_from_slice(b" -->");
        out.extend_from_slice(marker);
        out
    };
    assert_eq!(
        kind(&fake(b"<html><HTA:APPLICATION/></html>\n"), None),
        FileKind::Hta
    );
    assert_eq!(
        kind(
            &fake(b"<html><script>x()</script></html>\n"),
            Some("evil.hta")
        ),
        FileKind::Hta
    );
    assert_eq!(
        kind(&fake(b"<?php system($x); ?>\n"), None),
        FileKind::Script(ScriptKind::Php)
    );
    assert_eq!(
        kind(&fake(b"#@~^AAAA==abc^#~@\n"), Some("a.vbe")),
        FileKind::Script(ScriptKind::VbScript)
    );
    let mut sh = b"#!/bin/sh\n#".to_vec();
    sh.extend(b"A\0".repeat(250));
    sh.extend_from_slice(b"\necho hi\n");
    assert_eq!(kind(&sh, None), FileKind::Script(ScriptKind::Shell));
    let mut long = fake(b"\n");
    long.extend(POWERSHELL.repeat(200).bytes());
    assert_eq!(kind(&long, None), FileKind::Script(ScriptKind::PowerShell));
    // Genuine UTF-16 without a mark is still read as UTF-16.
    let c = classify(&utf16le(POWERSHELL, false), None);
    assert_eq!(c.text_encoding, Some(TextEncoding::Utf16LeNoBom));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::PowerShell));
}

#[test]
fn zero_padded_scripts_with_a_planted_descriptor() {
    let plant = |body: &[u8], fill: u8| {
        let mut out = body.to_vec();
        out.resize(0x8000, fill);
        out.extend_from_slice(b"\x01CD001\x01\0");
        out.resize(0x9800, 0);
        out
    };
    let script = b"@echo off\r\necho pwned\r\nexit /b 0\r\n";
    for fill in [0, b' '] {
        let polyglot = plant(script, fill);
        for name in [Some("evil.bat"), Some("invoice.pdf.bat"), None] {
            let c = classify(&polyglot, name);
            assert_eq!(
                c.content_kind,
                FileKind::Script(ScriptKind::Batch),
                "{fill} {name:?}"
            );
        }
        assert_eq!(
            classify(&polyglot, Some("invoice.pdf.bat")).mismatch_severity,
            MismatchSeverity::Critical
        );
    }
    // UDF descriptors with zeros, after a text system area.
    let mut udf = POWERSHELL
        .repeat(0x8000 / POWERSHELL.len() + 1)
        .into_bytes();
    udf.truncate(0x8000);
    udf.extend_from_slice(b"\0BEA01\x01");
    udf.resize(0x9800, 0);
    assert_eq!(kind(&udf, None), FileKind::Script(ScriptKind::PowerShell));
    // Plain text with a planted descriptor stays text.
    let mut text = b"Just some notes.\n".repeat(0x8000 / 17 + 1);
    text.truncate(0x8000);
    text.extend_from_slice(b"\x01CD001\x01\0");
    text.resize(0x9800, 0);
    assert_eq!(kind(&text, None), FileKind::Text);
    // A real image's system area is zeros or a few bytes of boot code.
    let mut boot = iso(b"CD001");
    boot[..2].copy_from_slice(&[0xeb, 0x63]);
    assert_eq!(kind(&boot, Some("disc.iso")), FileKind::Iso);
}

/// `zip(b"", names)` with `comment` as the last directory entry's comment.
fn zip_with_last_comment(names: &[&str], comment: &[u8]) -> Vec<u8> {
    let base = zip(b"", names);
    let end = base.len() - 22;
    let dir = u32::from_le_bytes(base[end + 16..end + 20].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(base[end + 12..end + 16].try_into().unwrap());
    // The last entry header: walk the directory.
    let mut at = dir;
    let mut last = dir;
    while at < end {
        last = at;
        let n = u16::from_le_bytes(base[at + 28..at + 30].try_into().unwrap()) as usize;
        at += 46 + n;
    }
    let mut out = base[..end].to_vec();
    put16(&mut out, last + 32, comment.len() as u16);
    out.extend_from_slice(comment);
    out.extend_from_slice(&base[end..]);
    let e = out.len() - 22;
    put32(&mut out, e + 12, size + comment.len() as u32);
    out
}

#[test]
fn decoy_zip64_record_in_a_comment_does_not_hide_entries() {
    let mut record = b"PK\x06\x06".to_vec();
    record.extend_from_slice(&44_u64.to_le_bytes());
    record.extend_from_slice(&[0; 44]);
    // Without a locator.
    let mut plain = record.clone();
    plain.extend_from_slice(&[0; 20]);
    // With a locator pointing at the decoy record.
    let names = ["AppxManifest.xml"];
    let data = zip_with_last_comment(&names, &plain);
    let c = classify(&data, Some("invoice.pdf"));
    assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
    let base = zip_with_last_comment(&names, &[0; 76]);
    let record_at = (base.len() - 22 - 76) as u64;
    let mut with_locator = record.clone();
    with_locator.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    with_locator.extend_from_slice(&record_at.to_le_bytes());
    with_locator.extend_from_slice(&1_u32.to_le_bytes());
    let data = zip_with_last_comment(&names, &with_locator);
    assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
    for jar in [&["META-INF/MANIFEST.MF"][..], &["word/vbaProject.bin"]] {
        let data = zip_with_last_comment(jar, &with_locator);
        assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
    }
    // A locator-less ZIP64 record with an odd declared size.
    let mut odd = zip64_hidden(&["__main__.py"], 0, 0, 0, false);
    let at = odd.len() - 22 - 20 - 56 + 4;
    put32(&mut odd, at, 99);
    assert_fails_closed(
        &classify(&odd, Some("a.pyz")),
        ParseError::ZipDirectoryAmbiguous,
    );
    // An entry whose comment runs past the directory.
    let mut bad = zip(b"", &["a"]);
    let e = bad.len() - 22;
    let dir = u32::from_le_bytes(bad[e + 16..e + 20].try_into().unwrap()) as usize;
    put16(&mut bad, dir + 32, 500);
    assert_fails_closed(&classify(&bad, None), ParseError::ZipDirectoryMalformed);
}

#[test]
fn utf16_guess_does_not_hide_markers_behind_keywords() {
    // Eight-bit markers, padding that passes for UTF-16, and UTF-16
    // keywords for another language.
    let polyglot = |marker: &[u8]| {
        let mut out = marker.to_vec();
        out.extend_from_slice(b"<!--");
        out.extend("dim x : msgbox x".encode_utf16().flat_map(u16::to_le_bytes));
        out.extend(b"A\0".repeat(400));
        out.extend_from_slice(b"-->\n");
        out
    };
    let c = classify(&polyglot(b"#!/usr/bin/env python3\n"), Some("a.js"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Python));
    assert!(c.mismatch);
    assert_eq!(
        kind(&polyglot(b"<html><HTA:APPLICATION/>"), None),
        FileKind::Hta
    );
    assert_eq!(kind(&polyglot(b"REGEDIT4\r\n"), None), FileKind::Reg);
    assert_eq!(
        kind(&polyglot(b"<?php x(); ?>"), Some("a.com")),
        FileKind::Script(ScriptKind::Php)
    );
    // A signature block in the eight-bit view of the tail, behind 64 KiB of
    // padding.
    let mut long = b"Write-Host hi\n<#".to_vec();
    long.extend(b" \0".repeat(HEAD_LEN));
    long.extend_from_slice(b"#>\r\n# SIG # Begin signature block\r\n");
    let c = classify(&long, None);
    assert!(c.flags.script_signature_block, "{c:?}");
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::PowerShell));
}

#[test]
fn planted_descriptor_polyglots_with_noise() {
    let plant = |body: &[u8]| {
        let mut out = body.to_vec();
        out.resize(0x8000, 0);
        out.extend_from_slice(b"\x01CD001\x01\0");
        out.resize(0x9800, 0);
        out
    };
    // Control bytes in a first-line comment.
    let mut noisy = b"::".to_vec();
    noisy.extend([1_u8; 20]);
    noisy.extend_from_slice(b"\r\n@echo off\r\nsetlocal\r\nset /a x=1\r\nexit /b 0\r\n");
    // Under a script name it stays the script (the host runs it); with no
    // name, that many control bytes make it binary.
    assert!(matches!(
        kind(&plant(&noisy), Some("evil.bat")),
        FileKind::Script(_)
    ));
    assert!(matches!(
        kind(&plant(&noisy), Some("invoice.pdf.bat")),
        FileKind::Script(_)
    ));
    // A legacy code page byte in the first line.
    let cp = plant(b"::\xe9\r\npowershell -enc AAAA\r\nexit /b 0\r\n");
    let c = classify(&cp, Some("invoice.pdf.bat"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Batch));
    assert_eq!(c.mismatch_severity, MismatchSeverity::Critical);
    // A very short script under a script name.
    let short = plant(b"calc\r\n");
    for name in ["evil.bat", "invoice.pdf.bat"] {
        assert_eq!(
            kind(&short, Some(name)),
            FileKind::Script(ScriptKind::Batch),
            "{name}"
        );
    }
    // Padding that passes for UTF-16, with control pairs, in front of an
    // HTA marker.
    let mut hta = b"<!--".to_vec();
    hta.extend(b" \0".repeat(15_000));
    hta.extend(b"\x01\0".repeat(200));
    hta.extend_from_slice(b" --><html><HTA:APPLICATION/></html>");
    let hta = plant(&hta);
    assert_eq!(kind(&hta, Some("invoice.pdf")), FileKind::Hta);
    // A real image with boot code is still a disc image under its name.
    let mut boot = iso(b"CD001");
    boot[..4].copy_from_slice(&[0xeb, 0x63, 0x90, 0x10]);
    assert_eq!(kind(&boot, Some("disc.iso")), FileKind::Iso);
}

#[test]
fn zip_directory_at_its_recorded_offset() {
    // The real directory at the recorded offset, a separator byte, then a
    // decoy directory of the same size just before the end record.
    let real = zip(b"", &["AppxManifest.xml"]);
    let end = real.len() - 22;
    let dir_at = u32::from_le_bytes(real[end + 16..end + 20].try_into().unwrap()) as usize;
    let real_dir = real[dir_at..end].to_vec();
    let decoy_name = "r".repeat("AppxManifest.xml".len());
    let decoy = zip(b"", &[decoy_name.as_str()]);
    let de = decoy.len() - 22;
    let decoy_at = u32::from_le_bytes(decoy[de + 16..de + 20].try_into().unwrap()) as usize;
    assert_eq!(de - decoy_at, real_dir.len());
    let mut data = real[..end].to_vec();
    data.push(0);
    data.extend_from_slice(&decoy[decoy_at..de]);
    data.extend_from_slice(&real[end..]);
    let c = classify(&data, Some("invoice.pdf"));
    assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
    // The same through a ZIP64 record.
    let mut z = real[..end].to_vec();
    z.push(0);
    z.extend_from_slice(&decoy[decoy_at..de]);
    let record_at = z.len() as u64;
    z.extend_from_slice(b"PK\x06\x06");
    z.extend_from_slice(&44_u64.to_le_bytes());
    z.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&1_u64.to_le_bytes());
    z.extend_from_slice(&1_u64.to_le_bytes());
    z.extend_from_slice(&(real_dir.len() as u64).to_le_bytes());
    z.extend_from_slice(&(dir_at as u64).to_le_bytes());
    z.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    z.extend_from_slice(&record_at.to_le_bytes());
    z.extend_from_slice(&1_u32.to_le_bytes());
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\0");
    assert_fails_closed(&classify(&z, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn zip64_locator_and_signature_only_record() {
    // A locator whose record does not fit, and a record at the fixed place
    // with an odd size field, behind a zeroed 32-bit record.
    let mut z = zip64_hidden(&["__main__.py"], 0, 0, 0, true);
    let at = z.len() - 22 - 20 - 56 + 4;
    put32(&mut z, at, 0);
    let c = classify(&z, Some("invoice.pdf.pyz"));
    assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Critical);
}

#[test]
fn large_decoy_does_not_starve_the_real_directory() {
    // A 32-bit archive with a real directory of about 200 KiB, and a decoy
    // ZIP64 record in the last comment claiming a 4 MiB directory.
    let names: Vec<String> = (0..4000)
        .map(|i| format!("assets/file-{i:05}.bin"))
        .collect();
    let mut refs: Vec<&str> = names.iter().map(String::as_str).collect();
    refs.push("AppxManifest.xml");
    let mut record = b"PK\x06\x06".to_vec();
    record.extend_from_slice(&44_u64.to_le_bytes());
    record.extend_from_slice(&[0; 28]);
    record.extend_from_slice(&(4_u64 << 20).to_le_bytes());
    record.extend_from_slice(&[0; 8]);
    record.extend_from_slice(&[0; 20]);
    let mut data = vec![0_u8; 5 << 20];
    data[..4].copy_from_slice(b"PK\x03\x04");
    let archive = zip_with_last_comment(&refs, &record);
    // Shift the archive behind 5 MiB of padding (offsets are not used).
    data.extend_from_slice(&archive);
    // The archive's own offsets do not count the padding, and a ZIP64
    // record sits in a comment: ambiguous, so it fails closed without
    // reading the claimed 4 MiB.
    assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
    let record_at = data.windows(4).rposition(|w| w == b"PK\x06\x06").unwrap();
    let decoy_start = record_at - (4 << 20);
    data[decoy_start..decoy_start + 4].copy_from_slice(b"PK\x01\x02");
    assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
    // A real ZIP64 archive with matching records reads one directory.
    let names = ["META-INF/MANIFEST.MF"];
    let base = zip(b"", &names);
    let size = u32::from_le_bytes(base[base.len() - 10..base.len() - 6].try_into().unwrap());
    let both = zip64_hidden(&names, 0xffff, size, 0xffff_ffff, true);
    let c = classify(&both, None);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Jar, None));
    // A 32-bit field that is neither the ZIP64 value nor the sentinel:
    // readers that use the 32-bit field read elsewhere.
    for (s, o) in [(size + 1, 0xffff_ffff), (size, 0)] {
        let off = zip64_hidden(&names, 0xffff, s, o, true);
        assert_fails_closed(&classify(&off, None), ParseError::ZipDirectoryAmbiguous);
    }
}

#[test]
fn weak_marker_in_one_view_does_not_shadow_a_strong_one() {
    let mut data = b"#!/usr/bin/env python3\n# ".to_vec();
    data.extend_from_slice(b"#\0@\0~\0^\0");
    data.extend(b"A\0".repeat(300));
    data.extend_from_slice(b"\nprint(1)\n");
    let c = classify(&data, Some("a.js"));
    assert_eq!(
        c.content_kind,
        FileKind::Script(ScriptKind::Python),
        "{c:?}"
    );
    assert!(c.mismatch);
    // A keyword script, then control pairs and padding that pass for
    // UTF-16.
    let mut padded = BATCH.as_bytes().to_vec();
    padded.extend(b"\x01\0".repeat(600));
    padded.extend(b"A\0".repeat(4800));
    assert_eq!(kind(&padded, None), FileKind::Script(ScriptKind::Batch));
}

#[test]
fn payload_after_a_planted_descriptor() {
    let mut hta = b"<!-- ".to_vec();
    hta.resize(0x8000, b' ');
    hta.extend_from_slice(b"\x01CD001\x01");
    hta.extend_from_slice(b" --><html><HTA:APPLICATION/><script>x()</script></html>\n");
    let c = classify(&hta, Some("invoice.pdf.hta"));
    assert_eq!(c.content_kind, FileKind::Hta);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Critical);
    assert_eq!(kind(&hta, Some("invoice.pdf")), FileKind::Hta);
    // Bytecode with a descriptor in a constant.
    let mut pyc = vec![0_u8; 0x9000];
    put16(&mut pyc, 0, 3495);
    pyc[2..4].copy_from_slice(b"\r\n");
    pyc[0x8000..0x8007].copy_from_slice(b"\x01CD001\x01");
    let c = classify(&pyc, Some("invoice.pdf"));
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Python));
    // A text system area of a long image: the image's contents are not
    // searched for a signature block.
    let mut image = b"Some readme text\n".repeat(0x8000 / 17 + 1);
    image.truncate(0x8000);
    image.extend_from_slice(b"\x01CD001\x01\0");
    image.resize(HEAD_LEN * 3, 0);
    let n = image.len();
    image[n - 40..n - 10].copy_from_slice(b"# SIG # Begin signature block\n");
    let c = classify(&image, None);
    assert!(!c.is_executable_content(), "{c:?}");
}

#[test]
fn understated_directory_sizes_do_not_hide_entries() {
    let names = ["readme.txt", "AppxManifest.xml"];
    let base = zip(b"", &names);
    let end = base.len() - 22;
    let first = 46 + "readme.txt".len();
    for size in [0_u32, first as u32] {
        let mut data = base.clone();
        put32(&mut data, end + 12, size);
        let c = classify(&data, Some("invoice.pdf"));
        assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
        assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
    }
    // The same through a ZIP64 record.
    let mut z = zip64_hidden(&names, 0xffff, 0xffff_ffff, 0xffff_ffff, true);
    let record = z.windows(4).rposition(|w| w == b"PK\x06\x06").unwrap();
    z[record + 40..record + 48].copy_from_slice(&(first as u64).to_le_bytes());
    assert_fails_closed(&classify(&z, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn zip64_record_away_from_the_locator() {
    // The real directory and its ZIP64 end record, then a decoy directory,
    // then a locator pointing at the record, then a 32-bit record
    // describing the decoy.
    let real = zip(b"", &["AppxManifest.xml"]);
    let end = real.len() - 22;
    let dir_at = u32::from_le_bytes(real[end + 16..end + 20].try_into().unwrap()) as u64;
    let dir_len = (end as u64) - dir_at;
    let mut z = real[..end].to_vec();
    let record_at = z.len() as u64;
    z.extend_from_slice(b"PK\x06\x06");
    z.extend_from_slice(&44_u64.to_le_bytes());
    z.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&1_u64.to_le_bytes());
    z.extend_from_slice(&1_u64.to_le_bytes());
    z.extend_from_slice(&dir_len.to_le_bytes());
    z.extend_from_slice(&dir_at.to_le_bytes());
    let decoy = zip(b"", &["readme.txt"]);
    let de = decoy.len() - 22;
    let decoy_dir = u32::from_le_bytes(decoy[de + 16..de + 20].try_into().unwrap()) as usize;
    let decoy_at = z.len() as u32;
    z.extend_from_slice(&decoy[decoy_dir..de]);
    let decoy_len = (de - decoy_dir) as u32;
    z.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    z.extend_from_slice(&record_at.to_le_bytes());
    z.extend_from_slice(&1_u32.to_le_bytes());
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff");
    z.extend_from_slice(&decoy_len.to_le_bytes());
    z.extend_from_slice(&decoy_at.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    assert_fails_closed(&classify(&z, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn overlapping_decoys_cannot_starve_a_small_directory() {
    // A small real directory before the end record, and a decoy ZIP64
    // record claiming a 4 MiB directory that overlaps it, with directory
    // signatures at both of the decoy's starts.
    let mut data = vec![0_u8; 4_600_000];
    data[..4].copy_from_slice(b"PK\x03\x04");
    let mut record = b"PK\x06\x06".to_vec();
    record.extend_from_slice(&44_u64.to_le_bytes());
    record.extend_from_slice(&[0; 28]);
    record.extend_from_slice(&(4_u64 << 20).to_le_bytes());
    let archive = zip_with_last_comment(&["AppxManifest.xml"], &{
        let mut r = record.clone();
        r.extend_from_slice(&[0; 8]);
        r.extend_from_slice(&[0; 20]);
        r
    });
    data.extend_from_slice(&archive);
    let record_at = data.windows(4).rposition(|w| w == b"PK\x06\x06").unwrap();
    let decoy_end_start = record_at - (4 << 20);
    data[decoy_end_start..decoy_end_start + 4].copy_from_slice(b"PK\x01\x02");
    let offset = (record_at - 4_500_000) as u64;
    data[offset as usize..offset as usize + 4].copy_from_slice(b"PK\x01\x02");
    data[record_at + 48..record_at + 56].copy_from_slice(&offset.to_le_bytes());
    assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn code_page_bytes_in_the_printable_start() {
    let mut data = b":: \x93hi\x94\r\n".to_vec();
    data.extend_from_slice(BATCH.as_bytes());
    data.extend(b"\x01\0".repeat(600));
    data.extend(b"A\0".repeat(4800));
    assert_eq!(kind(&data, None), FileKind::Script(ScriptKind::Batch));
    let mut planted = data.clone();
    planted.resize(0x8000, 0);
    planted.extend_from_slice(b"\x01CD001\x01\0");
    planted.resize(0x9800, 0);
    assert_eq!(
        kind(&planted, Some("invoice.pdf")),
        FileKind::Script(ScriptKind::Batch)
    );
}

#[test]
fn planted_descriptor_results_get_name_hints() {
    // Plain text system area, binary bytes after the descriptor, and an
    // HTML application name: it fails closed as an HTML application.
    let mut data = b"Some notes\n".repeat(0x8000 / 11 + 1);
    data.truncate(0x8000);
    data.extend_from_slice(b"\x01CD001\x01\0");
    data.extend_from_slice(b"<script>x()</script>");
    data.resize(0x9800, 0);
    let c = classify(&data, Some("invoice.pdf.hta"));
    assert_eq!(c.content_kind, FileKind::Hta, "{c:?}");
    assert_eq!(c.mismatch_severity, MismatchSeverity::Critical);
    // A system area of zeros with a few bytes and boot code: the image
    // stays an image, not Unknown.
    let mut image = b"I\0S\0O\0 \0b\0o\0o\0t\0".to_vec();
    image.extend((0..480_u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
    image.resize(0x8000, 0);
    image.extend_from_slice(b"\x01CD001\x01\0");
    image.resize(0x9800, 0);
    assert_eq!(kind(&image, None), FileKind::Iso);
}

/// One central directory entry for `name`, with the given extra and comment
/// lengths (the bytes themselves are zeros).
fn dir_entry(name: &[u8], extra: u16, comment: u16) -> Vec<u8> {
    let mut e = b"PK\x01\x02".to_vec();
    e.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    e.extend_from_slice(&[0; 12]);
    e.extend_from_slice(&(name.len() as u16).to_le_bytes());
    e.extend_from_slice(&extra.to_le_bytes());
    e.extend_from_slice(&comment.to_le_bytes());
    e.extend_from_slice(&[0; 12]);
    e.extend_from_slice(name);
    e.extend(std::iter::repeat_n(
        0_u8,
        usize::from(extra) + usize::from(comment),
    ));
    e
}

/// A 32-bit end record.
fn end_record(count: u16, size: u32, offset: u32, comment: &[u8]) -> Vec<u8> {
    let mut e = b"PK\x05\x06\0\0\0\0".to_vec();
    e.extend_from_slice(&count.to_le_bytes());
    e.extend_from_slice(&count.to_le_bytes());
    e.extend_from_slice(&size.to_le_bytes());
    e.extend_from_slice(&offset.to_le_bytes());
    e.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    e.extend_from_slice(comment);
    e
}

#[test]
fn huge_decoy_entries_cannot_starve_a_real_directory() {
    // A real directory of about 200 KiB (4,001 entries, the manifest
    // last), and a ZIP64 end record pointing at a chain of 64 decoy
    // entries of 64 KiB each, placed before the real directory. With one
    // entry per turn, the decoy chain read a new chunk every turn and used
    // up the budget before the real walk left its first chunk.
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(64, 0);
    let decoy_at = data.len() as u64;
    for _ in 0..64 {
        data.extend(dir_entry(b"d", 0, 65_489));
    }
    // A non-entry byte ends the decoy chain.
    data.push(0);
    let real_at = data.len() as u32;
    for i in 0..4000 {
        data.extend(dir_entry(
            format!("assets/file-{i:05}.bin").as_bytes(),
            0,
            0,
        ));
    }
    data.extend(dir_entry(b"AppxManifest.xml", 0, 0));
    let real_len = data.len() as u32 - real_at;
    let record_at = data.len() as u64;
    data.extend_from_slice(b"PK\x06\x06");
    data.extend_from_slice(&44_u64.to_le_bytes());
    data.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&64_u64.to_le_bytes());
    data.extend_from_slice(&64_u64.to_le_bytes());
    data.extend_from_slice(&(64_u64 * 65_536).to_le_bytes());
    data.extend_from_slice(&decoy_at.to_le_bytes());
    data.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    data.extend_from_slice(&record_at.to_le_bytes());
    data.extend_from_slice(&1_u32.to_le_bytes());
    // The 32-bit record describes the real directory, but its end-relative
    // start is off (the ZIP64 records sit between), so only the recorded
    // offset finds it.
    data.extend(end_record(4001, real_len, real_at, b""));
    assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn a_cut_decoy_walk_does_not_stop_a_fresh_one() {
    // A decoy chain whose last entry lands on the real directory's 22nd
    // entry with its 4 MiB limit used up exactly, so it is cut there.
    // The real walk reaching that entry later must not stop on it.
    let entry_len = 46 + 2;
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(64, 0);
    let decoy_at = data.len();
    // 21 entries of 196,651 bytes, then one sized to finish just short of
    // real entry 22.
    let big = dir_entry(&[b'd'; 65_535], 65_535, 65_535);
    assert_eq!(big.len(), 196_651);
    let mut decoy = Vec::new();
    for _ in 0..21 {
        decoy.extend_from_slice(&big);
    }
    let cap = 4 * 1024 * 1024;
    // Covered after the last decoy entry plus real entry 22 equals the cap.
    let last_len = cap - decoy.len() - entry_len;
    let last = dir_entry(b"d", 0, (last_len - 47) as u16);
    assert_eq!(last.len(), last_len);
    decoy.extend_from_slice(&last);
    let entry22 = decoy_at + decoy.len();
    let real_at = entry22 - 22 * entry_len;
    // The decoy chain overlaps the start of the real directory.
    data.resize(decoy_at, 0);
    data.extend_from_slice(&decoy);
    data.truncate(real_at);
    let mut real = Vec::new();
    for i in 0..23 {
        real.extend(dir_entry(format!("{i:02}").as_bytes(), 0, 0));
    }
    real.extend(dir_entry(b"AppxManifest.xml", 0, 0));
    data.extend_from_slice(&real);
    let record_at = data.len() as u64;
    data.extend_from_slice(b"PK\x06\x06");
    data.extend_from_slice(&44_u64.to_le_bytes());
    data.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&1_u64.to_le_bytes());
    data.extend_from_slice(&1_u64.to_le_bytes());
    data.extend_from_slice(&1_u64.to_le_bytes());
    data.extend_from_slice(&(decoy_at as u64).to_le_bytes());
    data.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    data.extend_from_slice(&record_at.to_le_bytes());
    data.extend_from_slice(&1_u32.to_le_bytes());
    data.extend(end_record(24, real.len() as u32, real_at as u32, b""));
    assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn directories_inside_the_end_record_comment() {
    let lfh = {
        let mut l = b"PK\x03\x04".to_vec();
        l.resize(30, 0);
        l
    };
    let decoy = dir_entry(b"readme.txt", 0, 0);
    let real = dir_entry(b"AppxManifest.xml", 0, 0);
    // A decoy before the end record, the real directory in its comment,
    // and the recorded offset pointing at the real one.
    let mut data = lfh.clone();
    data.extend_from_slice(&decoy);
    let end_pos = data.len() as u32;
    data.extend(end_record(1, decoy.len() as u32, end_pos + 22, &real));
    let c = classify(&data, Some("invoice.pdf"));
    assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
    // The end record at offset 0, the archive in its comment.
    let mut at0 = Vec::new();
    let mut comment = lfh.clone();
    comment.extend_from_slice(&real);
    at0.extend(end_record(1, 0, (22 + lfh.len()) as u32, &comment));
    assert_fails_closed(&classify(&at0, None), ParseError::ZipDirectoryAmbiguous);
    // A ZIP64 end record in the 32-bit end record's comment, pointing at
    // the real directory, with the 32-bit record describing a decoy.
    let mut z = lfh.clone();
    let real_at = z.len() as u64;
    z.extend_from_slice(&real);
    let decoy2_at = z.len() as u32;
    z.extend_from_slice(&decoy);
    let end2 = z.len() as u64 + 20;
    let mut record = b"PK\x06\x06".to_vec();
    record.extend_from_slice(&44_u64.to_le_bytes());
    record.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    record.extend_from_slice(&1_u64.to_le_bytes());
    record.extend_from_slice(&1_u64.to_le_bytes());
    record.extend_from_slice(&(real.len() as u64).to_le_bytes());
    record.extend_from_slice(&real_at.to_le_bytes());
    z.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    z.extend_from_slice(&(end2 + 22).to_le_bytes());
    z.extend_from_slice(&1_u32.to_le_bytes());
    z.extend(end_record(0xffff, decoy.len() as u32, decoy2_at, &record));
    assert_fails_closed(&classify(&z, None), ParseError::ZipDirectoryAmbiguous);
    // An entry whose comment runs past the end of the file, next to a
    // clean decoy walk: its name still counts.
    let mut over = lfh.clone();
    let d_at = over.len() as u32;
    over.extend_from_slice(&decoy);
    let r_at = over.len() as u32;
    over.extend(
        dir_entry(b"AppxManifest.xml", 0, 0)[..46 + 16]
            .iter()
            .copied(),
    );
    let n = over.len();
    put16(&mut over, n - 16 - 14, 200);
    over.extend(end_record(1, r_at - d_at, d_at, b""));
    assert_fails_closed(&classify(&over, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn zip64_read_failures_are_reported() {
    // A reader that fails past a point: the ZIP64 record at the locator's
    // offset cannot be read.
    struct FailPast(Cursor<Vec<u8>>, u64);
    impl Read for FailPast {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let pos = self.0.position();
            if pos < self.1 && pos + buf.len() as u64 > self.1 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if pos >= self.1 && pos < self.1 + 56 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.0.read(buf)
        }
    }
    impl Seek for FailPast {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }
    let data = zip64_hidden(&["AppxManifest.xml"], 0, 0, 0, true);
    let record = data.windows(4).rposition(|w| w == b"PK\x06\x06").unwrap() as u64;
    // The archive behind a 64 KiB stub, so the record is read with a
    // targeted read that the reader fails.
    let mut big = vec![0_u8; HEAD_LEN];
    big[..4].copy_from_slice(b"PK\x03\x04");
    let shift = big.len() as u64;
    let shifted = zip64_hidden(&["AppxManifest.xml"], 0, 0, 0, true);
    big.extend_from_slice(&shifted);
    let mut reader = FailPast(Cursor::new(big), shift + record);
    let c = filetype::classify(&mut reader, None);
    assert!(matches!(c.parse_error, Some(ParseError::Io(_))), "{c:?}");
    assert!(c.is_executable_content(), "{c:?}");
}

/// A clean archive of directory entries `names` (no local headers needed
/// for classification), with `comment` as the archive comment.
fn clean_zip(names: &[&[u8]], comment: &[u8]) -> Vec<u8> {
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(30, 0);
    let dir_at = data.len() as u32;
    for name in names {
        data.extend(dir_entry(name, 0, 0));
    }
    let size = data.len() as u32 - dir_at;
    data.extend(end_record(names.len() as u16, size, dir_at, comment));
    data
}

#[test]
fn clean_archives_have_one_reading() {
    for (names, want) in [
        (&[&b"AppxManifest.xml"[..]][..], FileKind::Msix),
        (&[b"META-INF/MANIFEST.MF", b"a.class"], FileKind::Jar),
        (&[b"readme.txt"], FileKind::Zip),
        (&[], FileKind::Zip),
    ] {
        for comment in [&b""[..], b"a comment"] {
            let c = classify(&clean_zip(names, comment), None);
            assert_eq!((c.content_kind, c.parse_error.clone()), (want, None));
            assert_eq!(c.is_executable_content(), want != FileKind::Zip);
        }
    }
}

#[test]
fn ambiguous_end_records_fail_closed() {
    let real = dir_entry(b"__main__.py", 0, 0);
    let decoy = dir_entry(b"readme.txt", 0, 0);
    let lfh = {
        let mut l = b"PK\x03\x04".to_vec();
        l.resize(30, 0);
        l
    };
    // Round 8: a decoy end record whose comment reaches the end of the
    // file, holding the real directory and a second end record with a
    // trailing byte (or an overlong comment). Python takes the last
    // signature and runs the real `__main__.py`.
    for tail in [&b"X"[..], b""] {
        let mut data = lfh.clone();
        let decoy_at = data.len() as u32;
        data.extend_from_slice(&decoy);
        let end1 = data.len() as u32;
        let real_at = end1 + 22;
        let mut inner = real.clone();
        let comment_len: u16 = if tail.is_empty() { 100 } else { 0 };
        let mut end2 = end_record(1, real.len() as u32, real_at, b"");
        put16(&mut end2, 20, comment_len);
        inner.extend_from_slice(&end2);
        inner.extend_from_slice(tail);
        data.extend(end_record(1, decoy.len() as u32, decoy_at, &inner));
        for name in [Some("nested.pyz"), Some("invoice.pdf"), None] {
            let c = classify(&data, name);
            assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
            if name == Some("invoice.pdf") {
                assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
            }
        }
    }
    // The same with a ZIP64 end record and locator inside the comment.
    let mut data = lfh.clone();
    let decoy_at = data.len() as u32;
    data.extend_from_slice(&decoy);
    let end1 = data.len() as u64;
    let real_at = end1 + 22;
    let mut inner = real.clone();
    let record_at = real_at + real.len() as u64;
    inner.extend_from_slice(b"PK\x06\x06");
    inner.extend_from_slice(&44_u64.to_le_bytes());
    inner.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    inner.extend_from_slice(&1_u64.to_le_bytes());
    inner.extend_from_slice(&1_u64.to_le_bytes());
    inner.extend_from_slice(&(real.len() as u64).to_le_bytes());
    inner.extend_from_slice(&real_at.to_le_bytes());
    inner.extend_from_slice(b"PK\x06\x07\0\0\0\0");
    inner.extend_from_slice(&record_at.to_le_bytes());
    inner.extend_from_slice(&1_u32.to_le_bytes());
    inner.extend(end_record(0xffff, 0xffff_ffff, 0xffff_ffff, b""));
    inner.push(b'X');
    data.extend(end_record(1, decoy.len() as u32, decoy_at, &inner));
    assert_fails_closed(
        &classify(&data, Some("AppxManifest.zip")),
        ParseError::ZipDirectoryAmbiguous,
    );
    // Trailing data after a clean archive.
    let mut trailing = clean_zip(&[b"AppxManifest.xml"], b"");
    trailing.push(0);
    assert_fails_closed(
        &classify(&trailing, None),
        ParseError::ZipDirectoryAmbiguous,
    );
    // A comment that runs past the end of the file.
    let mut short = clean_zip(&[b"AppxManifest.xml"], b"abc");
    short.pop();
    assert_fails_closed(&classify(&short, None), ParseError::ZipDirectoryAmbiguous);
    // An end record signature inside the last entry's comment, with a
    // comment length that would reach the end of the file.
    let mut nested = clean_zip(&[b"AppxManifest.xml"], b"");
    let end = nested.len() - 22;
    let fake = end_record(0, 0, 0, b"");
    let mut entry_end = nested[..end].to_vec();
    let mut fake_with_len = fake.clone();
    put16(&mut fake_with_len, 20, 22);
    entry_end.extend_from_slice(&fake_with_len);
    entry_end.extend_from_slice(&nested[end..]);
    nested = entry_end;
    let e = nested.len() - 22;
    let last = 30;
    put16(&mut nested, last + 32, 22);
    put32(&mut nested, e + 12, (e - 30) as u32);
    assert_fails_closed(&classify(&nested, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn ambiguous_directories_fail_closed() {
    let names: [&[u8]; 2] = [b"readme.txt", b"AppxManifest.xml"];
    let good = clean_zip(&names, b"");
    let end = good.len() - 22;
    let first = 46 + names[0].len();
    // Round 8: walks that would join another's chain. A directory start in
    // the middle of the real one (the recorded offset and the end-relative
    // start disagree).
    let mut mid = good.clone();
    put32(&mut mid, end + 16, 30 + first as u32);
    let c = classify(&mid, Some("invoice.pdf"));
    assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
    assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
    // A size that covers only the first entry, with a matching offset.
    let mut part = good.clone();
    put32(&mut part, end + 12, first as u32);
    put32(&mut part, end + 16, (end - first) as u32);
    assert_fails_closed(&classify(&part, None), ParseError::ZipDirectoryAmbiguous);
    // Data between the directory and the end record.
    let mut gap = good[..end].to_vec();
    gap.extend_from_slice(&[0; 8]);
    gap.extend_from_slice(&good[end..]);
    assert_fails_closed(&classify(&gap, None), ParseError::ZipDirectoryAmbiguous);
    // More entries in the directory than the count says, or fewer.
    for count in [1_u16, 3] {
        let mut c = good.clone();
        put16(&mut c, end + 8, count);
        put16(&mut c, end + 10, count);
        let c = classify(&c, None);
        assert_fails_closed(&c, ParseError::ZipDirectoryAmbiguous);
        // Every name that fits is still noted.
        assert_eq!(c.content_kind, FileKind::Msix);
    }
}

#[test]
fn truncated_and_overflowing_entries_fail_closed() {
    let names: [&[u8]; 2] = [b"readme.txt", b"AppxBundleManifest"];
    let good = clean_zip(&names, b"");
    let end = good.len() - 22;
    let second = 30 + 46 + names[0].len();
    // Round 8: an entry whose name, extra field or comment runs past the
    // directory.
    for (field, value) in [(28, 0x7000_u16), (30, 200), (32, 200), (32, 0xffff)] {
        let mut data = good.clone();
        put16(&mut data, second + field, value);
        assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryMalformed);
    }
    // A directory cut short mid-header, its size and offset still
    // consistent with the end record.
    let mut cut = good[..second + 20].to_vec();
    cut.extend(end_record(2, (second + 20 - 30) as u32, 30, b""));
    assert_fails_closed(&classify(&cut, None), ParseError::ZipDirectoryMalformed);
    // A directory that ends between records (three bytes of a signature).
    let mut stub = good[..end].to_vec();
    stub.extend_from_slice(b"PK\x01");
    stub.extend(end_record(2, (end + 3 - 30) as u32, 30, b""));
    assert_fails_closed(&classify(&stub, None), ParseError::ZipDirectoryMalformed);
    // A reader that returns less than the length it reported.
    struct Short(Cursor<Vec<u8>>, u64);
    impl Read for Short {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let left = self.1.saturating_sub(self.0.position()) as usize;
            let n = buf.len().min(left);
            self.0.read(&mut buf[..n])
        }
    }
    impl Seek for Short {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            match pos {
                SeekFrom::End(0) => Ok(self.0.get_ref().len() as u64 + 4096),
                other => self.0.seek(other),
            }
        }
    }
    let mut big = vec![0_u8; HEAD_LEN];
    big[..4].copy_from_slice(b"PK\x03\x04");
    let mut reader = Short(Cursor::new(big), HEAD_LEN as u64);
    let c = filetype::classify(&mut reader, None);
    assert_eq!(c.content_kind, FileKind::Zip);
    assert!(
        c.parse_error.is_some() && c.is_executable_content(),
        "{c:?}"
    );
}

#[test]
fn zip64_layouts_fail_closed_unless_consistent() {
    let names = ["AppxManifest.xml"];
    let base = zip(b"", &names);
    let end = base.len() - 22;
    let size = u32::from_le_bytes(base[end + 12..end + 16].try_into().unwrap());
    let offset = u32::from_le_bytes(base[end + 16..end + 20].try_into().unwrap());
    // Consistent: sentinels, or the same values, in the 32-bit record.
    for (count, s, o) in [(0xffff, 0xffff_ffff, 0xffff_ffff), (1, size, offset)] {
        let c = classify(&zip64_hidden(&names, count, s, o, true), None);
        assert_eq!((c.content_kind, c.parse_error), (FileKind::Msix, None));
    }
    let good = zip64_hidden(&names, 0xffff, 0xffff_ffff, 0xffff_ffff, true);
    let record = good.len() - 22 - 20 - 56;
    let locator = good.len() - 22 - 20;
    let cases: [(usize, &[u8]); 6] = [
        // Locator offset not at the record.
        (locator + 8, &1_u64.to_le_bytes()),
        // Locator disk count of 2, and of 0.
        (locator + 16, &2_u32.to_le_bytes()),
        (locator + 16, &0_u32.to_le_bytes()),
        // The two ZIP64 entry counts disagree.
        (record + 24, &2_u64.to_le_bytes()),
        // A record size with extensible data that is not there.
        (record + 4, &45_u64.to_le_bytes()),
        // A directory offset that does not meet the record.
        (record + 48, &1_u64.to_le_bytes()),
    ];
    for (at, value) in cases {
        let mut data = good.clone();
        data[at..at + value.len()].copy_from_slice(value);
        assert_fails_closed(&classify(&data, None), ParseError::ZipDirectoryAmbiguous);
    }
    // A locator with no record before it.
    let mut lonely = good.clone();
    lonely[record..record + 4].copy_from_slice(b"XXXX");
    assert_fails_closed(&classify(&lonely, None), ParseError::ZipDirectoryAmbiguous);
    // A second ZIP64 record signature after the real one.
    let mut second = good;
    second[record + 30..record + 34].copy_from_slice(b"PK\x06\x06");
    assert_fails_closed(&classify(&second, None), ParseError::ZipDirectoryAmbiguous);
}

#[test]
fn hidden_names_are_noted() {
    // A NUL byte in a name: some readers cut the name there.
    let c = classify(&clean_zip(&[b"AppxManifest.xml\0.txt"], b""), None);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Msix, None));
    // A percent-encoded part name, as the package reader decodes it.
    for name in [
        &b"AppxManifest%2Exml"[..],
        b"AppxMetadata%2fAppxBundleManifest.xml",
    ] {
        let c = classify(&clean_zip(&[name], b""), None);
        assert!(c.is_executable_content(), "{c:?}");
    }
    assert_eq!(
        kind(&clean_zip(&[b"100%25.txt", b"%zz"], b""), None),
        FileKind::Zip
    );
    // A Unicode path extra field: some readers use its name instead.
    let mut entry = dir_entry(b"readme.txt", 0, 0);
    let unicode = b"__main__.py";
    let mut extra = 0x7075_u16.to_le_bytes().to_vec();
    extra.extend_from_slice(&(5 + unicode.len() as u16).to_le_bytes());
    extra.push(1);
    extra.extend_from_slice(&[0; 4]);
    extra.extend_from_slice(unicode);
    put16(&mut entry, 30, extra.len() as u16);
    entry.extend_from_slice(&extra);
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(30, 0);
    data.extend_from_slice(&entry);
    data.extend(end_record(1, entry.len() as u32, 30, b""));
    let c = classify(&data, Some("a.pyz"));
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::Script(ScriptKind::Python), None)
    );
}

#[test]
fn unicode_path_floods_are_linear() {
    // Round 9: a directory of entries whose extra fields are packed with
    // tiny Unicode path subfields (some percent-encoded) once allocated
    // for every subfield.
    // Whole subfields only, up to the 65,535-byte extra field limit: a
    // cut subfield is malformed (round 15).
    let mut sub = Vec::new();
    for i in 0.. {
        let name: &[u8] = if i % 2 == 0 { b"a" } else { b"%41" };
        if sub.len() + 9 + name.len() > 65_535 {
            break;
        }
        flood_entry(&mut sub, name);
    }
    assert_linear_flood(&sub, None);
    // Round 10: subfields as long as a target name, nearly matching it,
    // with and without an escape, plain and behind a shebang with a
    // planted volume descriptor.
    for name in [
        &b"AppxMetadata/AppxBundleManifest.xm%"[..],
        b"AppxMetadata/AppxBundleManifest.x%6d",
        b"AppxMetadata/AppxBundleManifest.xm\0",
    ] {
        let mut sub = Vec::new();
        while sub.len() + 9 + name.len() <= 65_535 {
            flood_entry(&mut sub, name);
        }
        assert_linear_flood(&sub, None);
        assert_linear_flood(&sub, Some(b"#!/bin/sh\n"));
    }
}

/// Appends one Unicode path extra subfield naming `name`.
fn flood_entry(sub: &mut Vec<u8>, name: &[u8]) {
    sub.extend_from_slice(&0x7075_u16.to_le_bytes());
    sub.extend_from_slice(&(5 + name.len() as u16).to_le_bytes());
    sub.extend_from_slice(&[1, 0, 0, 0, 0]);
    sub.extend_from_slice(name);
}

/// A clean archive with about 4 MiB of entries, each with `sub` as its
/// extra field, optionally behind `shebang` with a disc image descriptor
/// planted at 32 KiB: it is read in bounded time and is not a package.
fn assert_linear_flood(sub: &[u8], shebang: Option<&[u8]>) {
    let mut data = shebang.unwrap_or_default().to_vec();
    data.extend_from_slice(b"PK\x03\x04");
    data.resize(data.len() + 26, 0);
    if shebang.is_some() {
        data.resize(0x8000 + 2048, 0);
        data[0x8000..0x8007].copy_from_slice(b"\x01CD001\x01");
    }
    let dir_at = data.len() as u32;
    let mut count = 0_u16;
    while data.len() + sub.len() + 47 < (4 << 20) - 64 {
        let mut entry = dir_entry(b"d", 0, 0);
        put16(&mut entry, 30, sub.len() as u16);
        entry.extend_from_slice(sub);
        data.extend_from_slice(&entry);
        count += 1;
    }
    let size = data.len() as u32 - dir_at;
    data.extend(end_record(count, size, dir_at, b""));
    let started = std::time::Instant::now();
    for name in [None, Some("a.exe"), Some("a.pyz")] {
        let c = classify(&data, name);
        if shebang.is_some() {
            // The script the `#!/bin/sh` line names, not a zip
            // application.
            assert_eq!(
                c.content_kind,
                FileKind::Script(ScriptKind::Shell),
                "{name:?}"
            );
            assert!(!c.flags.python_zipapp, "{name:?}");
        } else {
            assert!(!c.is_executable_content(), "{name:?}");
            assert_eq!(
                (c.content_kind, c.parse_error),
                (FileKind::Zip, None),
                "{name:?}"
            );
        }
    }
    // Generous: debug builds on slow CI runners.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn signature_record_floods_are_linear() {
    // Round 8: a 4 MiB run of empty digital signature records between
    // decoy starts once took millions of steps. Now the directory is read
    // once and the first non-entry record ends it.
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(30, 0);
    let dir_at = data.len() as u32;
    let sled_len = 4 << 20;
    data.extend(b"PK\x05\x05\0\0".iter().copied().cycle().take(sled_len));
    let size = data.len() as u32 - dir_at;
    data.extend(end_record(0, size, dir_at, b""));
    let started = std::time::Instant::now();
    for name in [None, Some("a.exe"), Some("a.pyz")] {
        assert_fails_closed(&classify(&data, name), ParseError::ZipDirectoryAmbiguous);
    }
    // Generous: debug builds on slow CI runners. The old code took over a
    // second per call in release.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn harmless_double_extensions() {
    let pe = PeBuilder::default().build();
    for name in ["disc.udf.exe", "backup.tgz.exe", "photos.7z.exe"] {
        assert_eq!(
            classify(&pe, Some(name)).mismatch_severity,
            MismatchSeverity::Critical,
            "{name}"
        );
    }
    assert_eq!(
        classify(&pe, Some("tool.dll.exe")).mismatch_severity,
        MismatchSeverity::None
    );
}

#[test]
fn truncated_names_and_load_config() {
    // An export name cut off by the end of the section raw data.
    let cut = |rva: u32| {
        let mut out = exports(&[])(rva);
        out.resize(0x200, 0);
        put32(&mut out, 24, 1);
        put32(&mut out, 32, rva + 0x100);
        put32(&mut out, 0x100, rva + 0x1fb);
        out[0x1fb..0x200].copy_from_slice(b"CPlAp");
        out
    };
    let dll = PeBuilder {
        entry_point: 0x1000,
        ..PeBuilder::dll()
    };
    assert!(pe_details(&pe_with(dll, cut, &[(0, 0, 40)]), None).incomplete);
    // A load configuration with only two bytes of raw data left.
    let full = |_rva: u32| vec![0_u8; 0x200];
    let d = pe_details(
        &pe_with(PeBuilder::default(), full, &[(10, 0x1fe, 0x140)]),
        None,
    );
    assert!(d.incomplete && d.hybrid.is_none());
}

#[test]
fn planted_volume_descriptor_does_not_hide_a_script() {
    let mut script = "Write-Host hi\n".repeat(0x9000 / 14).into_bytes();
    script.resize(0x9800, b'\n');
    script[..9].copy_from_slice(b"#!/bin/sh");
    script[0x8000] = 1;
    script[0x8001..0x8006].copy_from_slice(b"CD001");
    script[0x8006] = 1;
    assert_eq!(kind(&script, None), FileKind::Script(ScriptKind::Shell));
    // Without a definite marker, a valid descriptor is a disc image.
    assert_eq!(kind(&iso(b"CD001"), None), FileKind::Iso);
}

#[test]
fn signature_block_keeps_hta_and_reg() {
    let hta = format!("{HTA}\n'' SIG '' Begin signature block\n");
    assert_eq!(kind(hta.as_bytes(), None), FileKind::Hta);
    let c = classify(hta.as_bytes(), Some("app.hta"));
    assert!(c.flags.script_signature_block && !c.mismatch);
    let reg = "REGEDIT4\r\n# SIG # Begin signature block\r\n";
    assert_eq!(kind(reg.as_bytes(), None), FileKind::Reg);
}

#[test]
fn legacy_executables_fit_exe_names() {
    let mut dos = vec![0_u8; 0x80];
    dos[..2].copy_from_slice(b"MZ");
    assert!(!classify(&dos, Some("old.exe")).mismatch);
    assert!(!classify(&dos, Some("old.com")).mismatch);
    let mut ne = dos.clone();
    put32(&mut ne, 0x3c, 0x40);
    ne[0x40..0x42].copy_from_slice(b"NE");
    assert!(!classify(&ne, Some("old.exe")).mismatch);
    assert!(!classify(&ne, Some("old.drv")).mismatch);
    assert_eq!(
        classify(&ne, Some("old.sys")).mismatch_severity,
        MismatchSeverity::Benign
    );
    assert_eq!(
        classify(&dos, Some("old.pdf")).mismatch_severity,
        MismatchSeverity::Suspicious
    );
}

#[test]
fn names_that_disguise() {
    let pe = PeBuilder::default().build();
    for name in [
        "invoice.pdf..exe",
        "invoice.pdf. .exe",
        "photos.zip.exe",
        "page.html.exe",
    ] {
        assert_eq!(
            classify(&pe, Some(name)).mismatch_severity,
            MismatchSeverity::Critical,
            "{name}"
        );
    }
    // A PE in an alternate data stream of a text file.
    let c = classify(&pe, Some(r"C:\temp\a.txt:payload.exe"));
    assert_eq!(c.mismatch_severity, MismatchSeverity::Suspicious);
    let c = classify(&pe, Some(r"C:\temp\a:payload.exe"));
    assert_eq!(c.extension_kind, ExtensionKind::None);
    let long = format!("a.{}", "x".repeat(40));
    let c = classify(&pe, Some(&long));
    assert_eq!(
        (c.extension_kind, c.mismatch_severity),
        (ExtensionKind::Other, MismatchSeverity::Benign)
    );
    // A package renamed to `.zip` is a mismatch.
    let package = zip(b"", &["AppxManifest.xml"]);
    assert_eq!(
        classify(&package, Some("a.zip")).mismatch_severity,
        MismatchSeverity::Suspicious
    );
}

#[test]
fn hta_names_with_other_html() {
    let c = classify(b"<svg onload=\"x()\"></svg>", Some("a.hta"));
    assert_eq!(c.content_kind, FileKind::Hta);
}

#[test]
fn parse_errors_display() {
    assert_eq!(
        ParseError::ZipDirectoryMissing.to_string(),
        "no ZIP end of central directory record"
    );
    let e: &dyn std::error::Error = &ParseError::CfbHeader;
    assert!(!e.to_string().is_empty());
    assert!(!ParseError::PeHeadersTruncated.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Review round 15: short reads and markers
// ---------------------------------------------------------------------------

#[test]
fn compound_file_root_entry_cut_after_its_clsid() {
    // The file ends 20 bytes before the end of the root entry, after the
    // CLSID: the CLSID still decides the kind, and the cut is reported.
    let msi = cfb(installer_clsid(0x000c_1084));
    let c = classify(&msi[..512 + 108], None);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::Msi, Some(ParseError::CfbDirectory))
    );
    let c = classify(&cfb([0; 16])[..512 + 108], None);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::OtherCfb, Some(ParseError::CfbDirectory))
    );
    // A whole entry is clean.
    let c = classify(&msi[..512 + 128], None);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Msi, None));
}

#[test]
fn pe_cut_inside_its_section_table_stays_executable() {
    // One executable section, no directories and no entry point: with the
    // section header cut off, it once looked resource-only.
    let b = PeBuilder {
        entry_point: 0,
        ..PeBuilder::default()
    };
    let image = b.build();
    let table = b.section_table_offset();
    // Inside the section header, and inside the data directories.
    for cut in [table + 20, table + 39, table - 8] {
        let c = classify(&image[..cut], None);
        assert_eq!(
            (c.content_kind, c.parse_error.clone()),
            (FileKind::Mz16, Some(ParseError::PeHeadersTruncated)),
            "cut at {cut}"
        );
        assert!(c.pe.is_none() && c.is_executable_content(), "{c:?}");
    }
    // The whole section table is enough.
    let d = pe_details(&image[..table + 40], None);
    assert_eq!(d.sub_kind, PeSubKind::Exe);
    // A complete resource-only image is still resource-only.
    let mut ro = PeBuilder::dll();
    ro.sections[0].characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    let ro = ro.build();
    assert_eq!(pe_details(&ro, None).sub_kind, PeSubKind::ResourceOnly);
    assert_eq!(classify(&ro, None).parse_error, None);
}

/// A reader that fails every read from offset `.1` on.
struct FailFrom(Cursor<Vec<u8>>, u64);

impl Read for FailFrom {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0.position() >= self.1 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.0.read(buf)
    }
}

impl Seek for FailFrom {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

#[test]
fn unreadable_signature_tail_is_reported() {
    let denied = Some(ParseError::Io(io::ErrorKind::PermissionDenied));
    let fail_tail = |data: &[u8]| {
        filetype::classify(
            &mut FailFrom(Cursor::new(data.to_vec()), HEAD_LEN as u64),
            None,
        )
    };
    // Plain text whose signature block marker would be in the tail.
    let mut text = b"just some words\n".repeat(HEAD_LEN / 8);
    text.extend_from_slice(b"# SIG # Begin signature block\n");
    let c = fail_tail(&text);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::Text, denied.clone())
    );
    // Read in full, the marker names the language.
    let c = classify(&text, None);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::Script(ScriptKind::PowerShell), None)
    );
    // A definite marker in the head keeps its kind; the error is reported.
    let mut shell = b"#!/bin/sh\n".to_vec();
    shell.extend(b"echo hi\n".repeat(HEAD_LEN / 4));
    let c = fail_tail(&shell);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::Script(ScriptKind::Shell), denied)
    );
    // A tail read in full with no marker is a clean negative.
    let c = classify(&shell, None);
    assert!(!c.flags.script_signature_block);
    assert_eq!(
        (c.content_kind, c.parse_error),
        (FileKind::Script(ScriptKind::Shell), None)
    );
}

#[test]
fn rust_inner_attributes_are_not_shebangs() {
    for src in [
        &b"#![allow(dead_code)]\nfn main() {}\n"[..],
        b"#! [forbid(unsafe_code)]\n\nmod a;\n",
    ] {
        let c = classify(src, None);
        assert_ne!(c.content_kind, FileKind::Script(ScriptKind::Shell), "{c:?}");
        assert!(!c.is_executable_content(), "{c:?}");
    }
    // Shebangs, including one naming an unknown interpreter, are scripts.
    assert_eq!(
        kind(b"#!/opt/tool/runner\nx\n", None),
        FileKind::Script(ScriptKind::Shell)
    );
    assert_eq!(
        kind(b"#!python3\nprint(1)\n", None),
        FileKind::Script(ScriptKind::Python)
    );
    // Named as a shell script, it is one whatever the first line says.
    assert_eq!(
        kind(b"#![allow(dead_code)]\n", Some("build.sh")),
        FileKind::Script(ScriptKind::Shell)
    );
}

#[test]
fn definite_markers_win_over_the_hta_name() {
    let wsf = b"<job id=\"a\"><script language=\"VBScript\">x</script></job>";
    let c = classify(wsf, Some("app.hta"));
    assert_eq!(
        (c.content_kind, c.confidence),
        (FileKind::Script(ScriptKind::Wsf), Confidence::High)
    );
    assert!(!c.extension_assisted && c.mismatch, "{c:?}");
    let php = b"<html><body><?php echo 1; ?></body></html>";
    assert_eq!(
        kind(php, Some("app.hta")),
        FileKind::Script(ScriptKind::Php)
    );
    // Plain HTML still takes the name.
    let c = classify(b"<html><body>hi</body></html>", Some("app.hta"));
    assert_eq!(
        (c.content_kind, c.confidence),
        (FileKind::Hta, Confidence::Medium)
    );
    assert!(c.extension_assisted && !c.mismatch);
}

#[test]
fn env_shebang_options_with_operands() {
    let c = classify(b"#!/usr/bin/env -S -u PYTHONPATH python3\nprint(1)\n", None);
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Python));
    assert_eq!(
        kind(b"#!/usr/bin/env -i A=1 -u B perl\n", None),
        FileKind::Script(ScriptKind::Perl)
    );
}

/// A clean one-entry archive whose entry has `extra` as its extra field.
fn zip_with_extra(name: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut entry = dir_entry(name, 0, 0);
    put16(&mut entry, 30, extra.len() as u16);
    entry.extend_from_slice(extra);
    let mut data = b"PK\x03\x04".to_vec();
    data.resize(30, 0);
    data.extend_from_slice(&entry);
    data.extend(end_record(1, entry.len() as u32, 30, b""));
    data
}

#[test]
fn cut_extra_subfields_are_malformed() {
    let cut_header = [0x01, 0x00, 0x04];
    let cut_body = [0xfe, 0xca, 0x0a, 0x00, b'x', b'y'];
    let whole_then_cut = [0xfe, 0xca, 0x01, 0x00, b'x', 0x01];
    for extra in [&cut_header[..], &cut_body, &whole_then_cut] {
        let c = classify(&zip_with_extra(b"readme.txt", extra), None);
        assert_eq!(c.content_kind, FileKind::Zip);
        assert_fails_closed(&c, ParseError::ZipDirectoryMalformed);
        // The entry's own name still counts.
        let c = classify(&zip_with_extra(b"AppxManifest.xml", extra), None);
        assert_eq!(c.content_kind, FileKind::Msix);
        assert_fails_closed(&c, ParseError::ZipDirectoryMalformed);
    }
    // Complete unknown subfields, and an empty one, are fine.
    let whole = [0xfe, 0xca, 0x02, 0x00, b'x', b'y', 0x01, 0x00, 0x00, 0x00];
    let c = classify(&zip_with_extra(b"readme.txt", &whole), None);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Zip, None));
}

#[test]
fn zip_application_entry_names_are_exact() {
    for name in ["__MAIN__.PY", "__Main__.py", "__main__.PYC"] {
        // Python's zip importer finds `__main__` by its exact name.
        let c = classify(&zip(b"#!/bin/sh\n", &[name]), None);
        assert_eq!(
            c.content_kind,
            FileKind::Script(ScriptKind::Shell),
            "{name}"
        );
        assert!(!c.flags.python_zipapp, "{name}");
        let c = classify(&zip(b"", &[name]), Some("tool.pyz"));
        assert!(!c.flags.python_zipapp, "{name}");
    }
    for name in ["__main__.py", "__main__.pyc"] {
        let c = classify(&zip(b"#!/bin/sh\n", &[name]), None);
        assert_eq!(
            c.content_kind,
            FileKind::Script(ScriptKind::Python),
            "{name}"
        );
        assert!(c.flags.python_zipapp, "{name}");
    }
    // Package names still ignore case.
    assert_eq!(kind(&zip(b"", &["APPXMANIFEST.XML"]), None), FileKind::Msix);
}

// ---------------------------------------------------------------------------
// Review round 16: readers that end early, and failed reads in probes
// ---------------------------------------------------------------------------

/// A reader that reports `extra` more bytes than it has, then ends early
/// once it has returned `limit` bytes.
struct EndsEarly {
    data: Cursor<Vec<u8>>,
    limit: u64,
    extra: u64,
}

impl Read for EndsEarly {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.limit.saturating_sub(self.data.position()) as usize;
        let n = buf.len().min(left);
        self.data.read(&mut buf[..n])
    }
}

impl Seek for EndsEarly {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::End(0) => Ok(self.data.get_ref().len() as u64 + self.extra),
            other => self.data.seek(other),
        }
    }
}

fn classify_ending_early(data: &[u8], limit: usize, extra: u64) -> Classification {
    let mut reader = EndsEarly {
        data: Cursor::new(data.to_vec()),
        limit: limit as u64,
        extra,
    };
    filetype::classify(&mut reader, None)
}

const EOF: Option<ParseError> = Some(ParseError::Io(io::ErrorKind::UnexpectedEof));

#[test]
fn readers_that_end_early_are_reported() {
    // A PE whose reader returns nothing: not taken for an empty file.
    let pe = PeBuilder::default().build();
    let c = classify_ending_early(&pe, 0, 0);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Unknown, EOF));
    assert_eq!(c.file_size, pe.len() as u64);
    // An HTA cut after a leading comment, before its marker.
    let hta = b"<!-- a note -->\n<html><HTA:APPLICATION id=\"x\"/></html>\n";
    let c = classify_ending_early(hta, 16, 0);
    assert_eq!(c.parse_error, EOF, "{c:?}");
    // A whole file whose reader reports more than it has.
    let c = classify_ending_early(&pe, pe.len(), 4096);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Pe, EOF));
    // A signed script longer than the head, whose reader ends at the head.
    let mut signed = b"just some words\n".repeat(HEAD_LEN / 8);
    signed.extend_from_slice(b"# SIG # Begin signature block\n");
    let c = classify_ending_early(&signed, HEAD_LEN, 0);
    assert_eq!((c.content_kind, c.parse_error), (FileKind::Text, EOF));
    // A PE header past the head, where the reader ends.
    let image = PeBuilder::default().build();
    let shift = 0x2_0000;
    let mut moved = vec![0_u8; image.len() + shift];
    moved[..0x40].copy_from_slice(&image[..0x40]);
    put32(&mut moved, 0x3c, (E_LFANEW + shift) as u32);
    moved[E_LFANEW + shift..0x400 + shift].copy_from_slice(&image[E_LFANEW..0x400]);
    let c = classify_ending_early(&moved, HEAD_LEN, 0);
    assert_eq!(c.parse_error, EOF, "{c:?}");
    assert!(c.is_executable_content(), "{c:?}");
    // Read in full, each is clean.
    assert_eq!(classify(&pe, None).parse_error, None);
    assert_eq!(classify(hta, None).content_kind, FileKind::Hta);
    assert_eq!(classify(&moved, None).content_kind, FileKind::Pe);
}

#[test]
fn failed_reads_in_a_planted_descriptor_polyglot_are_reported() {
    // Text across the head with a planted descriptor, and a signature
    // block marker in the tail.
    let mut data = b"just some words\n".repeat(HEAD_LEN / 8);
    data[0x8000..0x8007].copy_from_slice(b"\x01CD001\x01");
    data.extend_from_slice(b"# SIG # Begin signature block\n");
    assert_eq!(kind(&data, None), FileKind::Script(ScriptKind::PowerShell));
    let c = filetype::classify(&mut FailFrom(Cursor::new(data), HEAD_LEN as u64), None);
    assert_eq!(
        c.parse_error,
        Some(ParseError::Io(io::ErrorKind::PermissionDenied)),
        "{c:?}"
    );
}

#[test]
fn failed_reads_in_the_shebang_zip_probe_are_reported() {
    // A zip application longer than the head, whose end records are past
    // it, where the reader fails.
    let long_a = "a".repeat(40_000);
    let long_b = "b".repeat(40_000);
    let app = zip(b"#!/bin/sh\n", &["__main__.py", &long_a, &long_b]);
    assert!(app.len() > HEAD_LEN + 70_000);
    let c = classify(&app, None);
    assert!(c.flags.python_zipapp, "{c:?}");
    let c = filetype::classify(&mut FailFrom(Cursor::new(app), HEAD_LEN as u64), None);
    assert_eq!(c.content_kind, FileKind::Script(ScriptKind::Shell));
    assert_eq!(
        c.parse_error,
        Some(ParseError::Io(io::ErrorKind::PermissionDenied)),
        "{c:?}"
    );
}

#[test]
fn failed_pe_directory_reads_are_reported() {
    // A native user-mode program importing `ntdll.dll`, with its import
    // section moved past the head, where the reader fails.
    let native = PeBuilder {
        subsystem: 1,
        ..PeBuilder::default()
    };
    let mut image = pe_with(native.clone(), imports(&["ntdll.dll"]), &[(1, 0, 40)]);
    let header = native.section_table_offset() + 40;
    let raw_ptr = u32::from_le_bytes(image[header + 20..header + 24].try_into().unwrap()) as usize;
    let raw_len = u32::from_le_bytes(image[header + 16..header + 20].try_into().unwrap()) as usize;
    let section = image[raw_ptr..raw_ptr + raw_len].to_vec();
    image.resize(HEAD_LEN, 0);
    image.extend_from_slice(&section);
    put32(&mut image, header + 20, HEAD_LEN as u32);
    let d = pe_details(&image, None);
    assert_eq!((d.sub_kind, d.incomplete), (PeSubKind::Exe, false));
    let c = filetype::classify(&mut FailFrom(Cursor::new(image), HEAD_LEN as u64), None);
    assert_eq!(c.content_kind, FileKind::Pe);
    assert!(c.pe.unwrap().incomplete);
    assert_eq!(
        c.parse_error,
        Some(ParseError::Io(io::ErrorKind::PermissionDenied))
    );
}

#[test]
fn rust_inner_attributes_do_not_start_a_zip_application() {
    let c = classify(&zip(b"#![x]\n", &["__main__.py"]), None);
    assert!(!c.flags.python_zipapp, "{c:?}");
    assert!(
        classify(&zip(b"#!/bin/sh\n", &["__main__.py"]), None)
            .flags
            .python_zipapp
    );
}

#[test]
fn a_short_head_is_the_reason_reported() {
    // Round 17: a compound file whose reader ends inside its header was
    // reported as a bad header, hiding that the read came up short.
    let msi = cfb(installer_clsid(0x000c_1084));
    for limit in [8, 20, 51, 600] {
        let c = classify_ending_early(&msi, limit, 0);
        assert_eq!(
            (c.content_kind, c.parse_error),
            (FileKind::OtherCfb, EOF),
            "limit {limit}"
        );
    }
    // A file that really is that short keeps its structure error.
    assert_eq!(
        classify(&msi[..20], None).parse_error,
        Some(ParseError::CfbHeader)
    );
}

#[test]
fn failed_shebang_zip_probe_reads_survive_a_planted_descriptor() {
    // Round 17: with a volume descriptor in the head as well, the probe's
    // read error was dropped on the disc image paths.
    let mut data = b"#!/bin/sh\nPK\x03\x04".to_vec();
    data.resize(0x8800, 0);
    data[0x8000..0x8007].copy_from_slice(b"\x01CD001\x01");
    data.resize(HEAD_LEN + 100_000, 0);
    let denied = Some(ParseError::Io(io::ErrorKind::PermissionDenied));
    for name in [None, Some("tool.sh"), Some("disk.iso")] {
        let mut reader = FailFrom(Cursor::new(data.clone()), HEAD_LEN as u64);
        let c = filetype::classify(&mut reader, name.map(OsStr::new));
        assert_eq!(c.parse_error, denied, "{name:?} {c:?}");
    }
    // With a reader that does not fail, the archive is ruled out cleanly.
    assert_eq!(classify(&data, None).parse_error, None);
}

#[test]
fn shebang_zip_needs_a_shebang_on_the_first_line() {
    assert!(
        !classify(&zip(b"#! \t[x]\n", &["__main__.py"]), None)
            .flags
            .python_zipapp
    );
    assert!(
        classify(&zip(b"#! /usr/bin/python3\n", &["__main__.py"]), None)
            .flags
            .python_zipapp
    );
}

/// Seed inputs for the property tests and the fuzz target.
fn seeds() -> Vec<Vec<u8>> {
    let dll = PeBuilder {
        entry_point: 0x1000,
        ..PeBuilder::dll()
    };
    vec![
        PeBuilder::default().build(),
        pe_with(
            dll.clone(),
            exports_and_named_resource(&["DllRegisterServer"], "TYPELIB"),
            &[(0, 0, 40), (2, 0x400, 0x400)],
        ),
        pe_with(
            PeBuilder {
                subsystem: 1,
                ..PeBuilder::default()
            },
            imports(&["ntoskrnl.exe"]),
            &[(1, 0, 40)],
        ),
        cfb(installer_clsid(0x000c_1084)),
        zip(b"", &["AppxManifest.xml", "AppxSignature.p7x"]),
        zip(b"#!/usr/bin/env python3\n", &["__main__.py"]),
        lnk(),
        POWERSHELL.as_bytes().to_vec(),
        utf16le(HTA, true),
        b"Windows Registry Editor Version 5.00\r\n".to_vec(),
    ]
}

/// Classifies `data` under every name hint, through a counting reader, and
/// checks the invariants.
fn check(data: &[u8]) {
    for name in [
        None,
        Some("a.exe"),
        Some("x.com"),
        Some("a.pdf.exe"),
        Some("s.ps1"),
    ] {
        let mut reader = Virtual {
            len: data.len() as u64,
            pos: 0,
            byte: |o: u64| data[o as usize],
            read: 0,
        };
        let c = filetype::classify(&mut reader, name.map(OsStr::new));
        assert!(reader.read <= READ_BOUND, "read {}", reader.read);
        assert_eq!(c.classifier_version, CLASSIFIER_VERSION);
        assert_eq!(c.file_size, data.len() as u64);
        assert_eq!(c.mismatch, c.mismatch_severity != MismatchSeverity::None);
        assert_eq!(c.pe.is_some(), c.content_kind == FileKind::Pe);
        if c.content_kind == FileKind::Com {
            assert!(c.heuristic && data.len() as u64 <= MAX_COM_SIZE);
        }
        if c.content_kind == FileKind::Unknown {
            assert!(!c.mismatch);
        }
        // A ZIP that could not be read in one consistent way fails closed.
        if c.content_kind == FileKind::Zip && c.parse_error.is_some() {
            assert!(c.is_executable_content());
        }
    }
}

#[test]
fn every_truncation_of_every_seed() {
    for seed in seeds() {
        for len in (0..seed.len()).step_by(7).chain([seed.len()]) {
            check(&seed[..len]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn random_bytes(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        check(&data);
    }

    #[test]
    fn mutated_seeds(
        index in 0_usize..10,
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..16),
        cut in any::<usize>(),
    ) {
        let mut data = seeds().swap_remove(index);
        for (at, value) in edits {
            let len = data.len();
            data[at % len] = value;
        }
        let keep = cut % (data.len() + 1);
        data.truncate(keep.max(data.len() / 2));
        check(&data);
    }
}

/// Writes the seeds as a fuzz corpus. Run with
/// `PALISADE_FUZZ_SEED_DIR=<dir> cargo test --test filetype -- --ignored`.
#[test]
#[ignore = "writes files; run by hand to seed the fuzz corpus"]
fn write_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    for (i, seed) in seeds().iter().enumerate() {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("seed-{i:02}")),
            seed,
        )
        .unwrap();
    }
}

#[test]
fn reader_position_does_not_matter() {
    let mut cursor = Cursor::new(PeBuilder::default().build());
    cursor.set_position(100);
    assert_eq!(
        filetype::classify(&mut cursor, None).content_kind,
        FileKind::Pe
    );
}

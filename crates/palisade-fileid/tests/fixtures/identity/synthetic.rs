//! The synthetic files of the file identity corpus (#55), built byte by
//! byte at test time. `signed.rs` signs some of them; `manifest.yaml`
//! names each by its `generator`. Shared by `tests/identity_corpus.rs` and
//! the `pal fileid` tests, so both see the same bytes.

#![allow(dead_code, clippy::indexing_slicing, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;

use crate::common::*;

fn version_image(strings: &[(&str, &str)], file: (u16, u16, u16, u16)) -> PeBuilder {
    let spec = VersionSpec {
        fixed: Some(fixed_info(file, file)),
        tables: vec![(
            "040904B0",
            strings.iter().map(|(k, v)| string(k, v)).collect(),
        )],
        translations: vec![(0x0409, 0x04b0)],
    };
    with_version(&spec)
}

/// A version resource that claims to be the OS PowerShell host.
fn powershell_strings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("CompanyName", "Palisade Tests"),
        ("FileDescription", "Windows PowerShell"),
        ("FileVersion", "10.0.0.1"),
        ("InternalName", "POWERSHELL"),
        ("OriginalFilename", "PowerShell.EXE.MUI"),
        ("ProductName", "Palisade Test OS"),
        ("ProductVersion", "10.0.0.1"),
    ]
}

/// A plain tool's version resource.
fn tool_strings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("CompanyName", "Example Org"),
        ("FileDescription", "Example tool"),
        ("FileVersion", "1.2.3.4"),
        ("InternalName", "extool"),
        ("OriginalFilename", "extool.exe"),
        ("ProductName", "Example Suite"),
        ("ProductVersion", "1.2.0.0"),
    ]
}

/// An import section for a section at `rva` importing `module!function`.
fn import_section(rva: u32, module: &str, function: &str) -> Vec<u8> {
    let mut out = vec![0_u8; 40];
    let thunks = out.len();
    out.resize(thunks + 16, 0);
    let hint = out.len();
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(function.as_bytes());
    out.push(0);
    if !out.len().is_multiple_of(2) {
        out.push(0);
    }
    let name = out.len();
    out.extend_from_slice(module.as_bytes());
    out.push(0);
    out[thunks..thunks + 8].copy_from_slice(&u64::from(rva + hint as u32).to_le_bytes());
    out[0..4].copy_from_slice(&(rva + thunks as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(rva + name as u32).to_le_bytes());
    out[16..20].copy_from_slice(&(rva + thunks as u32).to_le_bytes());
    out
}

/// A native-subsystem image importing the kernel: a driver.
fn driver_image() -> Vec<u8> {
    let builder = PeBuilder {
        subsystem: 1,
        ..PeBuilder::default()
    };
    // The import table goes in the second section, at RVA 0x2000.
    let rva = 0x2000;
    let mut image = builder
        .section(
            ".idata",
            import_section(rva, "ntoskrnl.exe", "IoCreateDevice"),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )
        .build();
    let dir = PeBuilder::default().data_directory_offset(1);
    image[dir..dir + 4].copy_from_slice(&rva.to_le_bytes());
    image[dir + 4..dir + 8].copy_from_slice(&40_u32.to_le_bytes());
    image
}

/// A manifest requesting administrator rights.
fn elevated_image() -> Vec<u8> {
    let xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:example:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:example:asm.v3"><security><requestedPrivileges>
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
</requestedPrivileges></security></trustInfo></assembly>"#;
    PeBuilder {
        resources: vec![Leaf {
            type_id: 24,
            name_id: 1,
            lang: 0x0409,
            data: xml.to_vec(),
        }],
        ..PeBuilder::default()
    }
    .build()
}

/// An image with a CLR runtime header directory entry (.NET).
fn dotnet_image() -> Vec<u8> {
    let mut image = PeBuilder::default().build();
    let dir = PeBuilder::default().data_directory_offset(14);
    image[dir..dir + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
    image[dir + 4..dir + 8].copy_from_slice(&72_u32.to_le_bytes());
    image
}

/// Every synthetic corpus file, by its `generator` name. The same bytes
/// are written for `generate.sh` to sign (`write_corpus_unsigned` in `tests/identity_corpus.rs`).
pub fn corpus_files() -> BTreeMap<&'static str, Vec<u8>> {
    let mut m = BTreeMap::new();
    m.insert("plain", PeBuilder::default().build());
    m.insert("dll", PeBuilder::dll().build());
    m.insert(
        "pe32",
        PeBuilder::pe32()
            .section(".data", vec![7; 3000], IMAGE_SCN_CNT_INITIALIZED_DATA)
            .build(),
    );
    m.insert("tool", version_image(&tool_strings(), (1, 2, 3, 4)).build());
    m.insert(
        "tool-v2",
        version_image(&tool_strings(), (2, 0, 0, 0)).build(),
    );
    m.insert(
        "powershell",
        version_image(&powershell_strings(), (10, 0, 0, 1)).build(),
    );
    m.insert("driver", driver_image());
    m.insert("elevated", elevated_image());
    m.insert("dotnet", dotnet_image());
    m.insert(
        "overlay",
        PeBuilder {
            overlay: b"overlay data".to_vec(),
            ..PeBuilder::default()
        }
        .build(),
    );
    // Not a PE image.
    m.insert("text", b"Palisade corpus: a plain text file.\n".to_vec());
    m.insert("empty", Vec::new());
    m.insert(
        "script",
        b"Write-Output 'Palisade corpus script'\r\n".to_vec(),
    );
    // A script whose language its shebang names.
    m.insert(
        "python",
        b"#!/usr/bin/env python3\nprint('Palisade corpus script')\n".to_vec(),
    );
    // The flat member of the catalog fixtures (`tests/catalog.rs`), which
    // `corpus.cat` lists by its flat SHA-256.
    m.insert(
        "flat-member",
        b"Palisade catalog test: a flat (non-PE) member file.\n".to_vec(),
    );
    // A PE whose headers are cut short: not a parseable image.
    let mut truncated = PeBuilder::default().build();
    truncated.truncate(0x90);
    m.insert("truncated", truncated);
    m
}

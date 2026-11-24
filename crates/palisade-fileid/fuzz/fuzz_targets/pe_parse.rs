//! Fuzzes the PE parser: no input may panic, hang or allocate without bound,
//! and every result must respect the documented limits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_fileid::pe::{self, ParseOptions, version::VersionField};

fuzz_target!(|data: &[u8]| {
    let len = data.len() as u64;
    for options in [ParseOptions::default(), ParseOptions::metadata_only()] {
        let Ok(info) = pe::parse_with(data, &options) else {
            continue;
        };
        assert!(info.parse_warnings.len() <= pe::MAX_WARNINGS);
        assert!(info.sections.len() <= pe::MAX_SECTIONS);
        assert!(info.data_directories.len() <= 16);
        for s in &info.sections {
            if let Some(e) = s.entropy {
                assert!((0.0..=8.0 + 1e-9).contains(&e));
            }
            let _ = info.rva_to_offset(s.virtual_address, 0);
        }
        if let Some(cert) = info.certificate_table {
            assert!(cert.size > 0 && cert.offset + cert.size <= len);
        }
        if let Some(overlay) = info.overlay {
            assert_eq!(overlay.offset + overlay.size, len);
        }
        if let Some(res) = &info.resources {
            assert!(res.entry_count <= pe::MAX_RESOURCE_ENTRIES);
            assert!(res.version_entries.len() <= pe::MAX_KEPT_RESOURCES);
            assert!(res.version_languages.len() <= pe::MAX_KEPT_RESOURCES);
            assert!(res.standard_manifests.len() <= 3);
            if let Some(v) = &res.version_resource {
                assert_eq!(v.name, pe::ResourceId::Id(1));
            }
        }
        if let Some(pdb) = &info.debug.codeview {
            assert!(pdb.path.len() <= pe::MAX_PDB_PATH * 3);
            let _ = pdb.guid_string();
        }
        let _ = info.timestamp_is_reproducible();
        let _ = info.checksum.is_valid();
        if let Some(v) = &info.version_info {
            if let Some(i) = v.selected {
                assert!(i < v.all_langs.len());
            }
            let _ = v.file_version_mismatch();
            let _ = v.product_version_mismatch();
            let _ = v.effective_file_name(VersionField::OriginalFileName);
        }
        if let Some(imports) = &info.imports {
            assert!(imports.modules.len() <= pe::MAX_IMPORT_MODULES);
            assert!(imports.function_count <= pe::MAX_IMPORTED_FUNCTIONS);
            assert!(imports.all_module_names.len() <= pe::MAX_IMPORT_DESCRIPTORS);
            let kept: usize = imports.all_module_names.iter().map(String::len).sum();
            assert!(kept <= pe::MAX_MODULE_NAME_BYTES);
            assert!(imports.kernel_modules.len() <= pe::KERNEL_MODULES.len());
            for m in &imports.modules {
                assert!(m.name.len() <= pe::MAX_NAME_LEN * 3);
            }
        }
        if let Some(exports) = &info.exports {
            assert!(exports.exports.len() <= pe::MAX_EXPORTS);
        }
        if let Some(m) = &info.manifest {
            assert!(m.supported_os.len() <= pe::manifest::MAX_SUPPORTED_OS);
        }
        // A non-native image is never a driver.
        if info.optional.subsystem != pe::Subsystem::Native {
            assert!(!info.is_kernel_driver());
        }
        let _ = info.requires_elevation(Some("setup.exe"));
    }
    // The manifest parser on its own, over raw input.
    let _ = pe::manifest::parse_manifest(data);
});

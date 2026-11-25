//! The Windows resources every shipped executable carries: a version
//! resource (`VERSIONINFO`) and an application manifest.
//!
//! They are written straight to a compiled resource file (`.res`), which the
//! MSVC linker takes as an input, so no resource compiler and no build
//! script is needed. The formats are the documented `RESOURCEHEADER` and
//! `VS_VERSIONINFO` layouts. The unit tests read the output back with an
//! independent reader, and CI reads the stamped binaries back through the
//! operating system's own version API (`cargo xtask dist` on Windows).

use super::os_ids;
use super::version::Version;

/// `RT_VERSION`.
const RT_VERSION: u16 = 16;
/// `RT_MANIFEST`.
const RT_MANIFEST: u16 = 24;
/// `CREATEPROCESS_MANIFEST_RESOURCE_ID`: the manifest the loader reads when
/// it starts an executable.
const MANIFEST_ID: u16 = 1;
/// The version resource's ID, `VS_VERSION_INFO`.
const VERSION_ID: u16 = 1;
/// U.S. English, the language of every string here.
const LANG_EN_US: u16 = 0x0409;
/// The UTF-16 code page, paired with the language in the string table key
/// and the translation table.
const CODE_PAGE_UNICODE: u16 = 0x04b0;
/// `MOVEABLE | PURE`, what the resource compiler writes.
const MEMORY_FLAGS: u16 = 0x0030;

/// `supportedOS` for Windows 10 and Windows 11, the only versions Palisade
/// supports.
pub const SUPPORTED_OS_WINDOWS_10: &str = "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}";

/// `VS_FF_PRERELEASE`.
const VS_FF_PRERELEASE: u32 = 0x2;
/// `VS_FFI_FILEFLAGSMASK`.
const VS_FFI_FILEFLAGSMASK: u32 = 0x3f;
/// `VOS_NT_WINDOWS32`.
const VOS_NT_WINDOWS32: u32 = 0x0004_0004;
/// `VFT_APP`.
const VFT_APP: u32 = 0x1;

/// The fixed strings of the version resource.
pub const COMPANY_NAME: &str = "Palisade Project";
/// `ProductName`.
pub const PRODUCT_NAME: &str = "Palisade";
/// `LegalCopyright`.
pub const LEGAL_COPYRIGHT: &str =
    "Copyright Palisade contributors. Licensed under Apache-2.0 OR MIT.";

/// What one executable's resources say about it.
#[derive(Debug, Clone)]
pub struct Stamp<'a> {
    /// The file name, such as `pal.exe`.
    pub file_name: &'a str,
    /// `FileDescription`.
    pub description: &'a str,
    /// The workspace version.
    pub version: &'a Version,
    /// The `ProductVersion` string, with the commit.
    pub product_version: &'a str,
}

/// The compiled resource file for one executable: the version resource and
/// the application manifest.
pub fn res_file(stamp: &Stamp<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    // A `.res` file starts with an empty entry that marks the format.
    entry(&mut out, 0, 0, 0, &[]);
    entry(
        &mut out,
        RT_VERSION,
        VERSION_ID,
        LANG_EN_US,
        &version_info(stamp),
    );
    entry(
        &mut out,
        RT_MANIFEST,
        MANIFEST_ID,
        LANG_EN_US,
        manifest().as_bytes(),
    );
    out
}

/// One `RESOURCEHEADER` with numeric type and name, then the data, padded
/// to a 4-byte boundary.
fn entry(out: &mut Vec<u8>, kind: u16, id: u16, language: u16, data: &[u8]) {
    let flags = if kind == 0 { 0 } else { MEMORY_FLAGS };
    let header_size: u32 = 32;
    out.extend_from_slice(&len32(data.len()).to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    for word in [0xffff, kind, 0xffff, id] {
        out.extend_from_slice(&u16::to_le_bytes(word));
    }
    out.extend_from_slice(&0_u32.to_le_bytes()); // DataVersion
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&language.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes()); // Version
    out.extend_from_slice(&0_u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(data);
    pad4(out);
}

/// The application manifest: run as the invoking user, long path aware,
/// written for Windows 10 and 11. The service, the tray and the CLI all run
/// as invoked; the service gets its rights from its service account.
pub fn manifest() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="{asm_v1}" manifestVersion="1.0">
  <trustInfo xmlns="{asm_v3}">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="{compat}">
    <application>
      <supportedOS Id="{SUPPORTED_OS_WINDOWS_10}"/>
    </application>
  </compatibility>
  <application xmlns="{asm_v3}">
    <windowsSettings>
      <longPathAware xmlns="{settings}">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#,
        asm_v1 = os_ids::ASM_V1,
        asm_v3 = os_ids::ASM_V3,
        compat = os_ids::COMPATIBILITY_V1,
        settings = os_ids::WINDOWS_SETTINGS_2016,
    )
}

/// A value in the version resource tree.
enum Value<'a> {
    None,
    Binary(&'a [u8]),
    Text(&'a str),
}

/// One version resource block: `wLength`, `wValueLength`, `wType`, the key,
/// the value and the children, each 4-byte aligned. `wLength` covers the
/// block up to the end of its last child, without trailing padding.
fn block(key: &str, value: Value<'_>, children: &[Vec<u8>]) -> Vec<u8> {
    let (kind, value_len, bytes): (u16, usize, Vec<u8>) = match value {
        Value::None => (1, 0, Vec::new()),
        Value::Binary(bytes) => (0, bytes.len(), bytes.to_vec()),
        Value::Text(text) => {
            let units = utf16z(text);
            // For text, the length is in UTF-16 code units, with the NUL.
            (1, units.len() / 2, units)
        }
    };
    let mut out = vec![0, 0];
    out.extend_from_slice(&len16(value_len).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&utf16z(key));
    if !bytes.is_empty() {
        pad4(&mut out);
        out.extend_from_slice(&bytes);
    }
    for child in children {
        pad4(&mut out);
        out.extend_from_slice(child);
    }
    let len = len16(out.len()).to_le_bytes();
    out[..2].copy_from_slice(&len);
    out
}

/// The `VS_VERSIONINFO` resource.
pub fn version_info(stamp: &Stamp<'_>) -> Vec<u8> {
    let [a, b, c, d] = stamp.version.quad();
    let ms = (u32::from(a) << 16) | u32::from(b);
    let ls = (u32::from(c) << 16) | u32::from(d);
    let flags = if stamp.version.pre.is_some() {
        VS_FF_PRERELEASE
    } else {
        0
    };
    let mut fixed = Vec::with_capacity(52);
    for word in [
        0xfeef_04bd, // dwSignature
        0x0001_0000, // dwStrucVersion
        ms,
        ls, // file version
        ms,
        ls, // product version
        VS_FFI_FILEFLAGSMASK,
        flags,
        VOS_NT_WINDOWS32,
        VFT_APP,
        0, // dwFileSubtype
        0,
        0, // dwFileDate
    ] {
        fixed.extend_from_slice(&u32::to_le_bytes(word));
    }

    let file_version = stamp.version.file_string();
    let internal_name = stamp
        .file_name
        .strip_suffix(".exe")
        .unwrap_or(stamp.file_name);
    let strings: Vec<Vec<u8>> = [
        ("CompanyName", COMPANY_NAME),
        ("FileDescription", stamp.description),
        ("FileVersion", file_version.as_str()),
        ("InternalName", internal_name),
        ("LegalCopyright", LEGAL_COPYRIGHT),
        ("OriginalFilename", stamp.file_name),
        ("ProductName", PRODUCT_NAME),
        ("ProductVersion", stamp.product_version),
    ]
    .iter()
    .map(|(key, value)| block(key, Value::Text(value), &[]))
    .collect();
    let table_key = format!("{LANG_EN_US:04X}{CODE_PAGE_UNICODE:04X}");
    let table = block(&table_key, Value::None, &strings);
    let string_file_info = block("StringFileInfo", Value::None, &[table]);

    let mut translation = Vec::new();
    translation.extend_from_slice(&LANG_EN_US.to_le_bytes());
    translation.extend_from_slice(&CODE_PAGE_UNICODE.to_le_bytes());
    let var = block("Translation", Value::Binary(&translation), &[]);
    let var_file_info = block("VarFileInfo", Value::None, &[var]);

    block(
        "VS_VERSION_INFO",
        Value::Binary(&fixed),
        &[string_file_info, var_file_info],
    )
}

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn pad4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Resource blocks are a few hundred bytes, far below `u16::MAX`.
fn len16(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

fn len32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp_for(version: &Version) -> Stamp<'_> {
        Stamp {
            file_name: "palisade-agent.exe",
            description: "Palisade endpoint agent",
            version,
            product_version: "0.3.1-rc.2+g1a2b3c4d5e6f",
        }
    }

    /// One parsed version block: key, value bytes, children.
    struct Block {
        key: String,
        kind: u16,
        value: Vec<u8>,
        children: Vec<Block>,
    }

    fn word(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }

    /// Reads a block the way the OS version API does, independently of the
    /// writer: lengths, key, 4-byte alignment and children.
    fn read_block(b: &[u8]) -> Block {
        let len = usize::from(word(b, 0));
        let value_len = usize::from(word(b, 2));
        let kind = word(b, 4);
        assert!(len <= b.len(), "wLength {len} past the buffer {}", b.len());
        let mut at = 6;
        let mut key = Vec::new();
        loop {
            let unit = word(b, at);
            at += 2;
            if unit == 0 {
                break;
            }
            key.push(unit);
        }
        let align = |n: usize| n.next_multiple_of(4);
        at = align(at);
        let value_bytes = if kind == 1 { value_len * 2 } else { value_len };
        let value = b[at..at + value_bytes].to_vec();
        at = align(at + value_bytes);
        let mut children = Vec::new();
        while at < len {
            let child_len = usize::from(word(b, at));
            assert!(child_len > 0);
            children.push(read_block(&b[at..at + child_len]));
            at = align(at + child_len);
        }
        Block {
            key: String::from_utf16(&key).unwrap(),
            kind,
            value,
            children,
        }
    }

    fn text(value: &[u8]) -> String {
        let units: Vec<u16> = value
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(units.last(), Some(&0), "text values end with NUL");
        String::from_utf16(&units[..units.len() - 1]).unwrap()
    }

    fn dword(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn version_info_has_the_documented_layout() {
        let version = Version::parse("0.3.1-rc.2").unwrap();
        let bytes = version_info(&stamp_for(&version));
        let root = read_block(&bytes);
        assert_eq!(usize::from(word(&bytes, 0)), bytes.len());
        assert_eq!(root.key, "VS_VERSION_INFO");
        assert_eq!((root.kind, root.value.len()), (0, 52));
        let fixed = &root.value;
        assert_eq!(dword(fixed, 0), 0xfeef_04bd);
        // File and product version 0.3.1.0.
        for at in [8, 16] {
            assert_eq!((dword(fixed, at), dword(fixed, at + 4)), (3, 1 << 16));
        }
        assert_eq!(dword(fixed, 28), VS_FF_PRERELEASE);
        assert_eq!(dword(fixed, 36), VFT_APP);

        let [strings, vars] = root.children.as_slice() else {
            panic!("expected StringFileInfo and VarFileInfo");
        };
        assert_eq!(strings.key, "StringFileInfo");
        let [table] = strings.children.as_slice() else {
            panic!("one string table");
        };
        assert_eq!(table.key, "040904B0");
        let found: Vec<(String, String)> = table
            .children
            .iter()
            .map(|s| {
                assert_eq!(s.kind, 1);
                (s.key.clone(), text(&s.value))
            })
            .collect();
        let want = [
            ("CompanyName", "Palisade Project"),
            ("FileDescription", "Palisade endpoint agent"),
            ("FileVersion", "0.3.1.0"),
            ("InternalName", "palisade-agent"),
            ("LegalCopyright", LEGAL_COPYRIGHT),
            ("OriginalFilename", "palisade-agent.exe"),
            ("ProductName", "Palisade"),
            ("ProductVersion", "0.3.1-rc.2+g1a2b3c4d5e6f"),
        ];
        let want: Vec<(String, String)> = want
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        assert_eq!(found, want);

        assert_eq!(vars.key, "VarFileInfo");
        assert_eq!(vars.children.len(), 1);
        assert_eq!(vars.children[0].key, "Translation");
        assert_eq!(vars.children[0].value, [0x09, 0x04, 0xb0, 0x04]);
    }

    #[test]
    fn a_release_version_is_not_marked_pre_release() {
        let version = Version::parse("1.2.3").unwrap();
        let root = read_block(&version_info(&stamp_for(&version)));
        assert_eq!(dword(&root.value, 28), 0);
        assert_eq!(dword(&root.value, 8), (1 << 16) | 2);
    }

    #[test]
    fn manifest_requests_as_invoker_long_paths_and_windows_10() {
        let m = manifest();
        assert!(m.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\""));
        assert!(m.contains(r#"<requestedExecutionLevel level="asInvoker" uiAccess="false"/>"#));
        assert!(m.contains(&format!(r#"<supportedOS Id="{SUPPORTED_OS_WINDOWS_10}"/>"#)));
        assert!(m.contains(">true</longPathAware>"));
        for ns in [
            os_ids::ASM_V1,
            os_ids::ASM_V3,
            os_ids::COMPATIBILITY_V1,
            os_ids::WINDOWS_SETTINGS_2016,
        ] {
            assert!(m.contains(&format!("xmlns=\"{ns}\"")), "{ns}");
        }
        // Balanced elements: every opening tag is closed.
        let opens = m.matches('<').count() - m.matches("</").count() - m.matches("<?").count();
        let closes = m.matches("</").count() + m.matches("/>").count();
        assert_eq!(opens, closes);
    }

    /// Walks the `.res` entries: `(type, name, language, data)`.
    fn entries(mut res: &[u8]) -> Vec<(u16, u16, u16, Vec<u8>)> {
        let mut out = Vec::new();
        while !res.is_empty() {
            let data_size = dword(res, 0) as usize;
            let header_size = dword(res, 4) as usize;
            assert_eq!(header_size, 32);
            assert_eq!((word(res, 8), word(res, 12)), (0xffff, 0xffff));
            let data = res[header_size..header_size + data_size].to_vec();
            out.push((word(res, 10), word(res, 14), word(res, 22), data));
            let next = (header_size + data_size).next_multiple_of(4);
            res = &res[next..];
        }
        out
    }

    #[test]
    fn res_file_holds_the_version_and_the_manifest() {
        let version = Version::parse("0.1.0").unwrap();
        let stamp = stamp_for(&version);
        let res = res_file(&stamp);
        assert_eq!(res.len() % 4, 0);
        let found = entries(&res);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0], (0, 0, 0, Vec::new()));
        assert_eq!(found[1], (RT_VERSION, 1, LANG_EN_US, version_info(&stamp)));
        assert_eq!(
            found[2],
            (RT_MANIFEST, 1, LANG_EN_US, manifest().into_bytes())
        );
    }
}

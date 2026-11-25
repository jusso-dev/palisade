//! Just enough PE reading to check the binaries `dist` builds: the machine
//! type, the debug directory (the PDB's CodeView record and the
//! reproducible-build marker), the imported DLLs and one resource's bytes.
//!
//! xtask may not link the workspace crates (`cargo xtask check-deps`), so
//! this does not use `palisade-fileid`. It only reads files this repository
//! just built, and it fails on anything it does not expect instead of
//! working around it.

/// `IMAGE_FILE_MACHINE_AMD64`.
pub const MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const MACHINE_ARM64: u16 = 0xaa64;

const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_DEBUG: usize = 6;
const DEBUG_TYPE_CODEVIEW: u32 = 2;
const DEBUG_TYPE_REPRO: u32 = 16;

/// The PDB a binary was linked with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeView {
    pub guid: [u8; 16],
    pub age: u32,
    /// The PDB path as recorded (with `/PDBALTPATH:%_PDB%`, the file name).
    pub path: String,
}

impl CodeView {
    /// The symbol-server directory key: the GUID as 32 uppercase hex
    /// digits (its first three fields read little-endian), then the age in
    /// uppercase hex without padding.
    pub fn symbol_key(&self) -> String {
        let g = &self.guid;
        let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
        let d2 = u16::from_le_bytes([g[4], g[5]]);
        let d3 = u16::from_le_bytes([g[6], g[7]]);
        let mut key = format!("{d1:08X}{d2:04X}{d3:04X}");
        for b in &g[8..] {
            key.push_str(&format!("{b:02X}"));
        }
        key.push_str(&format!("{:X}", self.age));
        key
    }

    /// The PDB file name, without any directory.
    pub fn file_name(&self) -> &str {
        self.path.rsplit(['\\', '/']).next().unwrap_or(&self.path)
    }
}

/// What [`parse`] reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub machine: u16,
    pub codeview: Option<CodeView>,
    /// The debug directory has a `REPRO` entry: the linker ran with
    /// `/Brepro`, so the COFF timestamp is a hash of the output.
    pub reproducible: bool,
    /// Imported DLL names, lowercase, in table order.
    pub imports: Vec<String>,
    sections: Vec<Section>,
    resource_dir: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn err(what: &str) -> String {
    format!("not a PE image this build produced: {what}")
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at.checked_add(2).ok_or_else(|| err("offset overflow"))?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| err("truncated"))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at.checked_add(4).ok_or_else(|| err("offset overflow"))?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| err("truncated"))
}

fn usize_of(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Parses the headers and the import and debug directories of a PE32+
/// image.
pub fn parse(data: &[u8]) -> Result<Image, String> {
    if data.get(..2) != Some(b"MZ") {
        return Err(err("no MZ header"));
    }
    let pe = usize_of(u32_at(data, 0x3c)?);
    if data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err(err("no PE signature"));
    }
    let coff = pe + 4;
    let machine = u16_at(data, coff)?;
    let section_count = usize::from(u16_at(data, coff + 2)?);
    let optional_size = usize::from(u16_at(data, coff + 16)?);
    let optional = coff + 20;
    if u16_at(data, optional)? != 0x20b {
        return Err(err("not PE32+"));
    }
    let dir_count = usize_of(u32_at(data, optional + 108)?);
    let directory = |index: usize| -> Result<Option<(u32, u32)>, String> {
        if index >= dir_count {
            return Ok(None);
        }
        let at = optional + 112 + index * 8;
        let (rva, size) = (u32_at(data, at)?, u32_at(data, at + 4)?);
        Ok((rva != 0 && size != 0).then_some((rva, size)))
    };
    let mut sections = Vec::with_capacity(section_count);
    let table = optional + optional_size;
    for i in 0..section_count {
        let at = table + i * 40;
        sections.push(Section {
            virtual_size: u32_at(data, at + 8)?,
            virtual_address: u32_at(data, at + 12)?,
            raw_size: u32_at(data, at + 16)?,
            raw_offset: u32_at(data, at + 20)?,
        });
    }
    let mut image = Image {
        machine,
        codeview: None,
        reproducible: false,
        imports: Vec::new(),
        sections,
        resource_dir: directory(DIR_RESOURCE)?,
    };
    if let Some((rva, size)) = directory(DIR_DEBUG)? {
        let start = image.offset(rva)?;
        for i in 0..usize_of(size) / 28 {
            let entry = start + i * 28;
            let kind = u32_at(data, entry + 12)?;
            let len = usize_of(u32_at(data, entry + 16)?);
            let raw = usize_of(u32_at(data, entry + 24)?);
            match kind {
                DEBUG_TYPE_REPRO => image.reproducible = true,
                DEBUG_TYPE_CODEVIEW => image.codeview = Some(codeview(data, raw, len)?),
                _ => {}
            }
        }
    }
    if let Some((rva, _)) = directory(DIR_IMPORT)? {
        let mut at = image.offset(rva)?;
        loop {
            let name_rva = u32_at(data, at + 12)?;
            if u32_at(data, at)? == 0 && name_rva == 0 {
                break;
            }
            image
                .imports
                .push(c_string(data, image.offset(name_rva)?)?.to_ascii_lowercase());
            at += 20;
            if image.imports.len() > 4096 {
                return Err(err("import table does not end"));
            }
        }
    }
    Ok(image)
}

fn codeview(data: &[u8], at: usize, len: usize) -> Result<CodeView, String> {
    let record = data
        .get(at..at.saturating_add(len))
        .ok_or_else(|| err("CodeView record outside the file"))?;
    if record.len() < 24 || &record[..4] != b"RSDS" {
        return Err(err("CodeView record is not RSDS"));
    }
    let mut guid = [0; 16];
    guid.copy_from_slice(&record[4..20]);
    Ok(CodeView {
        guid,
        age: u32_at(record, 20)?,
        path: c_string(record, 24)?,
    })
}

fn c_string(data: &[u8], at: usize) -> Result<String, String> {
    let rest = data
        .get(at..)
        .ok_or_else(|| err("string outside the file"))?;
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| err("unterminated string"))?;
    String::from_utf8(rest[..end].to_vec()).map_err(|_| err("string is not UTF-8"))
}

impl Image {
    /// The file offset of an RVA.
    /// Only RVAs backed by the section's file data map; one in its
    /// zero-filled tail does not.
    fn offset(&self, rva: u32) -> Result<usize, String> {
        self.sections
            .iter()
            .find(|s| {
                // Linkers may leave VirtualSize zero; the raw size bounds it then.
                let mapped = if s.virtual_size == 0 {
                    s.raw_size
                } else {
                    s.virtual_size.min(s.raw_size)
                };
                rva >= s.virtual_address && rva - s.virtual_address < mapped
            })
            .and_then(|s| usize_of(s.raw_offset).checked_add(usize_of(rva - s.virtual_address)))
            .ok_or_else(|| err("RVA outside every section"))
    }

    /// The data of the resource with numeric `kind` and `id`, in its first
    /// language.
    pub fn resource<'a>(
        &self,
        data: &'a [u8],
        kind: u16,
        id: u16,
    ) -> Result<Option<&'a [u8]>, String> {
        let Some((rva, _)) = self.resource_dir else {
            return Ok(None);
        };
        let root = self.offset(rva)?;
        let find = |dir: usize, want: Option<u16>| -> Result<Option<u32>, String> {
            let named = usize::from(u16_at(data, dir + 12)?);
            let ids = usize::from(u16_at(data, dir + 14)?);
            for i in named..named + ids {
                let entry = dir + 16 + i * 8;
                let name = u32_at(data, entry)?;
                if want.is_none_or(|w| name == u32::from(w)) {
                    return Ok(Some(u32_at(data, entry + 4)?));
                }
            }
            Ok(None)
        };
        let subdir = |link: u32| -> Result<usize, String> {
            if link & 0x8000_0000 == 0 {
                return Err(err("resource level is not a directory"));
            }
            root.checked_add(usize_of(link & 0x7fff_ffff))
                .ok_or_else(|| err("resource directory out of range"))
        };
        let Some(by_kind) = find(root, Some(kind))? else {
            return Ok(None);
        };
        let Some(by_id) = find(subdir(by_kind)?, Some(id))? else {
            return Ok(None);
        };
        let Some(leaf) = find(subdir(by_id)?, None)? else {
            return Ok(None);
        };
        if leaf & 0x8000_0000 != 0 {
            return Err(err("resource language level is a directory"));
        }
        let entry = root
            .checked_add(usize_of(leaf))
            .ok_or_else(|| err("resource entry out of range"))?;
        let start = self.offset(u32_at(data, entry)?)?;
        let len = usize_of(u32_at(data, entry + 4)?);
        data.get(start..start.saturating_add(len))
            .map(Some)
            .ok_or_else(|| err("resource data outside the file"))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A minimal PE32+ image with one section holding an import table, a
    /// debug directory (CodeView and REPRO) and a resource tree with one
    /// resource, for tests here and in the other `dist` modules.
    pub fn sample(machine: u16, resource: (u16, u16, &[u8])) -> Vec<u8> {
        let section_rva = 0x1000_u32;
        let section_raw = 0x200_usize;
        let mut sec = vec![0_u8; 0x1000];
        let rva = |off: usize| section_rva + u32::try_from(off).unwrap();
        let put32 =
            |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let put16 =
            |b: &mut Vec<u8>, at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        // Imports at 0x000: two descriptors and the terminator; names at 0x80.
        sec[0x80..0x8d].copy_from_slice(b"KERNEL32.dll\0");
        sec[0x90..0x9b].copy_from_slice(b"ntdll.dll\0\0");
        put32(&mut sec, 12, rva(0x80));
        put32(&mut sec, 20 + 12, rva(0x90));
        // Debug directory at 0x100: CodeView, then REPRO. RSDS at 0x140.
        put32(&mut sec, 0x100 + 12, DEBUG_TYPE_CODEVIEW);
        put32(&mut sec, 0x100 + 16, 24 + 9);
        put32(
            &mut sec,
            0x100 + 24,
            u32::try_from(section_raw + 0x140).unwrap(),
        );
        put32(&mut sec, 0x100 + 28 + 12, DEBUG_TYPE_REPRO);
        sec[0x140..0x144].copy_from_slice(b"RSDS");
        for (i, b) in (0x140 + 4..0x140 + 20).enumerate() {
            sec[b] = u8::try_from(i).unwrap() + 1;
        }
        put32(&mut sec, 0x140 + 20, 3);
        sec[0x140 + 24..0x140 + 33].copy_from_slice(b"a_b.pdb\0\0");
        // Resources at 0x200: root -> kind -> id -> language -> data entry.
        let (kind, id, payload) = resource;
        let root = 0x200;
        for (dir, name, link) in [
            (root, u32::from(kind), 0x8000_0000 | 0x18),
            (root + 0x18, u32::from(id), 0x8000_0000 | 0x30),
            (root + 0x30, 0x409, 0x48),
        ] {
            put16(&mut sec, dir + 14, 1);
            put32(&mut sec, dir + 16, name);
            put32(&mut sec, dir + 20, link);
        }
        put32(&mut sec, root + 0x48, rva(0x300));
        put32(&mut sec, root + 0x4c, u32::try_from(payload.len()).unwrap());
        sec[0x300..0x300 + payload.len()].copy_from_slice(payload);

        let mut image = vec![0_u8; section_raw];
        image[..2].copy_from_slice(b"MZ");
        put32(&mut image, 0x3c, 0x40);
        image[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        put16(&mut image, coff, machine);
        put16(&mut image, coff + 2, 1);
        put16(&mut image, coff + 16, 240);
        let opt = coff + 20;
        put16(&mut image, opt, 0x20b);
        put32(&mut image, opt + 108, 16);
        for (index, off, size) in [
            (DIR_IMPORT, 0, 60),
            (DIR_DEBUG, 0x100, 56),
            (DIR_RESOURCE, 0x200, 0x50),
        ] {
            put32(&mut image, opt + 112 + index * 8, rva(off));
            put32(&mut image, opt + 112 + index * 8 + 4, size);
        }
        let s = opt + 240;
        image[s..s + 5].copy_from_slice(b".data");
        put32(&mut image, s + 8, 0x1000);
        put32(&mut image, s + 12, section_rva);
        put32(&mut image, s + 16, 0x1000);
        put32(&mut image, s + 20, u32::try_from(section_raw).unwrap());
        image.extend_from_slice(&sec);
        image
    }

    #[test]
    fn reads_the_sample_image() {
        let data = sample(MACHINE_ARM64, (16, 1, b"version bytes"));
        let image = parse(&data).unwrap();
        assert_eq!(image.machine, MACHINE_ARM64);
        assert!(image.reproducible);
        assert_eq!(image.imports, ["kernel32.dll", "ntdll.dll"]);
        let cv = image.codeview.clone().unwrap();
        assert_eq!(cv.file_name(), "a_b.pdb");
        assert_eq!(cv.age, 3);
        assert_eq!(cv.symbol_key(), "0403020106050807090A0B0C0D0E0F103");
        assert_eq!(
            image.resource(&data, 16, 1).unwrap(),
            Some(&b"version bytes"[..])
        );
        assert_eq!(image.resource(&data, 24, 1).unwrap(), None);
        assert_eq!(image.resource(&data, 16, 2).unwrap(), None);
    }

    #[test]
    fn rejects_other_files() {
        assert!(parse(b"").is_err());
        assert!(parse(b"MZ").is_err());
        let mut data = sample(MACHINE_AMD64, (16, 1, b"x"));
        data[0x40] = b'X';
        assert!(parse(&data).is_err());
    }

    #[test]
    fn symbol_keys_match_the_documented_layout() {
        // The registry form {01234567-89AB-CDEF-0123-456789ABCDEF} with age
        // 0x2A gives 0123456789ABCDEF0123456789ABCDEF2A.
        let cv = CodeView {
            guid: [
                0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ],
            age: 0x2a,
            path: r"C:\b\palisade_agent.pdb".into(),
        };
        assert_eq!(cv.symbol_key(), "0123456789ABCDEF0123456789ABCDEF2A");
        assert_eq!(cv.file_name(), "palisade_agent.pdb");
    }
}

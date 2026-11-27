//! A builder for small synthetic app packages and bundles, used only by
//! tests and fuzz seeds.
//!
//! [`AppxBuilder`] writes a ZIP archive in the shape packaging tools use:
//! files stored or deflated, each with a local header, then
//! `AppxBlockMap.xml` (with real SHA-256 block hashes of every file),
//! `[Content_Types].xml`, the central directory and the end record.
//! Deflate here is a plain fixed-Huffman encoder of literals only, which is
//! valid DEFLATE every reader accepts, laid out as the OS packaging tool
//! lays it out ([`deflate_blocks`]). A bundle puts its payload packages
//! first, as that tool does, so their offsets do not depend on the bundle
//! manifest that records them. Everything is deterministic.

#![allow(dead_code, clippy::cast_possible_truncation, clippy::unwrap_used)]

use sha2::{Digest as _, Sha256};

/// CRC-32 (IEEE).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Raw DEFLATE in the shape the OS packaging tool writes: each 64 KiB
/// block of the input compressed on its own and ended with a full flush
/// (here a fixed-Huffman block of literals, then the empty stored block
/// `00 00 ff ff` that byte-aligns it), and the stream closed by an empty
/// final fixed-Huffman block, the two bytes `03 00`. The tool flushes every
/// block because it cannot tell which block is the last, so that final
/// block is not counted in any block's size. Returns the stream and the
/// compressed size of each block (the block map's `Size`).
pub fn deflate_blocks(data: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::new();
    let mut sizes = Vec::new();
    for block in data.chunks(65536) {
        let start = out.len();
        let mut bits = Bits::default();
        bits.put(0, 1); // not final
        bits.put(1, 2); // fixed Huffman
        for &c in block {
            bits.literal(c);
        }
        bits.code(0, 7); // end of block (256)
        // Full flush: an empty, non-final stored block, byte-aligned.
        bits.put(0, 1);
        bits.put(0, 2);
        out.extend_from_slice(&bits.finish());
        out.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        sizes.push(out.len() - start);
    }
    // The empty final block.
    out.extend_from_slice(&[0x03, 0x00]);
    (out, sizes)
}

#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl Bits {
    fn put(&mut self, v: u32, len: u32) {
        for i in 0..len {
            self.acc |= ((v >> i) & 1) << self.n;
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    /// Huffman codes are sent most significant bit first.
    fn code(&mut self, v: u32, len: u32) {
        let mut r = 0;
        for i in 0..len {
            r |= ((v >> i) & 1) << (len - 1 - i);
        }
        self.put(r, len);
    }
    fn literal(&mut self, c: u8) {
        let c = u32::from(c);
        if c < 144 {
            self.code(0x30 + c, 8);
        } else {
            self.code(0x190 + (c - 144), 9);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// A real 1x1 PNG image, for the logos the manifest schema requires.
pub const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x60, 0x00, 0x02, 0x00,
    0x00, 0x05, 0x00, 0x01, 0xe9, 0xfa, 0xdc, 0xd8, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
    0xae, 0x42, 0x60, 0x82,
];

/// One file in the package.
#[derive(Clone, Debug)]
pub struct File {
    pub name: String,
    pub data: Vec<u8>,
    pub deflate: bool,
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((v >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub const PUBLISHER: &str = "CN=Palisade Test Package Signer, O=Palisade Tests";

/// A synthetic package.
#[derive(Clone, Debug)]
pub struct AppxBuilder {
    /// Payload files (the manifest is one of them).
    pub files: Vec<File>,
    /// Extra raw bytes in the block map's `<BlockMap>` element.
    pub blockmap_extra: String,
    /// Skip a file in the block map.
    pub blockmap_skip: Option<String>,
}

pub fn manifest(name: &str, publisher: &str, version: &str, arch: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
         xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap uap3 desktop rescap">
  <Identity Name="{name}" Publisher="{publisher}" Version="{version}" ProcessorArchitecture="{arch}"/>
  <Properties>
    <DisplayName>Palisade Test App</DisplayName>
    <PublisherDisplayName>Palisade Tests</PublisherDisplayName>
    <Logo>logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
    <PackageDependency Name="Palisade.Framework" Publisher="{publisher}" MinVersion="1.0.0.0"/>
  </Dependencies>
  <Resources><Resource Language="en-us"/></Resources>
  <Applications>
    <Application Id="App" Executable="app/tool.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Palisade Test App" Description="Palisade test app"
          BackgroundColor="transparent" Square150x150Logo="logo.png" Square44x44Logo="logo.png"/>
      <Extensions>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="app/tool.exe">
          <uap3:AppExecutionAlias>
            <desktop:ExecutionAlias Alias="palisade-tool.exe"/>
          </uap3:AppExecutionAlias>
        </uap3:Extension>
        <desktop:Extension Category="windows.fullTrustProcess" Executable="app/helper.exe"/>
      </Extensions>
    </Application>
  </Applications>
  <Capabilities>
    <Capability Name="internetClient"/>
    <rescap:Capability Name="runFullTrust"/>
    <DeviceCapability Name="webcam"/>
  </Capabilities>
</Package>
"#
    )
}

/// A minimal desktop app manifest for the OS SDK's packaging tool, which
/// validates manifests against its schema: one full-trust application with
/// its visual elements and logos (`logo.png`), and no extensions.
pub fn sdk_manifest(name: &str, publisher: &str, version: &str, arch: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap rescap">
  <Identity Name="{name}" Publisher="{publisher}" Version="{version}" ProcessorArchitecture="{arch}"/>
  <Properties>
    <DisplayName>Palisade SDK Probe</DisplayName>
    <PublisherDisplayName>Palisade Tests</PublisherDisplayName>
    <Logo>logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
  <Resources><Resource Language="en-us"/></Resources>
  <Applications>
    <Application Id="App" Executable="tool.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Palisade SDK Probe" Description="Palisade SDK probe"
          BackgroundColor="transparent" Square150x150Logo="logo.png" Square44x44Logo="logo.png"/>
    </Application>
  </Applications>
  <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>
"#
    )
}

/// The bundle manifest's part name.
pub const BUNDLE_MANIFEST: &str = "AppxMetadata/AppxBundleManifest.xml";

/// The manifest of a resource package for `language`.
pub fn resource_manifest(name: &str, publisher: &str, version: &str, language: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="{name}" Publisher="{publisher}" Version="{version}" ResourceId="{language}"/>
  <Properties>
    <ResourcePackage>true</ResourcePackage>
    <DisplayName>Palisade Test App</DisplayName>
    <PublisherDisplayName>Palisade Tests</PublisherDisplayName>
    <Logo>logo.png</Logo>
  </Properties>
  <Resources><Resource Language="{language}"/></Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
</Package>
"#
    )
}

impl AppxBuilder {
    /// A package with a manifest, an executable, a big deflated file (more
    /// than one block) and a small stored one.
    pub fn package() -> Self {
        Self {
            files: vec![
                File {
                    name: "AppxManifest.xml".into(),
                    data: manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "x64").into_bytes(),
                    deflate: true,
                },
                File {
                    name: "app/tool.exe".into(),
                    data: b"MZ synthetic tool, not a real PE".to_vec(),
                    deflate: false,
                },
                File {
                    name: "assets/big.bin".into(),
                    data: (0..150_000_u32).map(|i| (i * 7 % 251) as u8).collect(),
                    deflate: true,
                },
                File {
                    name: "logo.png".into(),
                    data: PNG.to_vec(),
                    deflate: false,
                },
            ],
            blockmap_extra: String::new(),
            blockmap_skip: None,
        }
    }

    /// A small package (manifest, executable, logo) with the given
    /// identity: a bundle's application payload.
    pub fn small_package(name: &str, version: &str, arch: &str) -> Self {
        let mut b = Self::package();
        b.files[0].data = manifest(name, PUBLISHER, version, arch).into_bytes();
        b.files.retain(|f| f.name != "assets/big.bin");
        b
    }

    /// A resource package for `language`: a bundle's resource payload.
    pub fn resource_package(name: &str, version: &str, language: &str) -> Self {
        Self {
            files: vec![
                File {
                    name: "AppxManifest.xml".into(),
                    data: resource_manifest(name, PUBLISHER, version, language).into_bytes(),
                    deflate: true,
                },
                File {
                    name: "logo.png".into(),
                    data: PNG.to_vec(),
                    deflate: false,
                },
            ],
            blockmap_extra: String::new(),
            blockmap_skip: None,
        }
    }

    /// A bundle of two payload packages (an x64 application package and an
    /// `en-us` resource package, both real packages with the bundle's
    /// identity) and a bundle manifest that lists them with the offset and
    /// size of their data, as the OS packaging tool lays a bundle out:
    /// payloads first and stored, then the manifest. The offsets are those
    /// of [`Self::build`] (no data descriptors).
    pub fn bundle() -> Self {
        let payloads = [
            File {
                name: "app_x64.msix".into(),
                data: Self::small_package("Palisade.TestBundle", "2.0.0.0", "x64").build(),
                deflate: false,
            },
            File {
                name: "app_en-us.msix".into(),
                data: Self::resource_package("Palisade.TestBundle", "2.0.0.0", "en-us").build(),
                deflate: false,
            },
        ];
        let mut at = 0;
        let mut place = Vec::new();
        for p in &payloads {
            let data = at + Self::local_header_len(&p.name);
            place.push((data, p.data.len()));
            at = data + p.data.len();
        }
        let ((x64_at, x64_len), (en_at, en_len)) = (place[0], place[1]);
        let bundle_manifest = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="5.0">
  <Identity Name="Palisade.TestBundle" Publisher="{PUBLISHER}" Version="2.0.0.0"/>
  <Packages>
    <Package Type="application" Version="2.0.0.0" Architecture="x64" FileName="app_x64.msix" Offset="{x64_at}" Size="{x64_len}">
      <Resources><Resource Language="en-us"/></Resources>
    </Package>
    <Package Type="resource" Version="2.0.0.0" ResourceId="en-us" FileName="app_en-us.msix" Offset="{en_at}" Size="{en_len}">
      <Resources><Resource Language="en-us"/></Resources>
    </Package>
  </Packages>
</Bundle>
"#
        );
        let mut files = payloads.to_vec();
        files.push(File {
            name: BUNDLE_MANIFEST.into(),
            data: bundle_manifest.into_bytes(),
            deflate: true,
        });
        Self {
            files,
            blockmap_extra: String::new(),
            blockmap_skip: None,
        }
    }

    /// The bundle manifest, for a bundle builder.
    pub fn bundle_manifest(&self) -> &[u8] {
        &self
            .files
            .iter()
            .find(|f| f.name == BUNDLE_MANIFEST)
            .unwrap()
            .data
    }

    fn is_bundle(&self) -> bool {
        self.files.iter().any(|f| f.name == BUNDLE_MANIFEST)
    }

    fn compressed(f: &File) -> (u16, Vec<u8>) {
        if f.deflate {
            (8, deflate_blocks(&f.data).0)
        } else {
            (0, f.data.clone())
        }
    }

    fn local_header_len(name: &str) -> usize {
        // No local extra fields in any style.
        30 + name.len()
    }

    /// The block map for the payload files: every file of a package, with
    /// each block's compressed size for a deflated file, or only the bundle
    /// manifest of a bundle (its payload packages are not listed).
    pub fn block_map(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">",
        );
        out.push_str(&self.blockmap_extra);
        for f in &self.files {
            if self.blockmap_skip.as_deref() == Some(f.name.as_str())
                || (self.is_bundle() && f.name != BUNDLE_MANIFEST)
            {
                continue;
            }
            out.push_str(&format!(
                "<File Name=\"{}\" Size=\"{}\" LfhSize=\"{}\">",
                f.name.replace('/', "\\"),
                f.data.len(),
                Self::local_header_len(&f.name)
            ));
            let sizes = deflate_blocks(&f.data).1;
            for (i, block) in f.data.chunks(65536).enumerate() {
                let h = Sha256::digest(block);
                if f.deflate {
                    out.push_str(&format!(
                        "<Block Hash=\"{}\" Size=\"{}\"/>",
                        base64(&h),
                        sizes[i]
                    ));
                } else {
                    out.push_str(&format!("<Block Hash=\"{}\"/>", base64(&h)));
                }
            }
            out.push_str("</File>");
        }
        out.push_str("</BlockMap>");
        out
    }

    /// `[Content_Types].xml` for a bundle, as the OS packaging tool writes
    /// it: payload packages and the bundle manifest by extension.
    pub fn bundle_content_types() -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"msix\" ContentType=\"application/vnd.ms-appx\"/><Default Extension=\"xml\" ContentType=\"application/vnd.ms-appx.bundlemanifest+xml\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/></Types>".into()
    }

    pub fn content_types() -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/><Default Extension=\"exe\" ContentType=\"application/x-msdownload\"/><Default Extension=\"bin\" ContentType=\"application/octet-stream\"/><Default Extension=\"png\" ContentType=\"image/png\"/><Default Extension=\"msix\" ContentType=\"application/vnd.ms-appx\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/></Types>".into()
    }

    /// The unsigned archive, in `style`.
    pub fn build_with(&self, style: &ZipStyle) -> Vec<u8> {
        write_zip_with(&self.all_files(), style)
    }

    /// The unsigned archive.
    pub fn build(&self) -> Vec<u8> {
        write_zip(&self.all_files())
    }

    fn all_files(&self) -> Vec<File> {
        let mut all: Vec<File> = self.files.clone();
        all.push(File {
            name: "AppxBlockMap.xml".into(),
            data: self.block_map().into_bytes(),
            deflate: true,
        });
        all.push(File {
            name: "[Content_Types].xml".into(),
            data: if self.is_bundle() {
                Self::bundle_content_types()
            } else {
                Self::content_types()
            }
            .into_bytes(),
            deflate: true,
        });
        all
    }
}

/// How [`write_zip_with`] lays an archive out.
#[derive(Clone, Debug, Default)]
pub struct ZipStyle {
    /// Data descriptors (with their signature) after each member, with
    /// zero CRC and sizes in the local headers, as packaging tools write.
    pub descriptors: bool,
    /// ZIP64 end records, and ZIP64 extra fields with every central
    /// size and offset marked `0xffffffff`.
    pub zip64: bool,
    /// Extra bytes appended to the first member's central extra field
    /// (for negative tests; every length and offset stays consistent).
    pub central_extra_tail: Vec<u8>,
    /// Extra bytes put in the first member's local extra field.
    pub local_extra: Vec<u8>,
    /// With `zip64`: central entries carry their real 32-bit sizes and
    /// offset and no ZIP64 extra field, as the OS packaging tool writes
    /// entries whose values fit.
    pub plain_entries: bool,
    /// The classic end record's two disk numbers are the `0xffff` marker,
    /// as the OS packaging tool writes them in its ZIP64 archives.
    pub disk_marker: bool,
    /// Deflated members end on their last full flush, without the empty
    /// final block (for negative tests).
    pub no_final_block: bool,
    /// Data descriptors with 4-byte sizes even in a ZIP64 archive (for
    /// negative tests).
    pub narrow_descriptors: bool,
    /// Data descriptors with 8-byte sizes even without ZIP64 (for negative
    /// tests).
    pub wide_descriptors: bool,
}

impl ZipStyle {
    /// The layout the OS packaging tool writes: a data descriptor with
    /// 8-byte sizes after every member, ZIP64 end records whose classic
    /// record holds the `0xffff` and `0xffffffff` markers (disk numbers
    /// included), and central entries without ZIP64 extra fields.
    pub fn packaging_tool() -> Self {
        Self {
            descriptors: true,
            zip64: true,
            plain_entries: true,
            disk_marker: true,
            ..Self::default()
        }
    }
}

/// Writes `files` as a ZIP archive in order.
pub fn write_zip(files: &[File]) -> Vec<u8> {
    write_zip_with(files, &ZipStyle::default())
}

/// Writes `files` as a ZIP archive in order, in `style`.
pub fn write_zip_with(files: &[File], style: &ZipStyle) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (index, f) in files.iter().enumerate() {
        let first = index == 0;
        let local_extra: &[u8] = if first { &style.local_extra } else { &[] };
        let tail: &[u8] = if first {
            &style.central_extra_tail
        } else {
            &[]
        };
        let (method, mut body) = AppxBuilder::compressed(f);
        if method == 8 && style.no_final_block {
            body.truncate(body.len() - 2);
        }
        let crc = crc32(&f.data);
        let offset = out.len() as u32;
        let name = f.name.as_bytes();
        let flags: u16 = if style.descriptors { 0x0008 } else { 0 };
        out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
        out.extend_from_slice(&20_u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0x5821_u16.to_le_bytes());
        if style.descriptors {
            out.extend_from_slice(&[0; 12]);
        } else {
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        }
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(local_extra.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(local_extra);
        out.extend_from_slice(&body);
        if style.descriptors {
            out.extend_from_slice(&0x0807_4b50_u32.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            if (style.zip64 && !style.narrow_descriptors) || style.wide_descriptors {
                out.extend_from_slice(&(body.len() as u64).to_le_bytes());
                out.extend_from_slice(&(f.data.len() as u64).to_le_bytes());
            } else {
                out.extend_from_slice(&(body.len() as u32).to_le_bytes());
                out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
            }
        }

        central.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        central.extend_from_slice(&45_u16.to_le_bytes());
        central.extend_from_slice(&20_u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&0_u16.to_le_bytes());
        central.extend_from_slice(&0x5821_u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        let extras = style.zip64 && !style.plain_entries;
        if extras {
            central.extend_from_slice(&u32::MAX.to_le_bytes());
            central.extend_from_slice(&u32::MAX.to_le_bytes());
        } else {
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        }
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        let zip64_len: u16 = if extras { 28 } else { 0 };
        central.extend_from_slice(&(zip64_len + tail.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 6]);
        central.extend_from_slice(&[0; 4]);
        if extras {
            central.extend_from_slice(&u32::MAX.to_le_bytes());
        } else {
            central.extend_from_slice(&offset.to_le_bytes());
        }
        central.extend_from_slice(name);
        if extras {
            central.extend_from_slice(&1_u16.to_le_bytes());
            central.extend_from_slice(&24_u16.to_le_bytes());
            central.extend_from_slice(&(f.data.len() as u64).to_le_bytes());
            central.extend_from_slice(&(body.len() as u64).to_le_bytes());
            central.extend_from_slice(&u64::from(offset).to_le_bytes());
        }
        central.extend_from_slice(tail);
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    if style.zip64 {
        let rec = out.len() as u64;
        out.extend_from_slice(&0x0606_4b50_u32.to_le_bytes());
        out.extend_from_slice(&44_u64.to_le_bytes());
        out.extend_from_slice(&45_u16.to_le_bytes());
        out.extend_from_slice(&45_u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&(files.len() as u64).to_le_bytes());
        out.extend_from_slice(&(files.len() as u64).to_le_bytes());
        out.extend_from_slice(&(central.len() as u64).to_le_bytes());
        out.extend_from_slice(&u64::from(cd_offset).to_le_bytes());
        out.extend_from_slice(&0x0706_4b50_u32.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&rec.to_le_bytes());
        out.extend_from_slice(&1_u32.to_le_bytes());
    }
    out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    let disk: u16 = if style.disk_marker { u16::MAX } else { 0 };
    out.extend_from_slice(&disk.to_le_bytes());
    out.extend_from_slice(&disk.to_le_bytes());
    let (n, size, off) = if style.zip64 {
        (u16::MAX, u32::MAX, u32::MAX)
    } else {
        (files.len() as u16, central.len() as u32, cd_offset)
    };
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&off.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out
}

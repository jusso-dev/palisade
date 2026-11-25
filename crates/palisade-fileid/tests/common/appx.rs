//! A builder for small synthetic app packages and bundles, used only by
//! tests and fuzz seeds.
//!
//! [`AppxBuilder`] writes a ZIP archive in the shape packaging tools use:
//! files stored or deflated, each with a local header, then
//! `AppxBlockMap.xml` (with real SHA-256 block hashes of every file),
//! `[Content_Types].xml`, the central directory and the end record.
//! Deflate here is a plain fixed-Huffman encoder of literals only, which is
//! valid DEFLATE every reader accepts. Everything is deterministic.

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

/// Raw DEFLATE with one fixed-Huffman block of literals.
pub fn deflate_literals(data: &[u8]) -> Vec<u8> {
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
    }
    let mut b = Bits {
        out: Vec::new(),
        acc: 0,
        n: 0,
    };
    b.put(1, 1); // final
    b.put(1, 2); // fixed Huffman
    for &c in data {
        let c = u32::from(c);
        if c < 144 {
            b.code(0x30 + c, 8);
        } else {
            b.code(0x190 + (c - 144), 9);
        }
    }
    b.code(0, 7); // end of block (256)
    if b.n > 0 {
        b.out.push(b.acc as u8);
    }
    b.out
}

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
                    data: vec![0x89, b'P', b'N', b'G', 1, 2, 3],
                    deflate: false,
                },
            ],
            blockmap_extra: String::new(),
            blockmap_skip: None,
        }
    }

    /// A bundle with a bundle manifest listing two (opaque) packages.
    pub fn bundle() -> Self {
        let bundle_manifest = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="5.0">
  <Identity Name="Palisade.TestBundle" Publisher="{PUBLISHER}" Version="2.0.0.0"/>
  <Packages>
    <Package Type="application" Version="2.0.0.0" Architecture="x64" FileName="app_x64.msix" Offset="100" Size="32"/>
    <Package Type="resource" Version="2.0.0.0" ResourceId="en-us" FileName="app_en-us.msix" Offset="200" Size="16"/>
  </Packages>
</Bundle>
"#
        );
        Self {
            files: vec![
                File {
                    name: "AppxMetadata/AppxBundleManifest.xml".into(),
                    data: bundle_manifest.into_bytes(),
                    deflate: true,
                },
                File {
                    name: "app_x64.msix".into(),
                    data: vec![0x50; 32],
                    deflate: false,
                },
                File {
                    name: "app_en-us.msix".into(),
                    data: vec![0x51; 16],
                    deflate: false,
                },
            ],
            blockmap_extra: String::new(),
            blockmap_skip: None,
        }
    }

    fn compressed(f: &File) -> (u16, Vec<u8>) {
        if f.deflate {
            (8, deflate_literals(&f.data))
        } else {
            (0, f.data.clone())
        }
    }

    fn local_header_len(name: &str) -> usize {
        // No local extra fields in any style.
        30 + name.len()
    }

    /// The block map for the payload files.
    pub fn block_map(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">",
        );
        out.push_str(&self.blockmap_extra);
        for f in &self.files {
            if self.blockmap_skip.as_deref() == Some(f.name.as_str()) {
                continue;
            }
            out.push_str(&format!(
                "<File Name=\"{}\" Size=\"{}\" LfhSize=\"{}\">",
                f.name.replace('/', "\\"),
                f.data.len(),
                Self::local_header_len(&f.name)
            ));
            for block in f.data.chunks(65536) {
                let h = Sha256::digest(block);
                out.push_str(&format!("<Block Hash=\"{}\"/>", base64(&h)));
            }
            out.push_str("</File>");
        }
        out.push_str("</BlockMap>");
        out
    }

    pub fn content_types() -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/><Default Extension=\"exe\" ContentType=\"application/x-msdownload\"/><Default Extension=\"bin\" ContentType=\"application/octet-stream\"/><Default Extension=\"png\" ContentType=\"image/png\"/><Default Extension=\"msix\" ContentType=\"application/vnd.ms-appx\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/></Types>".into()
    }

    /// The unsigned archive, in `style`.
    pub fn build_with(&self, style: ZipStyle) -> Vec<u8> {
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
            data: Self::content_types().into_bytes(),
            deflate: true,
        });
        all
    }
}

/// How [`write_zip_with`] lays an archive out.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZipStyle {
    /// Data descriptors (with their signature) after each member, with
    /// zero CRC and sizes in the local headers, as packaging tools write.
    pub descriptors: bool,
    /// ZIP64 end records, and ZIP64 extra fields with every central
    /// size and offset marked `0xffffffff`.
    pub zip64: bool,
}

/// Writes `files` as a ZIP archive in order.
pub fn write_zip(files: &[File]) -> Vec<u8> {
    write_zip_with(files, ZipStyle::default())
}

/// Writes `files` as a ZIP archive in order, in `style`.
pub fn write_zip_with(files: &[File], style: ZipStyle) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for f in files {
        let (method, body) = AppxBuilder::compressed(f);
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
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&body);
        if style.descriptors {
            out.extend_from_slice(&0x0807_4b50_u32.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            if style.zip64 {
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
        if style.zip64 {
            central.extend_from_slice(&u32::MAX.to_le_bytes());
            central.extend_from_slice(&u32::MAX.to_le_bytes());
        } else {
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        }
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&(if style.zip64 { 28_u16 } else { 0 }).to_le_bytes());
        central.extend_from_slice(&[0; 6]);
        central.extend_from_slice(&[0; 4]);
        if style.zip64 {
            central.extend_from_slice(&u32::MAX.to_le_bytes());
        } else {
            central.extend_from_slice(&offset.to_le_bytes());
        }
        central.extend_from_slice(name);
        if style.zip64 {
            central.extend_from_slice(&1_u16.to_le_bytes());
            central.extend_from_slice(&24_u16.to_le_bytes());
            central.extend_from_slice(&(f.data.len() as u64).to_le_bytes());
            central.extend_from_slice(&(body.len() as u64).to_le_bytes());
            central.extend_from_slice(&u64::from(offset).to_le_bytes());
        }
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
    out.extend_from_slice(&[0; 4]);
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

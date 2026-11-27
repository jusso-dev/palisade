//! Volume and drive classification.
//!
//! The OS reports a volume's file system name (`GetVolumeInformationW`), its
//! drive type (`GetDriveTypeW`) and the bus of the disk behind it
//! (`IOCTL_STORAGE_QUERY_PROPERTY`, `STORAGE_BUS_TYPE`). The functions here
//! turn those raw values into enums, and the enums into a
//! [`LocationClass`] that rules and guardrails can condition on. The
//! storage-query results are parsed here too
//! ([`parse_storage_device_descriptor`], [`parse_hotplug_info`]); the
//! Windows backend (`palisade_fileid::win::volume`) makes the calls.
//!
//! The classification is conservative: when the inputs disagree, the less
//! trusted class wins. A fixed drive on a USB bus is [`LocationClass::Removable`],
//! and a disk on a virtual bus is [`LocationClass::VirtualDisk`] unless it
//! is the OS volume. When an input is missing, the result is
//! [`LocationClass::Unknown`], never a trusted class: the OS volume is only
//! [`LocationClass::OsVolume`] when it is known not to be hot-pluggable, and
//! another fixed disk is only [`LocationClass::OtherFixed`] when its file
//! system, bus and hot-plug state are all known.
//!
//! The location class and owner support are separate questions. A VHD the
//! OS boots from is [`LocationClass::OsVolume`] for location rules, but its
//! owners can still have been written on another machine, so
//! [`VolumeInfo::supports_owner`] also requires a known, non-virtual bus.

#![forbid(unsafe_code)]

/// The file system of a volume.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FsType {
    /// NTFS.
    Ntfs,
    /// ReFS.
    Refs,
    /// FAT12, FAT16 or FAT32.
    Fat,
    /// exFAT.
    ExFat,
    /// UDF (optical and some removable media).
    Udf,
    /// CDFS (ISO 9660).
    Cdfs,
    /// A network redirector. The OS reports the remote file system's name
    /// for a share, so the backend sets this from the drive type instead.
    Network,
    /// Any other name, as reported.
    Other(String),
}

impl FsType {
    /// Classifies the name `GetVolumeInformationW` reports (`NTFS`, `FAT32`
    /// and so on), ignoring ASCII case.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let n = name.trim().to_ascii_uppercase();
        match n.as_str() {
            "NTFS" => Self::Ntfs,
            "REFS" => Self::Refs,
            "FAT" | "FAT12" | "FAT16" | "FAT32" => Self::Fat,
            "EXFAT" => Self::ExFat,
            "UDF" => Self::Udf,
            "CDFS" => Self::Cdfs,
            _ => Self::Other(name.trim().to_owned()),
        }
    }

    /// True if the file system records a reliable owner SID for each file.
    /// FAT, exFAT, UDF and CDFS do not, and a network share's owner is
    /// whatever the server reports, so owner-based conditions do not apply.
    #[must_use]
    pub fn supports_owner(&self) -> bool {
        matches!(self, Self::Ntfs | Self::Refs)
    }

    /// True if the file system can hold alternate data streams, and so a
    /// mark-of-the-web. ReFS gained streams later and only small ones; it is
    /// counted as supporting them.
    #[must_use]
    pub fn supports_streams(&self) -> bool {
        matches!(self, Self::Ntfs | Self::Refs)
    }
}

/// The drive type `GetDriveTypeW` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriveType {
    /// `DRIVE_UNKNOWN` (0) or `DRIVE_NO_ROOT_DIR` (1), or any other value.
    Unknown,
    /// `DRIVE_REMOVABLE` (2).
    Removable,
    /// `DRIVE_FIXED` (3).
    Fixed,
    /// `DRIVE_REMOTE` (4).
    Network,
    /// `DRIVE_CDROM` (5).
    CdRom,
    /// `DRIVE_RAMDISK` (6).
    RamDisk,
}

impl DriveType {
    /// Maps a `GetDriveTypeW` return value.
    #[must_use]
    pub const fn from_win32(value: u32) -> Self {
        match value {
            2 => Self::Removable,
            3 => Self::Fixed,
            4 => Self::Network,
            5 => Self::CdRom,
            6 => Self::RamDisk,
            _ => Self::Unknown,
        }
    }
}

/// The bus of the disk behind a volume (`STORAGE_BUS_TYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BusType {
    /// `BusTypeScsi` (1).
    Scsi,
    /// `BusTypeAtapi` (2).
    Atapi,
    /// `BusTypeAta` (3).
    Ata,
    /// `BusType1394` (4).
    Ieee1394,
    /// `BusTypeSsa` (5).
    Ssa,
    /// `BusTypeFibre` (6).
    Fibre,
    /// `BusTypeUsb` (7).
    Usb,
    /// `BusTypeRAID` (8).
    Raid,
    /// `BusTypeiScsi` (9).
    Iscsi,
    /// `BusTypeSas` (10).
    Sas,
    /// `BusTypeSata` (11).
    Sata,
    /// `BusTypeSd` (12).
    Sd,
    /// `BusTypeMmc` (13).
    Mmc,
    /// `BusTypeVirtual` (14).
    Virtual,
    /// `BusTypeFileBackedVirtual` (15): a VHD or VHDX file.
    FileBackedVirtual,
    /// `BusTypeSpaces` (16): a storage-pool virtual disk.
    Spaces,
    /// `BusTypeNvme` (17).
    Nvme,
    /// `BusTypeSCM` (18): storage-class memory.
    Scm,
    /// `BusTypeUfs` (19).
    Ufs,
    /// `BusTypeNvmeof` (20): NVMe over fabrics.
    NvmeOf,
    /// `BusTypeUnknown` (0), or a value this crate does not know.
    Unknown(u32),
}

impl BusType {
    /// Maps a `STORAGE_BUS_TYPE` value.
    #[must_use]
    pub const fn from_win32(value: u32) -> Self {
        match value {
            1 => Self::Scsi,
            2 => Self::Atapi,
            3 => Self::Ata,
            4 => Self::Ieee1394,
            5 => Self::Ssa,
            6 => Self::Fibre,
            7 => Self::Usb,
            8 => Self::Raid,
            9 => Self::Iscsi,
            10 => Self::Sas,
            11 => Self::Sata,
            12 => Self::Sd,
            13 => Self::Mmc,
            14 => Self::Virtual,
            15 => Self::FileBackedVirtual,
            16 => Self::Spaces,
            17 => Self::Nvme,
            18 => Self::Scm,
            19 => Self::Ufs,
            20 => Self::NvmeOf,
            n => Self::Unknown(n),
        }
    }

    /// True for buses whose devices are usually plugged in by a user: USB,
    /// IEEE 1394, SD and MMC.
    #[must_use]
    pub const fn is_user_pluggable(self) -> bool {
        matches!(self, Self::Usb | Self::Ieee1394 | Self::Sd | Self::Mmc)
    }

    /// True for a disk backed by a file or a network target rather than
    /// local hardware: a VHD/VHDX or an iSCSI or NVMe-over-fabrics target.
    #[must_use]
    pub const fn is_virtual(self) -> bool {
        matches!(
            self,
            Self::FileBackedVirtual | Self::Virtual | Self::Iscsi | Self::NvmeOf
        )
    }
}

/// Where a file lives, for location conditions and guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocationClass {
    /// The volume the OS runs from.
    OsVolume,
    /// Another fixed local disk.
    OtherFixed,
    /// Removable media, or a disk on a user-pluggable bus.
    Removable,
    /// An optical disc.
    Optical,
    /// A network share.
    Network,
    /// A RAM disk.
    RamDisk,
    /// A virtual disk (VHD/VHDX, iSCSI and similar) that is not the OS
    /// volume.
    VirtualDisk,
    /// Not enough information to classify.
    Unknown,
}

impl LocationClass {
    /// True if files here should be treated as coming from outside the
    /// managed system: everything except the OS volume and other fixed
    /// local disks.
    #[must_use]
    pub const fn is_untrusted_location(self) -> bool {
        !matches!(self, Self::OsVolume | Self::OtherFixed)
    }
}

/// What is known about a volume. Every field is optional because each comes
/// from a separate OS call that can fail.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VolumeInfo {
    /// The volume serial number.
    pub serial: Option<u32>,
    /// The file system.
    pub fs_type: Option<FsType>,
    /// The drive type.
    pub drive_type: Option<DriveType>,
    /// The bus of the disk.
    pub bus_type: Option<BusType>,
    /// The device can be removed while the system runs (hot-plug).
    pub is_hotplug: Option<bool>,
    /// The volume is the one the OS runs from.
    pub is_os_volume: Option<bool>,
    /// The file system keeps a change journal (USN).
    pub supports_usn: Option<bool>,
}

impl VolumeInfo {
    /// True if the disk is a VHD or VHDX file.
    #[must_use]
    pub fn is_vhd(&self) -> bool {
        self.bus_type == Some(BusType::FileBackedVirtual)
    }

    /// True if the owner recorded on this volume can be relied on: the file
    /// system records owners, the volume is a local fixed disk
    /// ([`LocationClass::OsVolume`] or [`LocationClass::OtherFixed`]), and
    /// its bus is known and not virtual.
    ///
    /// Removable media, virtual disks and network shares are excluded: their
    /// contents can be prepared on another machine, with any owner SID
    /// written into them, or the owner is whatever a server reports. That
    /// holds for a VHD even when the OS boots from it, so the bus is checked
    /// separately from the location class.
    #[must_use]
    pub fn supports_owner(&self) -> bool {
        let physical_bus = matches!(
            self.bus_type,
            Some(b) if !b.is_virtual() && !matches!(b, BusType::Unknown(_))
        );
        self.fs_type.as_ref().is_some_and(FsType::supports_owner)
            && physical_bus
            && matches!(
                self.location_class(),
                LocationClass::OsVolume | LocationClass::OtherFixed
            )
    }

    /// The location class. See the module documentation for how
    /// disagreements are settled.
    #[must_use]
    pub fn location_class(&self) -> LocationClass {
        match self.drive_type {
            Some(DriveType::Network) => return LocationClass::Network,
            Some(DriveType::CdRom) => return LocationClass::Optical,
            Some(DriveType::RamDisk) => return LocationClass::RamDisk,
            Some(DriveType::Removable) => return LocationClass::Removable,
            Some(DriveType::Fixed) => {}
            Some(DriveType::Unknown) | None => return LocationClass::Unknown,
        }
        if matches!(self.fs_type, Some(FsType::Network)) {
            return LocationClass::Network;
        }
        // Pluggable and virtual disks are checked before the file system:
        // a USB disk or a VHD can be formatted with UDF, and is still a
        // USB disk or a VHD.
        if self.is_hotplug == Some(true) || self.bus_type.is_some_and(BusType::is_user_pluggable) {
            return LocationClass::Removable;
        }
        if self.is_os_volume == Some(true) {
            // An OS volume whose hot-plug state is unknown might be on a
            // pluggable disk, which a known state would make removable.
            return if self.is_hotplug == Some(false) {
                LocationClass::OsVolume
            } else {
                LocationClass::Unknown
            };
        }
        if self.bus_type.is_some_and(BusType::is_virtual) {
            return LocationClass::VirtualDisk;
        }
        if matches!(self.fs_type, Some(FsType::Cdfs | FsType::Udf)) {
            return LocationClass::Optical;
        }
        // A disk that is neither the OS volume nor known to be a local,
        // non-pluggable disk stays unknown. External USB disks and attached
        // VHDs also report `DRIVE_FIXED`, so a failed bus or hot-plug query
        // must not make a volume look like a trusted fixed disk. Nor must a
        // failed file-system query: a UDF disk is optical, checked above.
        let bus_known = matches!(self.bus_type, Some(b) if !matches!(b, BusType::Unknown(_)));
        if self.is_os_volume == Some(false)
            && bus_known
            && self.is_hotplug == Some(false)
            && self.fs_type.is_some()
        {
            LocationClass::OtherFixed
        } else {
            LocationClass::Unknown
        }
    }
}

/// Independent signs that a file was reached through a network redirector.
/// Each is `None` when it could not be read.
///
/// No single OS answer is relied on. `FileRemoteProtocolInfo` is the
/// documented test, but it has been seen to fail on a real redirector
/// handle (#54, the Windows 11 Arm64 runner), and a share's server reports
/// its own file system (`NTFS`) and serial. Any one sign saying "network"
/// makes the volume [`VolumeInfo::network`]; see [`VolumeInfo::settle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkEvidence {
    /// `FileRemoteProtocolInfo` answered for the handle, which only a
    /// redirector does.
    pub remote_protocol: Option<bool>,
    /// The handle's NT path is under a network provider
    /// (`\Device\Mup\…`), from [`nt_path_on_network`].
    pub nt_path_on_network: Option<bool>,
    /// The name the file was opened by is a UNC path, or a drive letter
    /// the OS reports as remote.
    pub opened_as_network: Option<bool>,
}

impl NetworkEvidence {
    /// True if any sign says the file is on the network.
    #[must_use]
    pub const fn is_network(&self) -> bool {
        matches!(self.remote_protocol, Some(true))
            || matches!(self.nt_path_on_network, Some(true))
            || matches!(self.opened_as_network, Some(true))
    }
}

/// NT devices of network redirectors and providers: the multiple UNC
/// provider, SMB, WebDAV, remote-desktop drive redirection and the
/// Linux-subsystem file server.
const REDIRECTOR_DEVICES: [&str; 5] = [
    "Mup",
    "LanmanRedirector",
    "WebDavRedirector",
    "RdpDr",
    "P9Rdr",
];

/// What an NT device name (`Mup`, `HarddiskVolume3`) says: `Some(true)` for
/// a redirector, `Some(false)` for a local disk volume or shadow copy,
/// `None` for anything else.
fn nt_device_on_network(device: &str) -> Option<bool> {
    if REDIRECTOR_DEVICES
        .iter()
        .any(|r| device.eq_ignore_ascii_case(r))
    {
        return Some(true);
    }
    let local = device
        .get(..14)
        .is_some_and(|p| p.eq_ignore_ascii_case("HarddiskVolume"))
        && device.len() > 14;
    local.then_some(false)
}

/// Whether an NT path, as `GetFinalPathNameByHandleW` reports it with
/// `VOLUME_NAME_NT`, is under a network provider. `Some(true)` for
/// `\Device\Mup\…`, `\Device\LanmanRedirector\…` and the other redirector
/// devices; `Some(false)` for a local disk volume
/// (`\Device\HarddiskVolumeN\…`); `None` for any other device or a path
/// that is not under `\Device\`, which never counts as either.
///
/// Only the device name is read, not the rest of the path, so a
/// redirector path the path normaliser would reject (a provider prefix
/// such as `;:1`) still counts as the network.
#[must_use]
pub fn nt_path_on_network(nt_path: &str) -> Option<bool> {
    let mut parts = nt_path.split('\\');
    let (Some(""), Some(dev), Some(device)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    if !dev.eq_ignore_ascii_case("Device") {
        return None;
    }
    nt_device_on_network(device)
}

/// What the name a file was opened by says about the network, without the
/// OS: `Some(true)` for a UNC path (also `\\?\UNC\…` and
/// `\\?\GLOBALROOT\Device\Mup\…`), `Some(false)` for a volume GUID or local
/// disk path, and `None` for a drive letter, which only the OS can map
/// (it may be a mapped network drive), or anything else.
#[must_use]
pub fn opened_name_on_network(path: &super::path::NormalizedPath) -> Option<bool> {
    match path.root() {
        super::path::Root::Unc { .. } => Some(true),
        super::path::Root::VolumeGuid(_) => Some(false),
        super::path::Root::NtDevice(d) => nt_device_on_network(d),
        _ => None,
    }
}

impl VolumeInfo {
    /// A volume reached through a network redirector: [`FsType::Network`],
    /// [`DriveType::Network`] and no change journal, whatever the server
    /// reports. The serial is kept as reported; it is the server's.
    #[must_use]
    pub fn network(serial: Option<u32>) -> Self {
        Self {
            serial,
            fs_type: Some(FsType::Network),
            drive_type: Some(DriveType::Network),
            supports_usn: Some(false),
            ..Self::default()
        }
    }

    /// Settles what the OS `reported` for a handle into the value the
    /// backend returns, so a missing or contradicted fact can never make
    /// the volume look like a trusted local disk (ADR 0018):
    ///
    /// - any sign of the network in `evidence` gives [`VolumeInfo::network`],
    ///   even if the redirector query said "local";
    /// - otherwise, if the handle's local volume root could not be resolved
    ///   (`root_resolved` is false), only the serial is kept. The file
    ///   system, journal and drive facts may then be a server's, so they are
    ///   dropped and the class is [`LocationClass::Unknown`];
    /// - otherwise `reported` is returned unchanged.
    #[must_use]
    pub fn settle(reported: Self, evidence: NetworkEvidence, root_resolved: bool) -> Self {
        if evidence.is_network() {
            Self::network(reported.serial)
        } else if root_resolved {
            reported
        } else {
            Self {
                serial: reported.serial,
                ..Self::default()
            }
        }
    }
}

/// What the disk behind a volume says about itself: the header of the
/// `STORAGE_DEVICE_DESCRIPTOR` that `IOCTL_STORAGE_QUERY_PROPERTY` returns
/// for `StorageDeviceProperty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageDevice {
    /// The bus.
    pub bus_type: BusType,
    /// The device reports removable media.
    pub removable_media: bool,
}

/// The fixed part of `STORAGE_DEVICE_DESCRIPTOR`, up to and including
/// `BusType`.
const STORAGE_DEVICE_HEADER: usize = 32;

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    let bytes = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Parses the `STORAGE_DEVICE_DESCRIPTOR` bytes the OS returned. `None` if
/// they are shorter than the header, or the descriptor's own `Size` says
/// it is.
#[must_use]
pub fn parse_storage_device_descriptor(bytes: &[u8]) -> Option<StorageDevice> {
    let size = usize::try_from(u32_le(bytes, 4)?).ok()?;
    if bytes.len() < STORAGE_DEVICE_HEADER || size < STORAGE_DEVICE_HEADER {
        return None;
    }
    Some(StorageDevice {
        bus_type: BusType::from_win32(u32_le(bytes, 28)?),
        removable_media: *bytes.get(10)? != 0,
    })
}

/// What `IOCTL_STORAGE_GET_HOTPLUG_INFO` reports (`STORAGE_HOTPLUG_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotplugInfo {
    /// The media can be removed from the device.
    pub media_removable: bool,
    /// The media can be removed while the system runs.
    pub media_hotplug: bool,
    /// The device itself can be removed while the system runs.
    pub device_hotplug: bool,
}

impl HotplugInfo {
    /// Whether the device or its media can be removed while the system
    /// runs: the value of [`VolumeInfo::is_hotplug`].
    #[must_use]
    pub const fn is_hotplug(self) -> bool {
        self.media_hotplug || self.device_hotplug
    }
}

/// The value of [`VolumeInfo::is_hotplug`] from the two storage queries,
/// either of which may have failed. Removable media counts as
/// hot-pluggable: it can be swapped while the system runs, whatever the
/// hot-plug flags say. Either query reporting removable media is enough.
/// `None` only when neither query answered and so nothing is known.
#[must_use]
pub fn combined_hotplug(
    storage: Option<StorageDevice>,
    hotplug: Option<HotplugInfo>,
) -> Option<bool> {
    let removable =
        storage.is_some_and(|s| s.removable_media) || hotplug.is_some_and(|h| h.media_removable);
    match hotplug {
        Some(h) => Some(h.is_hotplug() || removable),
        None if removable => Some(true),
        None => None,
    }
}

/// Parses the `STORAGE_HOTPLUG_INFO` bytes the OS returned: a `u32` size
/// and four one-byte flags. `None` if shorter.
#[must_use]
pub fn parse_hotplug_info(bytes: &[u8]) -> Option<HotplugInfo> {
    let size = usize::try_from(u32_le(bytes, 0)?).ok()?;
    let flags = bytes.get(4..8)?;
    if size < 8 {
        return None;
    }
    Some(HotplugInfo {
        media_removable: flags.first().is_some_and(|&b| b != 0),
        media_hotplug: flags.get(1).is_some_and(|&b| b != 0),
        device_hotplug: flags.get(2).is_some_and(|&b| b != 0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_descriptors_parse() {
        let mut d = vec![0_u8; 40];
        d[0..4].copy_from_slice(&1_u32.to_le_bytes());
        d[4..8].copy_from_slice(&40_u32.to_le_bytes());
        d[10] = 1;
        d[28..32].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            parse_storage_device_descriptor(&d),
            Some(StorageDevice {
                bus_type: BusType::Usb,
                removable_media: true
            })
        );
        // Too short, or a `Size` that does not cover the bus type.
        assert_eq!(parse_storage_device_descriptor(&d[..31]), None);
        d[4..8].copy_from_slice(&8_u32.to_le_bytes());
        assert_eq!(parse_storage_device_descriptor(&d), None);
        assert_eq!(parse_storage_device_descriptor(&[]), None);

        let h = [8, 0, 0, 0, 0, 0, 1, 0];
        let info = parse_hotplug_info(&h).unwrap();
        assert!(info.device_hotplug && info.is_hotplug() && !info.media_removable);
        assert!(
            !parse_hotplug_info(&[8, 0, 0, 0, 1, 0, 0, 0])
                .unwrap()
                .is_hotplug()
        );
        assert_eq!(parse_hotplug_info(&[8, 0, 0, 0, 1]), None);
        assert_eq!(parse_hotplug_info(&[4, 0, 0, 0, 1, 1, 1, 1]), None);
    }

    #[test]
    fn removable_media_is_hot_pluggable_from_either_query() {
        let flags = |media_removable, media_hotplug, device_hotplug| HotplugInfo {
            media_removable,
            media_hotplug,
            device_hotplug,
        };
        let disk = |removable_media| StorageDevice {
            bus_type: BusType::Sata,
            removable_media,
        };
        // The storage query failed; the hot-plug reply says removable
        // media with both hot-plug flags clear.
        let only_removable = flags(true, false, false);
        assert!(!only_removable.is_hotplug());
        assert_eq!(combined_hotplug(None, Some(only_removable)), Some(true));
        assert_eq!(
            combined_hotplug(Some(disk(false)), Some(only_removable)),
            Some(true)
        );
        // Removable media from the storage query alone.
        assert_eq!(combined_hotplug(Some(disk(true)), None), Some(true));
        assert_eq!(
            combined_hotplug(Some(disk(true)), Some(flags(false, false, false))),
            Some(true)
        );
        // Either hot-plug flag.
        assert_eq!(
            combined_hotplug(None, Some(flags(false, false, true))),
            Some(true)
        );
        assert_eq!(
            combined_hotplug(None, Some(flags(false, true, false))),
            Some(true)
        );
        // A fixed, non-pluggable disk, and nothing known.
        assert_eq!(
            combined_hotplug(Some(disk(false)), Some(flags(false, false, false))),
            Some(false)
        );
        assert_eq!(combined_hotplug(Some(disk(false)), None), None);
        assert_eq!(combined_hotplug(None, None), None);
    }

    fn fixed(bus: BusType, os: bool) -> VolumeInfo {
        VolumeInfo {
            fs_type: Some(FsType::Ntfs),
            drive_type: Some(DriveType::Fixed),
            bus_type: Some(bus),
            is_hotplug: Some(false),
            is_os_volume: Some(os),
            ..VolumeInfo::default()
        }
    }

    #[test]
    fn raw_values_map() {
        assert_eq!(FsType::from_name("ntfs"), FsType::Ntfs);
        assert_eq!(FsType::from_name("FAT32"), FsType::Fat);
        assert_eq!(FsType::from_name("exFAT"), FsType::ExFat);
        assert_eq!(FsType::from_name("ReFS"), FsType::Refs);
        assert_eq!(FsType::from_name(" Btrfs "), FsType::Other("Btrfs".into()));
        assert_eq!(DriveType::from_win32(3), DriveType::Fixed);
        assert_eq!(DriveType::from_win32(1), DriveType::Unknown);
        assert_eq!(DriveType::from_win32(99), DriveType::Unknown);
        assert_eq!(BusType::from_win32(7), BusType::Usb);
        assert_eq!(BusType::from_win32(17), BusType::Nvme);
        assert_eq!(BusType::from_win32(20), BusType::NvmeOf);
        assert_eq!(BusType::from_win32(0), BusType::Unknown(0));
        assert_eq!(BusType::from_win32(0x7F), BusType::Unknown(0x7F));
    }

    #[test]
    fn classification() {
        assert_eq!(
            fixed(BusType::Nvme, true).location_class(),
            LocationClass::OsVolume
        );
        assert_eq!(
            fixed(BusType::Sata, false).location_class(),
            LocationClass::OtherFixed
        );
        // A fixed drive on USB is removable, even if it claims to be the OS
        // volume (a portable OS install).
        assert_eq!(
            fixed(BusType::Usb, true).location_class(),
            LocationClass::Removable
        );
        assert_eq!(
            fixed(BusType::FileBackedVirtual, false).location_class(),
            LocationClass::VirtualDisk
        );
        assert!(fixed(BusType::FileBackedVirtual, false).is_vhd());
        // Booting from a VHD makes it the OS volume.
        assert_eq!(
            fixed(BusType::FileBackedVirtual, true).location_class(),
            LocationClass::OsVolume
        );
        // UDF on a USB disk or a VHD is still removable or virtual.
        let mut udf_usb = fixed(BusType::Usb, false);
        udf_usb.fs_type = Some(FsType::Udf);
        assert_eq!(udf_usb.location_class(), LocationClass::Removable);
        let mut udf_vhd = fixed(BusType::FileBackedVirtual, false);
        udf_vhd.fs_type = Some(FsType::Udf);
        assert_eq!(udf_vhd.location_class(), LocationClass::VirtualDisk);
        let mut udf_sata = fixed(BusType::Sata, false);
        udf_sata.fs_type = Some(FsType::Udf);
        assert_eq!(udf_sata.location_class(), LocationClass::Optical);
        let mut hot = fixed(BusType::Sata, false);
        hot.is_hotplug = Some(true);
        assert_eq!(hot.location_class(), LocationClass::Removable);

        for (drive, class) in [
            (DriveType::Network, LocationClass::Network),
            (DriveType::CdRom, LocationClass::Optical),
            (DriveType::RamDisk, LocationClass::RamDisk),
            (DriveType::Removable, LocationClass::Removable),
            (DriveType::Unknown, LocationClass::Unknown),
        ] {
            let v = VolumeInfo {
                drive_type: Some(drive),
                ..VolumeInfo::default()
            };
            assert_eq!(v.location_class(), class);
            assert!(class.is_untrusted_location());
        }
        assert_eq!(
            VolumeInfo::default().location_class(),
            LocationClass::Unknown
        );
        let unknown_os = VolumeInfo {
            drive_type: Some(DriveType::Fixed),
            ..VolumeInfo::default()
        };
        assert_eq!(unknown_os.location_class(), LocationClass::Unknown);
        // A non-OS fixed disk whose bus or hot-plug state is unknown is not
        // promoted to a trusted fixed disk.
        let mut v = fixed(BusType::Sata, false);
        v.bus_type = None;
        assert_eq!(v.location_class(), LocationClass::Unknown);
        let mut v = fixed(BusType::Unknown(0), false);
        assert_eq!(v.location_class(), LocationClass::Unknown);
        v.bus_type = Some(BusType::Sata);
        v.is_hotplug = None;
        assert_eq!(v.location_class(), LocationClass::Unknown);
        // A failed file-system query does not turn a possibly optical disk
        // into a trusted fixed disk.
        let mut v = fixed(BusType::Sata, false);
        v.fs_type = None;
        assert_eq!(v.location_class(), LocationClass::Unknown);
        // Nor does an unknown hot-plug state make an OS volume trusted.
        let mut v = fixed(BusType::Sata, true);
        v.is_hotplug = None;
        assert_eq!(v.location_class(), LocationClass::Unknown);
    }

    #[test]
    fn owner_support() {
        assert!(fixed(BusType::Sata, false).supports_owner());
        let fat = VolumeInfo {
            fs_type: Some(FsType::Fat),
            drive_type: Some(DriveType::Removable),
            ..VolumeInfo::default()
        };
        assert!(!fat.supports_owner());
        let share = VolumeInfo {
            fs_type: Some(FsType::Ntfs),
            drive_type: Some(DriveType::Network),
            ..VolumeInfo::default()
        };
        assert!(!share.supports_owner());
        assert!(!VolumeInfo::default().supports_owner());
        // NTFS on removable or virtual media: the owner may have been set
        // on another machine.
        assert!(!fixed(BusType::Usb, false).supports_owner());
        assert!(!fixed(BusType::FileBackedVirtual, false).supports_owner());
        let ntfs_stick = VolumeInfo {
            fs_type: Some(FsType::Ntfs),
            drive_type: Some(DriveType::Removable),
            ..VolumeInfo::default()
        };
        assert!(!ntfs_stick.supports_owner());
        let mut no_drive = fixed(BusType::Sata, false);
        no_drive.drive_type = None;
        assert!(!no_drive.supports_owner());
        // A boot VHD is the OS volume for location rules, but its owners may
        // have been written elsewhere.
        for bus in [
            BusType::FileBackedVirtual,
            BusType::Virtual,
            BusType::Iscsi,
            BusType::NvmeOf,
        ] {
            let boot = fixed(bus, true);
            assert_eq!(boot.location_class(), LocationClass::OsVolume);
            assert!(!boot.supports_owner(), "{bus:?}");
        }
        // A physical OS volume keeps owner support; an unknown bus or
        // hot-plug state does not.
        assert!(fixed(BusType::Nvme, true).supports_owner());
        let mut os = fixed(BusType::Nvme, true);
        os.bus_type = None;
        assert!(!os.supports_owner());
        os.bus_type = Some(BusType::Unknown(0));
        assert!(!os.supports_owner());
        let mut os = fixed(BusType::Sata, true);
        os.is_hotplug = None;
        assert!(!os.supports_owner());
    }

    #[test]
    fn nt_paths_of_redirectors_are_network() {
        for p in [
            r"\Device\Mup\localhost\share\tool.exe",
            r"\Device\Mup\;LanmanRedirector\;Z:000000000001a2b3\srv\share\x.exe",
            r"\Device\LanmanRedirector\srv\share\x.exe",
            r"\Device\WebDavRedirector\srv\DavWWWRoot\x.exe",
            r"\Device\RdpDr\;:1\tsclient\C\x.exe",
            r"\Device\P9Rdr\wsl.localhost\distro\x.exe",
        ] {
            assert_eq!(nt_path_on_network(p), Some(true), "{p}");
        }
        assert_eq!(
            nt_path_on_network(r"\Device\HarddiskVolume3\Windows\x.exe"),
            Some(false)
        );
        assert_eq!(
            nt_path_on_network(r"\Device\HarddiskVolumeShadowCopy2\x.exe"),
            Some(false)
        );
        // Another device, or something that is not an NT path, is neither.
        assert_eq!(nt_path_on_network(r"\Device\CdRom0\x.exe"), None);
        assert_eq!(nt_path_on_network(r"\Device\HarddiskVolume"), None);
        assert_eq!(nt_path_on_network(r"\??\C:\x.exe"), None);
        assert_eq!(nt_path_on_network(r"C:\x.exe"), None);
        assert_eq!(nt_path_on_network(""), None);
    }

    #[test]
    fn opened_names_of_shares_are_network() {
        let on = |p: &str| opened_name_on_network(&crate::fsctx::normalize_win32(p).unwrap());
        assert_eq!(on(r"\\localhost\share\tool.exe"), Some(true));
        assert_eq!(on(r"\\?\UNC\srv\share\tool.exe"), Some(true));
        assert_eq!(
            on(r"\\?\GLOBALROOT\Device\Mup\srv\share\tool.exe"),
            Some(true)
        );
        assert_eq!(
            on(r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\x.exe"),
            Some(false)
        );
        assert_eq!(
            on(r"\\?\GLOBALROOT\Device\HarddiskVolume2\x.exe"),
            Some(false)
        );
        // A drive letter may be a mapped network drive: only the OS knows.
        assert_eq!(on(r"Z:\tool.exe"), None);
        assert_eq!(on(r"\\.\pipe\x"), None);
    }

    /// What the Windows 11 Arm64 runner reported for a file opened as
    /// `\\localhost\share\tool.exe` (#54): the server's NTFS and serial,
    /// with the redirector query and the local volume root both failing.
    fn arm64_share_report() -> VolumeInfo {
        VolumeInfo {
            serial: Some(2_222_135_570),
            fs_type: Some(FsType::Ntfs),
            supports_usn: Some(false),
            ..VolumeInfo::default()
        }
    }

    #[test]
    fn a_share_whose_redirector_query_fails_is_still_network() {
        // Any one sign of the network wins, even against the query.
        for evidence in [
            NetworkEvidence {
                remote_protocol: Some(false),
                nt_path_on_network: Some(true),
                opened_as_network: None,
            },
            NetworkEvidence {
                remote_protocol: Some(false),
                nt_path_on_network: Some(false),
                opened_as_network: Some(true),
            },
            NetworkEvidence {
                remote_protocol: Some(true),
                nt_path_on_network: Some(false),
                opened_as_network: Some(false),
            },
        ] {
            assert!(evidence.is_network());
            for root in [false, true] {
                let v = VolumeInfo::settle(arm64_share_report(), evidence, root);
                assert_eq!(v, VolumeInfo::network(Some(2_222_135_570)));
                assert_eq!(v.location_class(), LocationClass::Network);
                assert!(!v.supports_owner());
            }
        }
        // A fully local-looking report is also overridden.
        let local = fixed(BusType::Nvme, true);
        let evidence = NetworkEvidence {
            opened_as_network: Some(true),
            ..NetworkEvidence::default()
        };
        assert_eq!(
            VolumeInfo::settle(local, evidence, true).location_class(),
            LocationClass::Network
        );
    }

    #[test]
    fn an_unresolved_volume_root_never_reads_as_local_ntfs() {
        // No sign of the network, but no local volume root either: the
        // file system may be a server's, so nothing but the serial is kept.
        for evidence in [
            NetworkEvidence::default(),
            NetworkEvidence {
                remote_protocol: Some(false),
                nt_path_on_network: None,
                opened_as_network: None,
            },
            NetworkEvidence {
                remote_protocol: None,
                nt_path_on_network: Some(false),
                opened_as_network: Some(false),
            },
        ] {
            assert!(!evidence.is_network());
            let v = VolumeInfo::settle(arm64_share_report(), evidence, false);
            assert_eq!(v.fs_type, None, "{v:?}");
            assert_eq!(v.supports_usn, None, "{v:?}");
            assert_eq!(v.serial, Some(2_222_135_570));
            assert_eq!(v.location_class(), LocationClass::Unknown);
            assert!(!v.supports_owner());
        }
        // With a resolved local root and no sign of the network, the
        // report stands.
        let local = fixed(BusType::Nvme, true);
        assert_eq!(
            VolumeInfo::settle(local.clone(), NetworkEvidence::default(), true),
            local
        );
    }
}

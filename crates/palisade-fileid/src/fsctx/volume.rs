//! Volume and drive classification.
//!
//! The OS reports a volume's file system name (`GetVolumeInformationW`), its
//! drive type (`GetDriveTypeW`) and the bus of the disk behind it
//! (`IOCTL_STORAGE_QUERY_PROPERTY`, `STORAGE_BUS_TYPE`). The functions here
//! turn those raw values into enums, and the enums into a
//! [`LocationClass`] that rules and guardrails can condition on. Reading
//! the values needs Windows FFI and is left to the OS backend (#54).
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

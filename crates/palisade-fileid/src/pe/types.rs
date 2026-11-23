//! Header field types: machine, subsystem and the flag words.

#![forbid(unsafe_code)]

use std::fmt;

/// The COFF `Machine` field: the CPU an image targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Machine {
    /// `0x0000`: unknown or any machine.
    Unknown,
    /// `0x014c`: x86 (I386).
    I386,
    /// `0x8664`: x64 (AMD64).
    Amd64,
    /// `0xaa64`: ARM64. ARM64X images also use this value.
    Arm64,
    /// `0xa641`: ARM64EC.
    Arm64Ec,
    /// `0xa64e`: ARM64X.
    Arm64X,
    /// `0x01c4`: ARM Thumb-2 (ARMNT).
    ArmNt,
    /// `0x01c0`: ARM little-endian.
    Arm,
    /// `0x01c2`: ARM Thumb.
    Thumb,
    /// `0x3a64`: compiled hybrid PE (CHPE) x86.
    ChpeX86,
    /// `0x0200`: IA-64 (Itanium architecture).
    Ia64,
    /// `0x0ebc`: EFI byte code.
    Ebc,
    /// Any other value.
    Other(u16),
}

impl Machine {
    /// Decodes the raw field.
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        match value {
            0x0000 => Self::Unknown,
            0x014c => Self::I386,
            0x8664 => Self::Amd64,
            0xaa64 => Self::Arm64,
            0xa641 => Self::Arm64Ec,
            0xa64e => Self::Arm64X,
            0x01c4 => Self::ArmNt,
            0x01c0 => Self::Arm,
            0x01c2 => Self::Thumb,
            0x3a64 => Self::ChpeX86,
            0x0200 => Self::Ia64,
            0x0ebc => Self::Ebc,
            other => Self::Other(other),
        }
    }

    /// The raw field value.
    #[must_use]
    pub const fn raw(self) -> u16 {
        match self {
            Self::Unknown => 0x0000,
            Self::I386 => 0x014c,
            Self::Amd64 => 0x8664,
            Self::Arm64 => 0xaa64,
            Self::Arm64Ec => 0xa641,
            Self::Arm64X => 0xa64e,
            Self::ArmNt => 0x01c4,
            Self::Arm => 0x01c0,
            Self::Thumb => 0x01c2,
            Self::ChpeX86 => 0x3a64,
            Self::Ia64 => 0x0200,
            Self::Ebc => 0x0ebc,
            Self::Other(other) => other,
        }
    }
}

/// The optional header `Subsystem` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subsystem {
    /// `0`: unknown.
    Unknown,
    /// `1`: native (kernel drivers and native processes).
    Native,
    /// `2`: Windows GUI.
    WindowsGui,
    /// `3`: Windows console (CUI).
    WindowsCui,
    /// `5`: OS/2 console.
    Os2Cui,
    /// `7`: POSIX console.
    PosixCui,
    /// `8`: native Win9x driver.
    NativeWindows,
    /// `9`: Windows CE GUI.
    WindowsCeGui,
    /// `10`: EFI application.
    EfiApplication,
    /// `11`: EFI boot service driver.
    EfiBootServiceDriver,
    /// `12`: EFI runtime driver.
    EfiRuntimeDriver,
    /// `13`: EFI ROM image.
    EfiRom,
    /// `14`: Xbox.
    Xbox,
    /// `16`: Windows boot application.
    WindowsBootApplication,
    /// Any other value.
    Other(u16),
}

impl Subsystem {
    /// Decodes the raw field.
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        match value {
            0 => Self::Unknown,
            1 => Self::Native,
            2 => Self::WindowsGui,
            3 => Self::WindowsCui,
            5 => Self::Os2Cui,
            7 => Self::PosixCui,
            8 => Self::NativeWindows,
            9 => Self::WindowsCeGui,
            10 => Self::EfiApplication,
            11 => Self::EfiBootServiceDriver,
            12 => Self::EfiRuntimeDriver,
            13 => Self::EfiRom,
            14 => Self::Xbox,
            16 => Self::WindowsBootApplication,
            other => Self::Other(other),
        }
    }

    /// Whether this is one of the EFI subsystems (10 to 13).
    #[must_use]
    pub const fn is_efi(self) -> bool {
        matches!(
            self,
            Self::EfiApplication
                | Self::EfiBootServiceDriver
                | Self::EfiRuntimeDriver
                | Self::EfiRom
        )
    }
}

macro_rules! flag_word {
    (
        $(#[$meta:meta])*
        $name:ident($int:ty) {
            $( $(#[$fmeta:meta])* $flag:ident = $value:expr; )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub $int);

        impl $name {
            $( $(#[$fmeta])* pub const $flag: $int = $value; )*

            /// Whether every bit of `flag` is set.
            #[must_use]
            pub const fn contains(self, flag: $int) -> bool {
                self.0 & flag == flag
            }

            /// The names of the known flags that are set.
            #[must_use]
            pub fn names(self) -> Vec<&'static str> {
                let mut names = Vec::new();
                $( if self.contains(Self::$flag) { names.push(stringify!($flag)); } )*
                names
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:#x}, {:?})", stringify!($name), self.0, self.names())
            }
        }
    };
}

flag_word! {
    /// The COFF `Characteristics` field.
    FileCharacteristics(u16) {
        /// Relocation information was stripped.
        RELOCS_STRIPPED = 0x0001;
        /// The image is valid and can be run.
        EXECUTABLE_IMAGE = 0x0002;
        /// The image can handle addresses above 2 GiB.
        LARGE_ADDRESS_AWARE = 0x0020;
        /// 32-bit machine.
        MACHINE_32BIT = 0x0100;
        /// Debugging information was removed.
        DEBUG_STRIPPED = 0x0200;
        /// A system file, such as a driver.
        SYSTEM = 0x1000;
        /// A dynamic-link library.
        DLL = 0x2000;
        /// Run only on a uniprocessor machine.
        UP_SYSTEM_ONLY = 0x4000;
    }
}

impl FileCharacteristics {
    /// `IMAGE_FILE_DLL` is set.
    #[must_use]
    pub const fn is_dll(self) -> bool {
        self.contains(Self::DLL)
    }

    /// `IMAGE_FILE_EXECUTABLE_IMAGE` is set.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.contains(Self::EXECUTABLE_IMAGE)
    }

    /// `IMAGE_FILE_LARGE_ADDRESS_AWARE` is set.
    #[must_use]
    pub const fn is_large_address_aware(self) -> bool {
        self.contains(Self::LARGE_ADDRESS_AWARE)
    }

    /// `IMAGE_FILE_SYSTEM` is set.
    #[must_use]
    pub const fn is_system(self) -> bool {
        self.contains(Self::SYSTEM)
    }
}

flag_word! {
    /// The optional header `DllCharacteristics` field.
    DllCharacteristics(u16) {
        /// 64-bit high-entropy ASLR.
        HIGH_ENTROPY_VA = 0x0020;
        /// Can be relocated at load time (ASLR).
        DYNAMIC_BASE = 0x0040;
        /// Code integrity checks are enforced.
        FORCE_INTEGRITY = 0x0080;
        /// Compatible with data execution prevention.
        NX_COMPAT = 0x0100;
        /// Isolation-aware, but do not isolate.
        NO_ISOLATION = 0x0200;
        /// Uses no structured exception handling.
        NO_SEH = 0x0400;
        /// Do not bind the image.
        NO_BIND = 0x0800;
        /// Must run in an app container.
        APPCONTAINER = 0x1000;
        /// A WDM driver.
        WDM_DRIVER = 0x2000;
        /// Supports control flow guard.
        GUARD_CF = 0x4000;
        /// Terminal-server aware.
        TERMINAL_SERVER_AWARE = 0x8000;
    }
}

flag_word! {
    /// A section header's `Characteristics` field.
    SectionCharacteristics(u32) {
        /// Contains executable code.
        CNT_CODE = 0x0000_0020;
        /// Contains initialised data.
        CNT_INITIALIZED_DATA = 0x0000_0040;
        /// Contains uninitialised data.
        CNT_UNINITIALIZED_DATA = 0x0000_0080;
        /// Can be discarded as needed.
        MEM_DISCARDABLE = 0x0200_0000;
        /// Cannot be cached.
        MEM_NOT_CACHED = 0x0400_0000;
        /// Is not pageable.
        MEM_NOT_PAGED = 0x0800_0000;
        /// Can be shared in memory.
        MEM_SHARED = 0x1000_0000;
        /// Can be executed as code.
        MEM_EXECUTE = 0x2000_0000;
        /// Can be read.
        MEM_READ = 0x4000_0000;
        /// Can be written to.
        MEM_WRITE = 0x8000_0000;
    }
}

/// The index of an optional header data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DataDirectoryKind {
    /// 0: export table.
    Export,
    /// 1: import table.
    Import,
    /// 2: resource table.
    Resource,
    /// 3: exception table.
    Exception,
    /// 4: attribute certificate table. Its address is a **file offset**,
    /// not an RVA.
    Security,
    /// 5: base relocation table.
    BaseRelocation,
    /// 6: debug directory.
    Debug,
    /// 7: architecture (reserved, zero).
    Architecture,
    /// 8: global pointer register.
    GlobalPtr,
    /// 9: thread-local storage table.
    Tls,
    /// 10: load configuration table.
    LoadConfig,
    /// 11: bound import table.
    BoundImport,
    /// 12: import address table.
    Iat,
    /// 13: delay-load import descriptors.
    DelayImport,
    /// 14: CLR runtime header (.NET).
    ClrRuntime,
    /// 15: reserved.
    Reserved,
}

impl DataDirectoryKind {
    /// All 16 kinds, in index order.
    pub const ALL: [Self; 16] = [
        Self::Export,
        Self::Import,
        Self::Resource,
        Self::Exception,
        Self::Security,
        Self::BaseRelocation,
        Self::Debug,
        Self::Architecture,
        Self::GlobalPtr,
        Self::Tls,
        Self::LoadConfig,
        Self::BoundImport,
        Self::Iat,
        Self::DelayImport,
        Self::ClrRuntime,
        Self::Reserved,
    ];

    /// The index in the data directory array.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_round_trips() {
        for raw in [
            0, 0x14c, 0x8664, 0xaa64, 0xa641, 0xa64e, 0x1c4, 0x1c0, 0x1c2, 0x3a64, 0x200, 0xebc,
            0x1234,
        ] {
            assert_eq!(Machine::from_raw(raw).raw(), raw);
        }
        assert_eq!(Machine::from_raw(0x1234), Machine::Other(0x1234));
    }

    #[test]
    fn subsystems() {
        assert_eq!(Subsystem::from_raw(1), Subsystem::Native);
        assert_eq!(Subsystem::from_raw(10), Subsystem::EfiApplication);
        assert!(Subsystem::from_raw(12).is_efi());
        assert!(!Subsystem::WindowsGui.is_efi());
        assert_eq!(Subsystem::from_raw(99), Subsystem::Other(99));
    }

    #[test]
    fn flag_words() {
        let c = FileCharacteristics(0x2022);
        assert!(c.is_dll() && c.is_executable() && c.is_large_address_aware());
        assert!(!c.is_system());
        assert_eq!(
            c.names(),
            ["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE", "DLL"]
        );
        let d = DllCharacteristics(0x4160);
        assert!(d.contains(DllCharacteristics::GUARD_CF));
        assert!(d.contains(DllCharacteristics::NX_COMPAT | DllCharacteristics::DYNAMIC_BASE));
        assert!(!d.contains(DllCharacteristics::APPCONTAINER));
        assert_eq!(
            format!("{:?}", FileCharacteristics(0x1000)),
            "FileCharacteristics(0x1000, [\"SYSTEM\"])"
        );
    }

    #[test]
    fn data_directory_indices() {
        for (i, kind) in DataDirectoryKind::ALL.iter().enumerate() {
            assert_eq!(kind.index(), i);
        }
    }
}

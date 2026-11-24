//! The extended key usage (EKU) catalogue (#49): known EKU object
//! identifiers and their friendly names.
//!
//! Unknown EKUs are kept as raw OIDs; the catalogue only adds names.
//! [`Eku::os_policy_value`] gives the form OS-native code integrity policy
//! uses for an EKU's `Value` attribute.

#![forbid(unsafe_code)]

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::asn1::ObjectId;

/// A known EKU: its OID content octets and friendly name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KnownEku {
    /// The OID, as DER content octets.
    pub oid: &'static [u8],
    /// The dotted-decimal form.
    pub dotted: &'static str,
    /// The friendly name.
    pub name: &'static str,
}

impl KnownEku {
    /// The OID.
    #[must_use]
    pub fn id(&self) -> ObjectId {
        ObjectId::from_der(self.oid)
    }
}

/// 2.5.29.37.0 `anyExtendedKeyUsage`.
pub const ANY: KnownEku = KnownEku {
    oid: &[0x55, 0x1d, 0x25, 0x00],
    dotted: "2.5.29.37.0",
    name: "Any Purpose",
};
/// 1.3.6.1.5.5.7.3.1 TLS server authentication.
pub const SERVER_AUTH: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
    dotted: "1.3.6.1.5.5.7.3.1",
    name: "Server Authentication",
};
/// 1.3.6.1.5.5.7.3.2 TLS client authentication.
pub const CLIENT_AUTH: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02],
    dotted: "1.3.6.1.5.5.7.3.2",
    name: "Client Authentication",
};
/// 1.3.6.1.5.5.7.3.3 code signing.
pub const CODE_SIGNING: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03],
    dotted: "1.3.6.1.5.5.7.3.3",
    name: "Code Signing",
};
/// 1.3.6.1.5.5.7.3.4 email protection.
pub const EMAIL_PROTECTION: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04],
    dotted: "1.3.6.1.5.5.7.3.4",
    name: "Secure Email",
};
/// 1.3.6.1.5.5.7.3.8 time stamping.
pub const TIME_STAMPING: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08],
    dotted: "1.3.6.1.5.5.7.3.8",
    name: "Time Stamping",
};
/// 1.3.6.1.5.5.7.3.9 OCSP signing.
pub const OCSP_SIGNING: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09],
    dotted: "1.3.6.1.5.5.7.3.9",
    name: "OCSP Signing",
};
/// 1.3.6.1.5.5.7.3.36 document signing (RFC 9336).
pub const DOCUMENT_SIGNING: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x24],
    dotted: "1.3.6.1.5.5.7.3.36",
    name: "Document Signing",
};
/// 1.3.6.1.4.1.311.10.3.5 the OS vendor's hardware (driver) certification
/// EKU, which `CertifiedDriver` rules require.
pub const HARDWARE_CERTIFICATION: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x05],
    dotted: "1.3.6.1.4.1.311.10.3.5",
    name: "Hardware Driver Certification",
};
/// 1.3.6.1.4.1.311.10.3.6 OS component verification.
pub const OS_COMPONENT: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x06],
    dotted: "1.3.6.1.4.1.311.10.3.6",
    name: "OS Component Verification",
};
/// 1.3.6.1.4.1.311.10.3.12 document signing, the OS vendor's older OID.
pub const DOCUMENT_SIGNING_LEGACY: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x0c],
    dotted: "1.3.6.1.4.1.311.10.3.12",
    name: "Document Signing (legacy)",
};
/// 1.3.6.1.4.1.311.10.3.13 lifetime signing: signatures expire with the
/// certificate, timestamp or not (#50).
pub const LIFETIME_SIGNING: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x0d],
    dotted: "1.3.6.1.4.1.311.10.3.13",
    name: "Lifetime Signing",
};
/// 1.3.6.1.4.1.311.10.3.22 Protected Process Light verification.
pub const PROTECTED_PROCESS_LIGHT: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x16],
    dotted: "1.3.6.1.4.1.311.10.3.22",
    name: "Protected Process Light Verification",
};
/// 1.3.6.1.4.1.311.10.3.24 Protected Process verification.
pub const PROTECTED_PROCESS: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x03, 0x18],
    dotted: "1.3.6.1.4.1.311.10.3.24",
    name: "Protected Process Verification",
};
/// 1.3.6.1.4.1.311.61.1.1 kernel-mode code signing.
pub const KERNEL_MODE_CODE_SIGNING: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3d, 0x01, 0x01],
    dotted: "1.3.6.1.4.1.311.61.1.1",
    name: "Kernel Mode Code Signing",
};
/// 1.3.6.1.4.1.311.61.4.1 Early Launch Antimalware drivers.
pub const EARLY_LAUNCH_ANTIMALWARE: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3d, 0x04, 0x01],
    dotted: "1.3.6.1.4.1.311.61.4.1",
    name: "Early Launch Antimalware Driver",
};
/// 1.3.6.1.4.1.311.61.5.1 HAL extension.
pub const HAL_EXTENSION: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3d, 0x05, 0x01],
    dotted: "1.3.6.1.4.1.311.61.5.1",
    name: "HAL Extension",
};
/// 1.3.6.1.4.1.311.76.3.1 package store signing (packaged apps).
pub const STORE_SIGNING: KnownEku = KnownEku {
    oid: &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4c, 0x03, 0x01],
    dotted: "1.3.6.1.4.1.311.76.3.1",
    name: "Package Store Signing",
};

/// Every known EKU.
pub const CATALOGUE: [KnownEku; 18] = [
    ANY,
    SERVER_AUTH,
    CLIENT_AUTH,
    CODE_SIGNING,
    EMAIL_PROTECTION,
    TIME_STAMPING,
    OCSP_SIGNING,
    DOCUMENT_SIGNING,
    HARDWARE_CERTIFICATION,
    OS_COMPONENT,
    DOCUMENT_SIGNING_LEGACY,
    LIFETIME_SIGNING,
    PROTECTED_PROCESS_LIGHT,
    PROTECTED_PROCESS,
    KERNEL_MODE_CODE_SIGNING,
    EARLY_LAUNCH_ANTIMALWARE,
    HAL_EXTENSION,
    STORE_SIGNING,
];

/// The catalogue entry for `oid`, if it is a known EKU.
#[must_use]
pub fn lookup(oid: &ObjectId) -> Option<&'static KnownEku> {
    CATALOGUE.iter().find(|k| k.oid == oid.as_bytes())
}

/// One EKU of a certificate. Serialised as `{"oid", "name",
/// "os_policy_value"}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eku {
    /// The OID, known or not.
    pub oid: ObjectId,
    /// The friendly name, for a known EKU.
    pub name: Option<&'static str>,
}

impl Eku {
    /// Wraps `oid`, naming it if it is in the catalogue.
    #[must_use]
    pub fn new(oid: ObjectId) -> Self {
        let name = lookup(&oid).map(|k| k.name);
        Self { oid, name }
    }

    /// The EKU in the form OS-native code integrity policy writes in an
    /// `EKU` element's `Value`: the octet `01`, one length octet, then the
    /// OID's DER content octets, in uppercase hex. For code signing,
    /// `01082B06010505070303` is `01`, `08`, `2B06010505070303`. `None` for an OID of
    /// more than 127 content octets, which one length octet cannot hold.
    #[must_use]
    pub fn os_policy_value(&self) -> Option<String> {
        let body = self.oid.as_bytes();
        let len = u8::try_from(body.len()).ok().filter(|l| *l < 0x80)?;
        let mut out = format!("01{len:02X}");
        for b in body {
            out.push_str(&format!("{b:02X}"));
        }
        Some(out)
    }
}

impl Serialize for Eku {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Eku", 3)?;
        st.serialize_field("oid", &self.oid)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("os_policy_value", &self.os_policy_value())?;
        st.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_entries_are_consistent() {
        for (i, known) in CATALOGUE.iter().enumerate() {
            assert_eq!(known.id().to_string(), known.dotted, "{}", known.name);
            assert_eq!(ObjectId::from_dotted(known.dotted), Some(known.id()));
            assert!(
                CATALOGUE.iter().skip(i + 1).all(|k| k.oid != known.oid),
                "duplicate {}",
                known.dotted
            );
            assert_eq!(lookup(&known.id()), Some(known));
        }
    }

    #[test]
    fn unknown_ekus_keep_their_oid() {
        let oid = ObjectId::from_dotted("1.2.3.4.5.6").unwrap();
        let eku = Eku::new(oid.clone());
        assert_eq!(eku, Eku { oid, name: None });
    }

    #[test]
    fn os_policy_values() {
        // Values as OS-native policy files write them.
        let value = |k: KnownEku| Eku::new(k.id()).os_policy_value().unwrap();
        assert_eq!(value(HARDWARE_CERTIFICATION), "010A2B0601040182370A0305");
        assert_eq!(value(OS_COMPONENT), "010A2B0601040182370A0306");
        assert_eq!(value(EARLY_LAUNCH_ANTIMALWARE), "010A2B0601040182373D0401");
        assert_eq!(value(CODE_SIGNING), "01082B06010505070303");
        let long = ObjectId::from_der(&[0x2b; 128]);
        assert_eq!(Eku::new(long).os_policy_value(), None);
        let edge = ObjectId::from_der(&[0x2b; 127]);
        assert!(
            Eku::new(edge)
                .os_policy_value()
                .unwrap()
                .starts_with("017F")
        );
    }
}

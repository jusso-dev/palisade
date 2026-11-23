//! Authenticode for PE images.
//!
//! - [`hash`]: the Authenticode image hash (#47), which identifies a PE file
//!   independently of its embedded signature.
//!
//! Parsing and verifying the signatures themselves (PKCS#7 / CMS) is #48.

#![forbid(unsafe_code)]

pub mod hash;

pub use hash::{
    AuthenticodeError, AuthenticodeHashes, AuthenticodeStatus, HashRanges, HashScenario,
    NonConformance, RangeHasher, authenticode_hashes, hash_pe,
};

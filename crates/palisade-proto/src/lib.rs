#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
// This crate decodes untrusted wire messages, so unchecked indexing is flagged.
#![warn(clippy::indexing_slicing)]

pub mod comms;
pub mod events;
pub mod mapping;
pub mod pki;
pub mod policy_bundle;
pub mod sntp;

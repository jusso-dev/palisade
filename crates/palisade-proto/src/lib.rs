#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
// This crate decodes untrusted wire messages, so unchecked indexing is flagged.
#![warn(clippy::indexing_slicing)]

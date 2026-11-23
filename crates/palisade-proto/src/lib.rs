#![doc = include_str!("../README.md")]
// This crate decodes untrusted wire messages, so unchecked indexing is flagged.
#![warn(clippy::indexing_slicing)]

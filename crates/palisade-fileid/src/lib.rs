#![doc = include_str!("../README.md")]
// This crate parses untrusted files, so unchecked indexing is flagged in
// library code. Unit tests index fixtures they built themselves.
#![warn(clippy::indexing_slicing)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod authenticode;
pub mod hash;
pub mod pe;

//! Windows OS backends (ADR 0003). Compiled only on Windows with the
//! off-by-default `os-trust` feature, so no other target and no crate that
//! does not opt in ever builds it.
//!
//! - [`fsctx`]: file-system context reads (#54).
//! - [`file`](mod@file): the file backend for hashing and the hash cache (#46): open
//!   flags, file IDs and USNs, timestamps and attributes, the
//!   [`crate::hash::FileStamp`] implementation, memory-mapped and buffered
//!   reads, and alternate data stream hashing.
//! - [`trust`]: the OS trust-verification cross-check (#48).
//! - `sys` (private): the file and volume calls themselves, wrapped once.
//!
//! This is the only part of the crate that may contain `unsafe` code (ADR
//! 0011). Each submodule that calls the Windows API says
//! `#![allow(unsafe_code)]` and is listed in `unsafe-allowlist.txt`; the
//! others, and this file, keep the workspace's `deny`. Every `unsafe` block
//! has a `// SAFETY:` comment, and each wrapper has tests that run on the
//! Windows CI runners.

pub mod file;
pub mod fsctx;
mod sys;
pub mod trust;

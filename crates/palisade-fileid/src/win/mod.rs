//! Windows OS backends (ADR 0003). Compiled only on Windows with the
//! off-by-default `os-trust` feature, so no other target and no crate that
//! does not opt in ever builds it.
//!
//! - [`fsctx`]: file-system context reads (#54).
//! - [`file`](mod@file): the file backend for hashing and the hash cache (#46): open
//!   flags, file IDs and USNs, timestamps and attributes, the
//!   [`crate::hash::FileStamp`] implementation, memory-mapped and buffered
//!   reads, and alternate data stream hashing.
//! - [`journal`]: a volume's change journal and master file table, and
//!   opening a file by its ID, for the file inventory (#60).
//! - [`links`]: reparse points and hard links of real files (#54).
//! - [`paths`]: the OS path forms (NT, volume GUID, long, mapped-drive
//!   UNC, DFS target) and an [`crate::fsctx::FsContext`] with its volume
//!   (#54).
//! - [`access`]: owners, writability of real paths, the OS access-check
//!   cross-check and a folder source for `enumerate_user_writable_dirs`
//!   (#54).
//! - [`security`]: security descriptors, account names and the OS access
//!   check (#54).
//! - [`packages`]: installed packages of a family for the current user,
//!   and app execution alias resolution against them (#333).
//! - [`package_manager`]: every user's installed packages, with the stub
//!   flag and each package's users, from the package manager's WinRT
//!   interface (#333).
//! - [`trust`]: the OS trust-verification cross-check (#48).
//! - [`volume`]: the volume a file is on (drive, bus, hot-plug, OS volume)
//!   and the per-directory case-sensitivity flag (#54).
//! - `sys` (private): the file and volume calls themselves, wrapped once.
//!
//! This is the only part of the crate that may contain `unsafe` code (ADR
//! 0011). Each submodule that calls the Windows API says
//! `#![allow(unsafe_code)]` and is listed in `unsafe-allowlist.txt`; the
//! others, and this file, keep the workspace's `deny`. Every `unsafe` block
//! has a `// SAFETY:` comment, and each wrapper has tests that run on the
//! Windows CI runners.

pub mod access;
pub mod file;
pub mod fsctx;
pub mod journal;
pub mod links;
pub mod package_manager;
pub mod packages;
pub mod paths;
pub mod security;
mod sys;
pub mod trust;
pub mod volume;

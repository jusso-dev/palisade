#![doc = include_str!("../README.md")]
// ADR 0011: `unsafe` code only in `ffi` (Windows only), which is on
// `unsafe-allowlist.txt`. The root cannot `forbid` it, since `forbid`
// cannot be relaxed, so it keeps the workspace's `deny`, and every other
// module forbids it at its own root.

pub mod cli;
pub mod config;
#[cfg(windows)]
mod ffi;
pub mod host;
pub mod lifecycle;
pub mod platform;
#[cfg(windows)]
pub mod service;
#[cfg(feature = "test-util")]
pub mod simulate;
pub mod subsystem;
pub mod supervisor;

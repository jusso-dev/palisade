#![doc = include_str!("../README.md")]
// No FFI module exists yet: the service control manager is reached through a
// safe wrapper crate, so the whole crate forbids unsafe code (ADR 0011).
#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod host;
pub mod lifecycle;
pub mod platform;
#[cfg(windows)]
pub mod service;
#[cfg(feature = "test-util")]
pub mod simulate;
pub mod subsystem;
pub mod supervisor;

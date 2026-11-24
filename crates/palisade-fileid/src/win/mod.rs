//! Windows OS backends (ADR 0003). Compiled only on Windows with the
//! off-by-default `os-trust` feature, so no other target and no crate that
//! does not opt in ever builds it.
//!
//! - [`fsctx`]: file-system context reads (#54).

#![forbid(unsafe_code)]

pub mod fsctx;

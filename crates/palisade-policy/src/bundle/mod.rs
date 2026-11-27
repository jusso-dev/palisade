//! The canonical compiled policy bundle (#43).
//!
//! A bundle is the one artefact that the agent enforces, the simulator
//! evaluates and #225 signs, so it has exactly one byte encoding for a given
//! content. This module builds it in layers:
//!
//! - [`cbor`]: a small, strict subset of CBOR (RFC 8949) in the core
//!   deterministic encoding of §4.2. The encoder writes only canonical
//!   bytes, and the decoder accepts only canonical bytes, so decoding and
//!   encoding again always gives the input back.

pub mod cbor;

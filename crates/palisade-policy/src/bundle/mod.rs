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
//! - [`keys`]: the stable registry of integer keys that stand for field and
//!   variant names, each critical or ignorable.
//! - [`serial`]: the policy model through serde as CBOR values, with
//!   registered keys in place of names and text in NFC.
//! - [`format`](mod@format): the bundle itself, a header that decodes on its own and a
//!   body in canonical order, with the bundle hash and the decision hash.

pub mod cbor;
pub mod format;
pub mod keys;
pub mod serial;

pub use format::{
    AgentVersion, Body, BundleError, BundleLimits, Header, InlineLibrary, PolicyBundle, SetContent,
    SourceRevisions, Target, TargetScope, bundle_hash, decode_header,
};

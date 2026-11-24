#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod condition;
pub mod context;
pub mod dsl;
pub mod facts;
pub mod model;
pub mod ops;
pub mod schema;
pub mod validate;

#[cfg(test)]
mod tests;

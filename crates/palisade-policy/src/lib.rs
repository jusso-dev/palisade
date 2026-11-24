#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod condition;
pub mod context;
pub mod decision;
pub mod dsl;
pub mod evaluate;
pub mod facts;
pub mod hierarchy;
pub mod library;
pub mod mode;
pub mod model;
pub mod ops;
pub mod precedence;
pub mod schema;
pub mod validate;

#[cfg(test)]
mod tests;

#![doc = include_str!("../README.md")]
// Kernel code has no standard library. Tests still link `std` for the harness.
#![cfg_attr(not(test), no_std)]

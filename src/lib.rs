#![cfg_attr(feature = "doc_auto_cfg", feature(doc_auto_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "disabler")]
pub mod disabler;

pub mod patch;
pub mod spider;

mod vm;

/// Re-export of the `iced_x86` crate.
pub use iced_x86;
/// Re-export of the `pelite` crate.
pub use pelite;

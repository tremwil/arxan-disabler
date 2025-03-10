#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "ffi")]
pub mod ffi;

pub mod patch;
pub mod spider;
pub mod vm;

pub use iced_x86;
pub use pelite;

#![no_std]
#![feature(allocator_api, generic_const_exprs)]
#![allow(incomplete_features)]

extern crate alloc;

pub mod cognitive;
pub mod formal;
pub mod holobus;
pub mod syscall;

pub use cognitive::*;

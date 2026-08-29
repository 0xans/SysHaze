#![cfg_attr(not(feature = "std"), no_std)]

mod ssn;
pub mod hashes;
mod resolver;
mod types;

#[cfg(feature = "std")]
extern crate std;

/**
 * Initialize the syscall engine
 * */
pub unsafe fn initialize() -> bool {
    ssn::initialize(core::ptr::null_mut())
}
#![cfg_attr(not(feature = "std"), no_std)]

pub mod ssn;
pub mod hashes;
pub mod resolver;
pub mod types;
pub mod invoke;
pub mod macros;
pub mod nt;

#[cfg(feature = "std")]
extern crate std;

use core::ffi::c_void;
/**
 * Initialize the syscall engine
 * */
pub unsafe fn initialize() -> bool { unsafe {
    ssn::initialize(core::ptr::null_mut())
}}

/**
 * Get a reference to the global syscall table
 * */
pub unsafe fn syscall_table() -> &'static ssn::SyscallTable { unsafe {
    ssn::syscall_table()
}}

/**
 * Compute the DJB2 hash of a function name (ASCII, case insensitive)
 * */
pub const fn hash_function_name(name: &str) -> u32 {
    hashes::hash_str(name)
}

/**
 * Compute the DJB2 hash of a UTF 16 module name (case insensitive)
 * */
pub const fn hash_module_name_wide(name: &[u16]) -> u32 {
    hashes::hash_module_wide(name)
}

/**
 * Resolve a loaded module by its wide name hash
 * */
pub unsafe fn resolve_module(hash: u32) -> *mut c_void { unsafe {
    resolver::ldr_module_search(hash)
}}

/**
 * Resolve a single export from a module by tis function name hash
 * */
pub unsafe fn resolve_function(module: *mut c_void, hash: u32) -> *mut c_void { unsafe {
    resolver::ldr_function_by_hash(module, hash)
}}


/**
 * Resolve an additional syscall by hash after initialization
 * */
unsafe fn resolve_extra_ssn(hash: u32) -> bool { unsafe {
    ssn::resolve_ssn(hash)
}}
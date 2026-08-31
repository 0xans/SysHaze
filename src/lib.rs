//! # SysHaze - Rust indirect syscall engine
//! 
//! Runtime SSN resolution with obfuscated indirect trampolines and per-function
//! `syscall;ret` addresses. No static tables, no versions dependencies, and no `GetProcAddress`
//!
//! ## Architecture
//!
//! 1. **PEB Walk** (`resolver`): finds ntdll base without any API calls
//! 2. **Export Parsing** (`resolver`): walks PE export table, matches by DJB2 hash
//! 3. **SSN Extraction** (`ssn`): reads `mov r10,rcx; mov eax,<SSN>` pattern
//! 4. **Gadget Search** (`ssn`): locates per-function `syscall;ret` (0F 05 C3)
//! 5. **Halo's Gate** (`ssn`): recovers hooked stubs via +-500 neighbor walk
//! 6. **Trampoline** (`invoke`): obfuscated `xchg rcx,r10` + `push;ret` dispatch

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate std;

pub mod ssn;
pub mod hashes;
pub mod resolver;
pub mod types;
pub mod invoke;
pub mod nt;
#[macro_use]
pub mod macros;

use core::ffi::c_void;

/**
 * Initialize the syscall engine
 * 
 * This is the main entry point, and it dose the following:
 *  1. Find ntdll by waling the PEB
 *  2. Parse its export table
 *  3. Extract SSNs and per-function `syscall;ret` address for roughly r0 common native functions
 *  
 * This function must be called once at startup bevore using any `nt::` wrappers or `indirect_syscall!`
 * 
 * Returns true if initialization was successfull.
 * */
pub unsafe fn initialize() -> bool { unsafe {
    ssn::initialize(core::ptr::null_mut())
}}

/**
 * Get a reference to the global syscall table
 * 
 * The table maps function hashes -> `SyscallEntry` (SSN, Syscall Address)
 * 
 * **NOTE**:
 * `initialize()` must have been called first
 * */
pub unsafe fn syscall_table() -> &'static ssn::SyscallTable { unsafe {
    ssn::syscall_table()
}}

/**
 * Compute the DJB2 hash of a function name (ASCII, case insensitive)
 * 
 * Use this to get hashes for functions not in the built in constants
 * 
 * ## Example 
 * ```
 *  let hash = syshaze::hash_function_name("NtIdkFucntion")
 * ```
 * */
pub const fn hash_function_name(name: &str) -> u32 {
    hashes::hash_str(name)
}

/**
 * Compute the DJB2 hash of a UTF 16 module name (case insensitive)
 * 
 * ## Example 
 * ```
 *  let hash = syshaze::hash_module_name_wide(&[0x6E, 0x74, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C]);
 * assert_eq!(hash, engine::hashes::NTDLL_HASH);
 * ```
 * */
pub const fn hash_module_name_wide(name: &[u16]) -> u32 {
    hashes::hash_module_wide(name)
}

/**
 * Resolve a loaded module by its wide name hash
 * 
 * Returns the module base address, or null if not found
 * 
 * **Safety**:
 * Must be called from a valid Windows process context.
 * */
pub unsafe fn resolve_module(hash: u32) -> *mut c_void { unsafe {
    resolver::ldr_module_search(hash)
}}

/**
 * Resolve a single export from a module by tis function name hash
 * 
 * Returns the module base address, or null if not found
 * 
 * **Safety**:
 * `module` must be a valid module base address
 * */
pub unsafe fn resolve_function(module: *mut c_void, hash: u32) -> *mut c_void { unsafe {
    resolver::ldr_function_by_hash(module, hash)
}}


/**
 * Resolve an additional syscall by hash after initialization
 * 
 * This is useful for adding syscalls that are not in the default set
 * 
 * ## Example 
 * ```ignore
 *  let hash = syshaze::hash_function_name("NtIdkFucntion");
 * unsafe { syshaze::resolve_extra_ssn(hash); }
 * // Not it should be available in the table
 * ```
 * **NOTE**:
 * `initialize()` must have been called first
 * */
unsafe fn resolve_extra_ssn(hash: u32) -> bool { unsafe {
    ssn::resolve_ssn(hash)
}}
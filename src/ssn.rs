//! # SSN extraction and hooked stub recovery
//! 
//! This module resolve SSNs at runtime by:
//! 1. Finding an Nt function address in ntdll export table
//! 2. Reading the `mov r10, rdx; mov eax, <SSN>` byte pattern from the stub
//! 3. Locating the `syscall; ret` (0F 05 C3) gadget within that stub
//!
//! If a stub appears hooked, it uses **Halo's Gate** to find an unhooked one,   
//! then compute the target SSN by offset 
//! ## Architecture
//!
//! The engine maintains a global table of resolved `SyscallEntry` values.
//! Each entry hold a SSN and the addres of the `syscall;ret` gadget from that specific function stub

use crate::hashes;
use crate::resolver;
use crate::types::{SyscallEntry, HANDLE};
use core::cell::UnsafeCell;
use core::ffi::c_void;


const RET_OPCODE: u8 = 0xC3;
const SYSCALL_SEARCH_RANGE: isize = 32;
const NEIGHBOUR_SEARCH_LIMIT: u32 = 500;

// Maximum number of syscall entries we can hold
// This is generous btw, Windows has around 470 syscalls total, so yah
pub const MAX_ENTRIES: usize = 64;

#[cfg(target_arch = "x86_64")]
mod arch {
    /// x64 Nt stub pattern: `4C 8B D1 B8 xx xx 00 00` (mov r10,rcx; mov eax,SSN)
    pub const MOV_R10_RCX_MOV_EAX: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
    pub const SSN_LOW_OFFSET: isize = 4;
    pub const SSN_HIGH_OFFSET: isize = 5;
    pub const STUB_SIZE: u32 = 0x12;
}

#[cfg(target_arch = "x86")]
mod arch {
    pub const MOV_EAX: [u8; 1] = [0xB8];
    pub const SSN_LOW_OFFSET: isize = 1;
    pub const SSN_HIGH_OFFSET: isize = 2;
    pub const SYSCALL_OPCODE: u16 = 0x050F;
    pub const STUB_SIZE: u32 = 0x0E;
}

// A resolved syscall entry paired with its hash for search
#[repr(C)]
#[derive(Clone, Copy)]
struct TableSlot {
    hash: u32,
    entry: SyscallEntry
}

impl TableSlot {
    const fn empty() -> Self {
        Self {
            hash: 0,
            entry: SyscallEntry::empty(),
        }
    }
}

pub struct SyscallTable {
    slots: [TableSlot; MAX_ENTRIES],
    count: usize,
    ntdll: HANDLE,
}

/**
 * The global syscall table holds resovled SSN and syscall address pairs
 * 
 * Initialized once at start up then read only
 * */
impl SyscallTable {
    const fn new() -> Self {
        Self {
            slots: [TableSlot::empty(); MAX_ENTRIES],
            count: 0,
            ntdll: core::ptr::null_mut(),
        }
    }

    /**
     * Search a resolved entry by its function hash
     * 
     * Return None if the hash was not resolved or resolution failed
     * */
    pub fn get(&self, hash: u32) -> Option<&SyscallEntry> {
        for i in 0..self.count {
            if self.slots[i].hash == hash {
                let entry = &self.slots[i].entry;
                if entry.is_resolved() {
                    return Some(entry);
                }
                return None;
            }
        }
        None
    }

    // Get the resolved ntdll base address.
    pub fn ntdll(&self) -> HANDLE {
        self.ntdll
    }

    // Get the number of resolved etries.
    pub fn len(&self) -> usize {
        self.count
    }

    // Check if the table is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}


// Wrapper to make SyscallInfo usable in a static.
// Safety: initialized once then read only. *single threaded*
struct SyscallCell(UnsafeCell<SyscallTable>);
unsafe impl Sync for SyscallCell {}

static GLOBAL_TABLE: SyscallCell = SyscallCell(UnsafeCell::new(SyscallTable::new()));


/**
 * Initialize the syscall engine
 * 
 * Resolved ntdll from the PEB then resolved a default set of common native syscall SSNs and 
 * `syscall;ret` address for each function
 * 
 * Call this one at ur program startup before using any `nt::` wrappers or calling `resolved_)ssn()`
 * 
 * # Arguments
 * `ntdll`: Optional handle to ntdll. If null the engine will find it vai PEB walk.
 * 
 * # Return 
 * `true` if initialization was successfull
 *  
 * # Safety
 * Must be called from a valid Windows process context
 * */
pub unsafe fn initialize(mut ntdll: *mut c_void) -> bool { unsafe {
    let table = &mut *GLOBAL_TABLE.0.get();

    if ntdll.is_null() {
        ntdll = resolver::ldr_module_search(hashes::NTDLL_HASH);
        if ntdll.is_null() {
            return false;
        }
    }
    table.ntdll = ntdll;

    // Resolve some of a common syscalls
    let default_hashes: &[u32] = &[
        // Process
        hashes::NTOPENPROCESS_HASH,
        hashes::NTTERMINATEPROCESS_HASH,
        hashes::NTQUERYINFORMATIONPROCESS_HASH,
        hashes::NTCREATEPROCESSEX_HASH,
        hashes::NTGETNEXTPROCESS_HASH,
        // Memory
        hashes::NTALLOCATEVIRTUALMEMORY_HASH,
        hashes::NTWRITEVIRTUALMEMORY_HASH,
        hashes::NTREADVIRTUALMEMORY_HASH,
        hashes::NTPROTECTVIRTUALMEMORY_HASH,
        // Thread
        hashes::NTCREATETHREADEX_HASH,
        hashes::NTRESUMETHREAD_HASH,
        hashes::NTQUEUEAPCTHREAD_HASH,
        hashes::NTGETCONTEXTTHREAD_HASH,
        hashes::NTSETCONTEXTTHREAD_HASH,
        hashes::NTSETINFORMATIONTHREAD_HASH,
        // Synchronization
        hashes::NTWAITFORSINGLEOBJECT_HASH,
        hashes::NTDELAYEXECUTION_HASH,
        // Handle
        hashes::NTCLOSE_HASH,
        hashes::NTDUPLICATEOBJECT_HASH,
        // File I/O
        hashes::NTCREATEFILE_HASH,
        hashes::NTWRITEFILE_HASH,
        hashes::NTREADFILE_HASH,
        hashes::NTSETINFORMATIONFILE_HASH,
        hashes::NTDELETEFILE_HASH,
        hashes::NTQUERYDIRECTORYFILE_HASH,
        hashes::NTQUERYVOLUMEINFORMATIONFILE_HASH,
        // Sections
        hashes::NTCREATESECTION_HASH,
        hashes::NTMAPVIEWOFSECTION_HASH,
        hashes::NTUNMAPVIEWOFSECTION_HASH,
        // System info
        hashes::NTQUERYSYSTEMINFORMATION_HASH,
        // Token
        hashes::NTOPENPROCESSTOKEN_HASH,
        hashes::NTQUERYINFORMATIONTOKEN_HASH,
        hashes::NTDUPLICATETOKEN_HASH,
        hashes::NTOPENTHREADTOKEN_HASH,
        hashes::NTADJUSTPRIVILEGESTOKEN_HASH,
        // I/O Completion
        hashes::NTSETIOCOMPLETION_HASH,
        hashes::NTQUERYINFORMATIONWORKERFACTORY_HASH,
        // Registry
        hashes::NTCREATEKEY_HASH,
        hashes::NTSETVALUEKEY_HASH,
        hashes::NTOPENKEY_HASH,
        hashes::NTQUERYVALUEKEY_HASH,
        hashes::NTDELETEKEY_HASH,
        // Driver
        hashes::NTLOADDRIVER_HASH,
        hashes::NTUNLOADDRIVER_HASH,
    ];

    for &hash in default_hashes {
        if table.count >= MAX_ENTRIES {
            break;
        }
        resolve_ssn_internal(table, ntdll, hash);
    }

    // Verify at least NtClose resolved
    table.get(hashes::NTCLOSE_HASH).is_some()
}}


/**
 * Resolve a single additional syscall by its function name hash
 * 
 * Use this to add syscalls beyond the default set after `initialize()`
 * 
 * # Example
 * ```ignore
 * let hash = syshaze::hashes::hash_str("NtSomeFunction");
 * unsafe { syshaze::ssn::resolve_ssn(hash) }
 * let entry = syshaze::ssn::syscall_table.get(hash);
 * ```
 * # Safety
 * `initialize()` must have been called first
 * */
pub unsafe fn resolve_ssn(hash: u32) -> bool { unsafe {
    let table = &mut *GLOBAL_TABLE.0.get();
    if table.ntdll.is_null() {
        return false;
    }

    // Check if already resolved 
    if table.get(hash).is_some() {
        return true;
    }

    resolve_ssn_internal(table, table.ntdll, hash)
}}


unsafe fn resolve_ssn_internal(table: &mut SyscallTable, ntdll: HANDLE, hash: u32) -> bool { unsafe {
    if table.count >= MAX_ENTRIES {
        return false;
    }

    let address = resolver::ldr_function_by_hash(ntdll, hash);
    if address.is_null() {
        return false;
    }

    let slot = &mut table.slots[table.count];
    slot.hash = hash;
    let success = extract_syscall_info(
        address,
        true,
        Some(&mut slot.entry.ssn),
        Some(&mut slot.entry.syscall_addr),
    );

    if success && slot.entry.is_resolved() {
        table.count += 1;
        true
    } else {
        *slot = TableSlot::empty();
        false
    }
}}


/**
 * Extract the SSn and `syscall;ret` address from a Nt API stub
 * 
 * On x64 looks for the byte pattern `4C 8B D1 B8 xx xx 00 00` (mov r10,rcx; mov eax,SSN)
 * then search forward for `0F 05 C3` (syscall;ret)
 * 
 * If the stub appears hooked, optionally tries Halo's Gate neighor walk to recover the correct SSN
 * */
unsafe fn extract_syscall_info(function: *mut c_void, resolve_hooked: bool, mut ssn: Option<&mut u16>, syscall_address: Option<&mut *mut c_void>) -> bool { unsafe {
    if function.is_null() {
        return false;
    }
    if ssn.is_none() && syscall_address.is_none() {
        return false;
    }

    let mut offset: isize = 0;
    let mut success = false;

    loop {
        if *(function as *const u8).offset(offset) == RET_OPCODE {
            break;
        }

        #[cfg(target_arch = "x86_64")]
        {
            if *(function as *const [u8; 4]).offset(offset) == arch::MOV_R10_RCX_MOV_EAX {
                if let Some(ssn_vale) = ssn.as_deref_mut() {
                    let low = *(function as *const u8).offset(offset + arch::SSN_LOW_OFFSET);
                    let high = *(function as *const u8).offset(offset + arch::SSN_HIGH_OFFSET);
                    *ssn_vale = (high as u16) << 8 | low as u16;
                    success = true;
                }

                // Search for the syscall;reg gadget (0F 05 C3)
                if let Some(addr_out) = syscall_address {
                    *addr_out = core::ptr::null_mut();
                    for i in 0..SYSCALL_SEARCH_RANGE {
                        let candidate = (function as *const u8).offset(offset + i);
                        if *candidate == 0x0F 
                            && *candidate.offset(1) == 0x05 
                            && *candidate.offset(2) == RET_OPCODE 
                        {
                            *addr_out = candidate as *mut c_void;
                            success = true;
                            break;
                        }
                    }
                }
                break;
            }
        } 

        #[cfg(target_arch = "x86")]
        {
            if *(function as *const u8).offset(offset) == arch::MOV_EAX[0] {
                if let Some(ssn_val) = ssn.as_deref_mut() {
                    let low = *(function as *const u8).offset(offset + arch::SSN_LOW_OFFSET);
                    let high = *(function as *const u8).offset(offset + arch::SSN_HIGH_OFFSET);
                    *ssn_val = (high as u16) << 8 | low as u16;
                    success = true;
                }
                if let Some(addr_out) = syscall_address {
                    *addr_out = core::ptr::null_mut();
                    for i in 0..SYSCALL_SEARCH_RANGE {
                        let candidate = (function as *const u16).offset(offset + i);
                        if *candidate == arch::SYSCALL_OPCODE {
                            *addr_out = candidate as *mut c_void;
                            success = true;
                            break;
                        }
                    }
                }
                break;
            }
        }

        offset += 1
    }

    // Halo's Gate: if the stub is hooked, try neighbor stubs
    if !success && ssn.is_some() && resolve_hooked {
        success = find_hooked_syscall_ssn(function, ssn.unwrap());
    }

    success
}}


/**
 * Halo's Gate, recover the SSN of a hooked stub by inspecting neighors
 * 
 * Walks neighboring stubs (each `STUB_SIZE` byte apart)
 * When it finds an unhookeed neighbor, it calculates the target SSN by adding/subtracting the distance
 * */
unsafe fn find_hooked_syscall_ssn(function: *mut c_void, ssn: &mut u16) -> bool { unsafe {
    let stub_size = arch::STUB_SIZE;
    if stub_size == 0 {
        return false;
    }

    for i in 1..NEIGHBOUR_SEARCH_LIMIT {
        // Try forward neighbor
        let neighbour = (function as usize + stub_size as usize * i as usize) as *mut c_void;
        let mut neighbour_ssn: u16 = 0;
        if extract_syscall_info(neighbour, false, Some(&mut neighbour_ssn), None) {
            *ssn = neighbour_ssn.wrapping_sub(i as u16);
            return true;
        }

        // Try backward neighbor
        let neighbour =
            (function as usize).wrapping_sub(stub_size as usize * i as usize) as *mut c_void;
        let mut neighbour_ssn: u16 = 0;
        if extract_syscall_info(neighbour, false, Some(&mut neighbour_ssn), None) {
            *ssn = neighbour_ssn.wrapping_add(i as u16);
            return true;
        }
    }

    false
}}


/**
 * Returns a reference to the initialized syscall table
 * 
 * # Safety
 * `initialize()` must have been called first
 * */
pub unsafe fn syscall_table() -> &'static SyscallTable { unsafe {
    &*GLOBAL_TABLE.0.get()
}}

use crate::hashes;
use crate::resolver;
use crate::types::{SyscallEntry, HANDLE};
use core::cell::UnsafeCell;
use core::ffi::c_void;

pub const MAX_ENTRIES: usize = 64;

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

impl SyscallTable {
    const fn new() -> Self {
        Self {
            slots: [TableSlot::empty(); MAX_ENTRIES],
            count: 0,
            ntdll: core::ptr::null_mut(),
        }
    }

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

    pub fn ntdll(&self) -> HANDLE {
        self.ntdll
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

struct SyscallCell(UnsafeCell<SyscallTable>);
unsafe impl Sync for SyscallCell {}

static GLOBAL_TABLE: SyscallCell = SyscallCell(UnsafeCell::new(SyscallTable::new()));

pub unsafe fn initialize(mut ntdll: *mut c_void) -> bool {
    let table = &mut *GLOBAL_TABLE.0.get();

    if ntdll.is_null() {
        ntdll = resolver::ldr_module_search(hashes::NTDLL_HASH);
        if ntdll.is_null() {
            return false;
        }
    }
    table.ntdll = ntdll;

    // TODO: Resolve some of a common syscalls

    true
}
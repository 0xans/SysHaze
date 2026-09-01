//! Macro for invoking syscall by hash

/**
 * Invoke an indirect syscall by function name hash and argument count
 * 
 * Looks up the entry from the global state then dispatches to the appropriate `invoke::syscallx()` and return NTSTATUS
 * 
 * # Usage
 * ```ignore
 * use syshaze::hashes;
 * 
 * let status = unsafe { syshaze::indirect_syscall!(hashes::NTCLOSE_HASH, handle as usize) }
 * 
 * let status = unsafe {
 *     engine::indirect_syscall!(
 *         hashes::NTALLOCATEVIRTUALMEMORY_HASH,
 *         process as usize,
 *         &mut base as *mut _ as usize,
 *         0usize,
 *         &mut size as *mut _ as usize,
 *         0x3000usize,
 *         0x40usize
 *     )
 * };
 * ```
 * */
#[macro_export]
macro_rules! indirect_syscall {
    ($hash:expr, $a1:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall1(e.ssn, e.syscall_addr as usize, $a1),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall2(e.ssn, e.syscall_addr as usize, $a1, $a2),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall3(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall4(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3, $a4),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall5(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3, $a4, $a5),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall6(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3, $a4, $a5, $a6),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall7(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3, $a4, $a5, $a6, $a7),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr, $a8:expr, $a9:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall9(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8, $a9),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr, $a8:expr, $a9:expr, $a10:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall10(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8, $a9, $a10),
            None => -1i32,
        }
    }};
    ($hash:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr, $a8:expr, $a9:expr, $a10:expr, $a11:expr) => {{
        let table = $crate::ssn::syscall_table();
        match table.get($hash) {
            Some(e) => $crate::invoke::syscall11(e.ssn, e.syscall_addr as usize, $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8, $a9, $a10, $a11),
            None => -1i32,
        }
    }};
}
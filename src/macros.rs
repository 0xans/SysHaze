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
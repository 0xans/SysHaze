use core::arch::global_asm;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::types::NTSTATUS;

static SC_REG_EAX: AtomicU32 = AtomicU32::new(0);
static SC_JMP_TARGET: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".global IndirectCallDispatch",
    "IndirectCallDispatch:",
    "xchg rcx, r10",
    "xor eax, eax",
    "mov ax, word ptr [rip + {ssn}]",
    "push qword ptr [rip + {addr}]",
    "ret",
    ssn = sym SC_REG_EAX,
    addr = sym SC_JMP_TARGET,
);

#[allow(clashing_extern_declarations)]
unsafe extern "system" {
    #[link_name = "IndirectCallDispatch"]
    fn sys1(a1: usize) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys2(a1: usize, a2: usize) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys3(a1: usize, a2: usize, a3: usize) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys4(a1: usize, a2: usize, a3: usize, a4: usize) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys5(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys6(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys7(a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys9(
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
        a7: usize,
        a8: usize,
        a9: usize,
    ) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys10(
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
        a7: usize,
        a8: usize,
        a9: usize,
        a10: usize,
    ) -> i32;
    #[link_name = "IndirectCallDispatch"]
    fn sys11(
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
        a7: usize,
        a8: usize,
        a9: usize,
        a10: usize,
        a11: usize,
    ) -> i32;
}

#[inline(always)]
unsafe fn set_config(ssn: u16, addr: usize) {
    SC_REG_EAX.store(ssn as u32, Ordering::Release);
    SC_JMP_TARGET.store(addr as u64, Ordering::Release);
}

pub unsafe fn syscall1(ssn: u16, addr: usize, a1: usize) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys1(a1)
    }
}

pub unsafe fn syscall2(ssn: u16, addr: usize, a1: usize, a2: usize) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys2(a1, a2)
    }
}

pub unsafe fn syscall3(ssn: u16, addr: usize, a1: usize, a2: usize, a3: usize) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys3(a1, a2, a3)
    }
}

pub unsafe fn syscall4(
    ssn: u16,
    addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys4(a1, a2, a3, a4)
    }
}

pub unsafe fn syscall5(
    ssn: u16,
    addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys5(a1, a2, a3, a4, a5)
    }
}

pub unsafe fn syscall6(
    ssn: u16,
    addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys6(a1, a2, a3, a4, a5, a6)
    }
}

pub unsafe fn syscall7(
    ssn: u16,
    addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys7(a1, a2, a3, a4, a5, a6, a7)
    }
}

pub unsafe fn syscall9(
    ssn: u16,
    addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys9(a1, a2, a3, a4, a5, a6, a7, a8, a9)
    }
}

pub unsafe fn syscall10(
    ssn: u16,
    addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys10(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
    }
}

pub unsafe fn syscall11(
    ssn: u16,
    addr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
) -> NTSTATUS {
    unsafe {
        set_config(ssn, addr);
        sys11(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
    }
}

pub unsafe fn call1(func: *mut c_void, a1: usize) -> NTSTATUS {
    unsafe {
        let f: unsafe extern "system" fn(usize) -> NTSTATUS = core::mem::transmute(func);
        f(a1)
    }
}

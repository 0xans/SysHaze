#![allow(non_snake_case)]

use crate::invoke;
use crate::ssn;
use crate::hashes;
use crate::types::*;
use core::ffi::c_void;

macro_rules! get_entry {
    ($hash:expr) => {{
        let table = ssn::syscall_table();
        match table.get($hash) {
            Some(e) => e,
            None => return -1, // STATUS_UNSUCCESSFUL
        }
    }};
}

pub unsafe fn NtOpenProcess(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientID,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTOPENPROCESS_HASH);
    invoke::syscall4(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        client_id as usize,
    )
}}

pub unsafe fn NtTerminateProcess(process_handle: HANDLE, exit_status: NTSTATUS) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTTERMINATEPROCESS_HASH);
    invoke::syscall2(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        exit_status as usize,
    )
}}

pub unsafe fn NtQueryInformationProcess(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTQUERYINFORMATIONPROCESS_HASH);
    invoke::syscall5(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        process_information_class as usize,
        process_information as usize,
        process_information_length as usize,
        return_length as usize,
    )
}}

pub unsafe fn NtClose(handle: HANDLE) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTCLOSE_HASH);
    invoke::syscall1(e.ssn, e.syscall_addr as usize, handle as usize)
}}

pub unsafe fn NtDuplicateObject(
    source_process: HANDLE,
    source_handle: HANDLE,
    target_process: HANDLE,
    target_handle: *mut HANDLE,
    desired_access: u32,
    attributes: u32,
    options: u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTDUPLICATEOBJECT_HASH);
    invoke::syscall7(
        e.ssn, e.syscall_addr as usize,
        source_process as usize,
        source_handle as usize,
        target_process as usize,
        target_handle as usize,
        desired_access as usize,
        attributes as usize,
        options as usize,
    )
}}


pub unsafe fn NtAllocateVirtualMemory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTALLOCATEVIRTUALMEMORY_HASH);
    invoke::syscall6(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        base_address as usize,
        zero_bits,
        region_size as usize,
        allocation_type as usize,
        protect as usize,
    )
}}

pub unsafe fn NtWriteVirtualMemory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *const c_void,
    buffer_size: usize,
    bytes_written: *mut usize,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTWRITEVIRTUALMEMORY_HASH);
    invoke::syscall5(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        base_address as usize,
        buffer as usize,
        buffer_size,
        bytes_written as usize,
    )
}}

pub unsafe fn NtReadVirtualMemory(
    process_handle: HANDLE,
    base_address: *mut c_void,
    buffer: *mut c_void,
    buffer_size: usize,
    bytes_read: *mut usize,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTREADVIRTUALMEMORY_HASH);
    invoke::syscall5(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        base_address as usize,
        buffer as usize,
        buffer_size,
        bytes_read as usize,
    )
}}

pub unsafe fn NtProtectVirtualMemory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTPROTECTVIRTUALMEMORY_HASH);
    invoke::syscall5(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        base_address as usize,
        region_size as usize,
        new_protect as usize,
        old_protect as usize,
    )
}}

pub unsafe fn NtCreateThreadEx(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut c_void,
    process_handle: HANDLE,
    start_address: *mut c_void,
    parameter: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_commit: usize,
    stack_reserve: usize,
    bytes_buffer: *mut c_void,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTCREATETHREADEX_HASH);
    invoke::syscall11(
        e.ssn, e.syscall_addr as usize,
        thread_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        process_handle as usize,
        start_address as usize,
        parameter as usize,
        create_flags as usize,
        zero_bits,
        stack_commit,
        stack_reserve,
        bytes_buffer as usize,
    )
}}

pub unsafe fn NtResumeThread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTRESUMETHREAD_HASH);
    invoke::syscall2(
        e.ssn, e.syscall_addr as usize,
        thread_handle as usize,
        previous_suspend_count as usize,
    )
}}

pub unsafe fn NtQueueApcThread(
    thread_handle: HANDLE,
    apc_routine: *mut c_void,
    apc_argument1: *mut c_void,
    apc_argument2: *mut c_void,
    apc_argument3: *mut c_void,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTQUEUEAPCTHREAD_HASH);
    invoke::syscall5(
        e.ssn, e.syscall_addr as usize,
        thread_handle as usize,
        apc_routine as usize,
        apc_argument1 as usize,
        apc_argument2 as usize,
        apc_argument3 as usize,
    )
}}

pub unsafe fn NtWaitForSingleObject(
    handle: HANDLE,
    alertable: u8,
    timeout: *mut c_void,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTWAITFORSINGLEOBJECT_HASH);
    invoke::syscall3(
        e.ssn, e.syscall_addr as usize,
        handle as usize,
        alertable as usize,
        timeout as usize,
    )
}}

pub unsafe fn NtSleep(ms: u64) { unsafe {
    let table = ssn::syscall_table();
    let e = match table.get(hashes::NTDELAYEXECUTION_HASH) {
        Some(e) => e,
        None => return,
    };

    let mut delay: i64 = -((ms * 10_000) as i64);
    invoke::syscall2(
        e.ssn, e.syscall_addr as usize,
        0, // Alertable = FALSE
        &mut delay as *mut _ as usize,
    );
}}

pub unsafe fn NtCreateFile(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    allocation_size: *mut c_void,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_length: u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTCREATEFILE_HASH);
    invoke::syscall11(
        e.ssn, e.syscall_addr as usize,
        file_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        io_status_block as usize,
        allocation_size as usize,
        file_attributes as usize,
        share_access as usize,
        create_disposition as usize,
        create_options as usize,
        ea_buffer as usize,
        ea_length as usize,
    )
}}

pub unsafe fn NtWriteFile(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    buffer: *const c_void,
    length: u32,
    byte_offset: *mut c_void,
    key: *mut c_void,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTWRITEFILE_HASH);
    invoke::syscall9(
        e.ssn, e.syscall_addr as usize,
        file_handle as usize,
        event as usize,
        apc_routine as usize,
        apc_context as usize,
        io_status_block as usize,
        buffer as usize,
        length as usize,
        byte_offset as usize,
        key as usize,
    )
}}

pub unsafe fn NtReadFile(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: *mut c_void,
    apc_context: *mut c_void,
    io_status_block: *mut IoStatusBlock,
    buffer: *mut c_void,
    length: u32,
    byte_offset: *mut c_void,
    key: *mut c_void,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTREADFILE_HASH);
    invoke::syscall9(
        e.ssn, e.syscall_addr as usize,
        file_handle as usize,
        event as usize,
        apc_routine as usize,
        apc_context as usize,
        io_status_block as usize,
        buffer as usize,
        length as usize,
        byte_offset as usize,
        key as usize,
    )
}}

pub unsafe fn NtSetInformationFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTSETINFORMATIONFILE_HASH);
    invoke::syscall5(
        e.ssn, e.syscall_addr as usize,
        file_handle as usize,
        io_status_block as usize,
        file_information as usize,
        length as usize,
        file_information_class as usize,
    )
}}

pub unsafe fn NtCreateSection(
    section_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut c_void,
    maximum_size: *mut c_void,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTCREATESECTION_HASH);
    invoke::syscall7(
        e.ssn, e.syscall_addr as usize,
        section_handle as usize,
        desired_access as usize,
        object_attributes as usize,
        maximum_size as usize,
        section_page_protection as usize,
        allocation_attributes as usize,
        file_handle as usize,
    )
}}

pub unsafe fn NtMapViewOfSection(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    commit_size: usize,
    section_offset: *mut i64,
    view_size: *mut usize,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTMAPVIEWOFSECTION_HASH);
    invoke::syscall10(
        e.ssn, e.syscall_addr as usize,
        section_handle as usize,
        process_handle as usize,
        base_address as usize,
        zero_bits,
        commit_size,
        section_offset as usize,
        view_size as usize,
        inherit_disposition as usize,
        allocation_type as usize,
        win32_protect as usize,
    )
}}

pub unsafe fn NtUnmapViewOfSection(
    process_handle: HANDLE,
    base_address: *mut c_void,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTUNMAPVIEWOFSECTION_HASH);
    invoke::syscall2(
        e.ssn, e.syscall_addr as usize,
        process_handle as usize,
        base_address as usize,
    )
}}

pub unsafe fn NtQuerySystemInformation(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS { unsafe {
    let e = get_entry!(hashes::NTQUERYSYSTEMINFORMATION_HASH);
    invoke::syscall4(
        e.ssn, e.syscall_addr as usize,
        system_information_class as usize,
        system_information as usize,
        system_information_length as usize,
        return_length as usize,
    )
}}

/**
 * Check if the current process token is elevated
 * */
pub unsafe fn IsElevated() -> bool { unsafe {
    let table = ssn::syscall_table();

    let e_open = match table.get(hashes::NTOPENPROCESSTOKEN_HASH) {
        Some(e) => e,
        None => return false,
    };

    let mut token_handle: HANDLE = core::ptr::null_mut();
    let status = invoke::syscall3(
        e_open.ssn, e_open.syscall_addr as usize,
        -1isize as usize, // current process
        0x0008,           // TOKEN_QUERY
        &mut token_handle as *mut _ as usize,
    );
    if status != 0 { return false; }

    let e_query = match table.get(hashes::NTQUERYINFORMATIONTOKEN_HASH) {
        Some(e) => e,
        None => { NtClose(token_handle); return false; },
    };

    let mut elevation: u32 = 0;
    let mut ret_len: u32 = 0;
    let status = invoke::syscall5(
        e_query.ssn, e_query.syscall_addr as usize,
        token_handle as usize,
        20, // TokenElevation
        &mut elevation as *mut u32 as usize,
        4,
        &mut ret_len as *mut u32 as usize,
    );

    NtClose(token_handle);
    status == 0 && elevation != 0
}}
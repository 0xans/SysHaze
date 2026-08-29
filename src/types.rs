pub type HANDLE = *mut core::ffi::c_void;

pub type NTSTATUS = i32;
pub const STATUS_SUCCESS: NTSTATUS = 0;

// PE Image Signature and Directory Constants
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub(crate) number_of_names: u32,
    pub address_of_functions: u32,     // RVA from base of image
    pub address_of_names: u32,         // RVA from base of image
    pub address_of_name_ordinals: u32, // RVA from base of image
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: HANDLE,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut core::ffi::c_void,
    pub security_quality_of_service: *mut core::ffi::c_void,
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

#[repr(C)]
pub struct ClientID {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

#[repr(C)]
pub struct IoStatusBlock {
    pub status: NTSTATUS,
    pub information: usize,
}

#[repr(C)]
pub struct LargeInteger {
    pub low_part: u32,
    pub high_part: i32,
}

#[repr(C)]
pub struct ProcessBasicInformation {
    pub exit_status: NTSTATUS,
    pub peb_base_address: *mut core::ffi::c_void,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEntry {
    pub ssn: u16,
    pub syscall_addr: *mut core::ffi::c_void,
}

impl SyscallEntry {
    pub const fn empty() -> Self {
        Self {
            ssn: 0,
            syscall_addr: core::ptr::null_mut(),
        }
    }

    #[inline]
    pub const fn is_resolved(&self) -> bool {
        self.ssn != 0 && !self.syscall_addr.is_null()
    }
}

unsafe impl Send for SyscallEntry {}
unsafe impl Sync for SyscallEntry {}

#[inline]
pub unsafe fn initialize_object_attributes(
    p: *mut ObjectAttributes,
    name: *mut UnicodeString,
    attr: u32,
    root: HANDLE,
    sec: *mut core::ffi::c_void,
) {
    unsafe {
        (*p).length = core::mem::size_of::<ObjectAttributes>() as u32;
        (*p).root_directory = root;
        (*p).object_name = name;
        (*p).attributes = attr;
        (*p).security_descriptor = sec;
        (*p).security_quality_of_service = core::ptr::null_mut();
    }
}

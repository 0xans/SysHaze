use core::arch::asm;
use core::ffi::c_void;
use core::ptr::{null_mut, read};
use core::slice::from_raw_parts;

use crate::types::*;

/// Read the PEB base address from the TEB
#[cfg(target_arch = "x86_64")]
unsafe fn peb() -> usize {
    unsafe {
        let peb: usize;
        asm!("mov {}, gs:[0x60]", out(reg) peb);
        peb
    }
}

#[cfg(target_arch = "x86")]
unsafe fn peb() -> usize {
    let peb: usize;
    core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb);
    peb
}

fn wide_ascii_lower(wide: u16) -> u8 {
    let byte = (wide & 0xFF) as u8;
    if byte >= b'A' && byte <= b'Z' {
        byte + 32
    } else {
        byte
    }
}

unsafe fn read_mem<T: Copy>(addr: *const T) -> T {
    unsafe { read(addr) }
}

pub unsafe fn ldr_module_search(module_hash: u32) -> HANDLE {
    unsafe { module_peb_by_hash(module_hash).map_or(null_mut(), |base| base as HANDLE) }
}

pub unsafe fn ldr_function_by_hash(module: HANDLE, hash: u32) -> HANDLE {
    unsafe {
        if module.is_null() {
            return null_mut();
        }
        resolve_export_by_hash(module as usize, hash).map_or(null_mut(), |addr| addr as HANDLE)
    }
}

unsafe fn module_peb_by_hash(target_hash: u32) -> Option<usize> {
    unsafe {
        let p = peb();
        let ldr = *((p + 0x18) as *const usize);
        if ldr == 0 {
            return None;
        }

        let list_head = ldr + 0x10;
        let mut entry = *(list_head as *const usize);

        while entry != list_head {
            // TODO: suport 0x86
            let base_addr = *((entry + 0x30) as *const usize);
            let name_len = *((entry + 0x58) as *const u16);
            let name_buff = *((entry + 0x60) as *const usize);

            if base_addr != 0 && name_len > 0 && name_buff != 0 {
                let dll_wide = from_raw_parts(name_buff as *const u16, (name_len / 2) as usize);
                let mut hash: u32 = crate::hashes::HASH_SEED;
                for &wide in dll_wide {
                    hash = ((hash << 5).wrapping_add(hash)).wrapping_add(wide_ascii_lower(wide) as u32);
                }
                hash ^= crate::hashes::HASH_XOR;
                if hash == target_hash {
                    return Some(base_addr);
                }
            }
            entry = *(entry as *const usize);
        }
        None
    }
}

unsafe fn resolve_export_by_hash(module_base: usize, target_hash: u32) -> Option<*const c_void> {
    unsafe {
        if module_base == 0 {
            return None;
        }

        let dos_header: ImageDosHeader = read_mem(module_base as *const _);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew < 0 {
            return None;
        }

        let nt_header_addr = module_base + dos_header.e_lfanew as usize;
        if *(nt_header_addr as *const u32) != IMAGE_NT_SIGNATURE {
            return None;
        }

        let opt_hdr = nt_header_addr + 4 + 20;
        let magic = *(opt_hdr as *const u16);
        let data_dir_offset = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => 0x60,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => 0x70,
            _ => return None,
        };

        let export_data_dir = read_mem(
            (opt_hdr
                + data_dir_offset
                + IMAGE_DIRECTORY_ENTRY_EXPORT * size_of::<ImageDataDirectory>())
                as *const ImageDataDirectory,
        );
        let export_dir_rva = export_data_dir.virtual_address as usize;
        let export_dir_size = export_data_dir.size as usize;
        if export_dir_rva == 0 || export_dir_size == 0 {
            return None;
        }

        let export_dir: ImageExportDirectory = read_mem((module_base + export_dir_rva) as *const _);
        let funcs = (module_base + export_dir.address_of_functions as usize) as *const u32;
        let names = (module_base + export_dir.address_of_names as usize) as *const u32;
        let ordinals = (module_base + export_dir.address_of_name_ordinals as usize) as *const u16;

        for i in 0..export_dir.number_of_names {
            let name_rva = *names.add(i as usize) as usize;

            let mut name_hash: u32 = crate::hashes::HASH_SEED;
            let mut ptr = (module_base + name_rva) as *const u8;
            loop {
                let byte = *ptr;
                if byte == 0 {
                    break;
                }

                let c = if byte >= b'A' && byte <= b'Z' {
                    byte + 32
                } else {
                    byte
                };
                name_hash = ((name_hash << 5).wrapping_add(name_hash)).wrapping_add(c as u32);
                ptr = ptr.add(1);
            }

            name_hash ^= crate::hashes::HASH_XOR;
            if name_hash == target_hash {
                let ordinal_index = *ordinals.add(i as usize) as usize;
                if ordinal_index >= export_dir.number_of_functions as usize {
                    return None;
                }
                let func_rva = *funcs.add(ordinal_index) as usize;
                if func_rva == 0 {
                    return None;
                }
                if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                    return None;
                }
                return Some((module_base + func_rva) as *const c_void);
            }
        }
        None
    }
}

/**
 * Batch resolve multiple exports in a single pass through the export table.
 * Instead of calling resolve_export_by_hash() N times, this walks the table ONCe and checks each export hash aganist all targets
 * */
pub unsafe fn resolve_exports_batch(module: HANDLE, targets: &mut [(u32, *mut *mut c_void)]) {
    unsafe {
        if module.is_null() {
            return;
        }

        let module_base = module as usize;
        let dos_header: ImageDosHeader = read_mem(module_base as *const _);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew < 0 {
            return;
        }

        let nt_header_addr = module_base + dos_header.e_lfanew as usize;
        if *(nt_header_addr as *const u32) != IMAGE_NT_SIGNATURE {
            return;
        }

        let opt_hdr = nt_header_addr + 4 + 20;
        let magic = *(opt_hdr as *const u16);
        let data_dir_offset = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => 0x60,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => 0x70,
            _ => return,
        };

        let export_data_dir = read_mem(
            (opt_hdr
                + data_dir_offset
                + IMAGE_DIRECTORY_ENTRY_EXPORT * size_of::<ImageDataDirectory>())
                as *const ImageDataDirectory,
        );
        let export_dir_rva = export_data_dir.virtual_address as usize;
        let export_dir_size = export_data_dir.size as usize;
        if export_dir_rva == 0 || export_dir_size == 0 {
            return;
        }

        let export_dir: ImageExportDirectory = read_mem((module_base + export_dir_rva) as *const _);
        let funcs = (module_base + export_dir.address_of_functions as usize) as *const u32;
        let names = (module_base + export_dir.address_of_names as usize) as *const u32;
        let ordinals = (module_base + export_dir.address_of_name_ordinals as usize) as *const u16;

        // Track how many targets ramain unresolved, also to save time by early exit when all found
        let mut remaining = targets.len();

        for i in 0..export_dir.number_of_names {
            if remaining == 0 {
                break; // All targets are resolved
            }

            let name_rva = *names.add(i as usize) as usize;

            // Compute the hash for this export name
            let mut name_hash: u32 = crate::hashes::HASH_SEED;
            let mut ptr = (module_base + name_rva) as *const u8;
            loop {
                let byte = *ptr;
                if byte == 0 {
                    break;
                }

                let c = if byte >= b'A' && byte <= b'Z' {
                    byte + 32
                } else {
                    byte
                };

                name_hash = ((name_hash << 5).wrapping_add(name_hash)).wrapping_add(c as u32);
                ptr = ptr.add(1);
            }
            name_hash ^= crate::hashes::HASH_XOR;

            // Check aganist All target hashes
            for (target_hash, target_ptr) in targets.iter_mut() {
                // Skip if already resolved target
                if !(**target_ptr).is_null() {
                    continue;
                }

                if name_hash == *target_hash {
                    let ordinal_index = *ordinals.add(i as usize) as usize;
                    if ordinal_index >= export_dir.number_of_functions as usize {
                        continue;
                    }

                    let func_rva = *funcs.add(ordinal_index) as usize;
                    if func_rva == 0 {
                        continue;
                    }

                    // Skipp forwarded exports
                    if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                        continue;
                    }

                    **target_ptr = (module_base + func_rva) as *mut c_void;
                    remaining -= 1;
                    break; // This export matched, move to the next 
                }
            }
        }
    }
}

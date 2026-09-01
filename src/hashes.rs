//! API hashing, seeded DJB2 with XOR
//!
//! Hash Constants - Seeded DJB2 + XOR finalization
//! Algorithm: seed=0x60475117, body=((h<<5)+h)+c, xor=0x76717421

pub const HASH_SEED: u32 = 0x60475117;
pub const HASH_XOR: u32 = 0x76717421;

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

pub const NTDLL_HASH: u32 = 0xf3cdd21e;
pub const KERNEL32_HASH: u32 = 0x3b81a1a6;
pub const NTOPENPROCESS_HASH: u32 = 0x6c1e8e2b;
pub const NTTERMINATEPROCESS_HASH: u32 = 0x2d7cc400;
pub const NTQUERYINFORMATIONPROCESS_HASH: u32 = 0x4ae31115;
pub const NTCREATEPROCESSEX_HASH: u32 = 0xb42710a8;
pub const NTGETNEXTPROCESS_HASH: u32 = 0x78bfb196;
pub const NTALLOCATEVIRTUALMEMORY_HASH: u32 = 0x156a33bf;
pub const NTWRITEVIRTUALMEMORY_HASH: u32 = 0xddfba105;
pub const NTREADVIRTUALMEMORY_HASH: u32 = 0x43a7da14;
pub const NTPROTECTVIRTUALMEMORY_HASH: u32 = 0x53d158fb;
pub const NTCREATETHREADEX_HASH: u32 = 0xc2f2a5e3;
pub const NTRESUMETHREAD_HASH: u32 = 0x70a85103;
pub const NTQUEUEAPCTHREAD_HASH: u32 = 0x79a012eb;
pub const NTGETCONTEXTTHREAD_HASH: u32 = 0x0f27bf77;
pub const NTSETCONTEXTTHREAD_HASH: u32 = 0x7da5e5c3;
pub const NTSETINFORMATIONTHREAD_HASH: u32 = 0x96827c62;
pub const NTWAITFORSINGLEOBJECT_HASH: u32 = 0xa9eb260f;
pub const NTDELAYEXECUTION_HASH: u32 = 0x8d654c9d;
pub const NTCLOSE_HASH: u32 = 0xd4741b6e;
pub const NTDUPLICATEOBJECT_HASH: u32 = 0x817c68ea;
pub const NTCREATEFILE_HASH: u32 = 0xe554446c;
pub const NTWRITEFILE_HASH: u32 = 0xa4deb3c5;
pub const NTREADFILE_HASH: u32 = 0x8e4d95f4;
pub const NTSETINFORMATIONFILE_HASH: u32 = 0xc0e9962a;
pub const NTDELETEFILE_HASH: u32 = 0x20e2bdad;
pub const NTQUERYDIRECTORYFILE_HASH: u32 = 0x02799125;
pub const NTQUERYVOLUMEINFORMATIONFILE_HASH: u32 = 0x885149cc;
pub const NTCREATESECTION_HASH: u32 = 0x80387323;
pub const NTMAPVIEWOFSECTION_HASH: u32 = 0x94e91abd;
pub const NTUNMAPVIEWOFSECTION_HASH: u32 = 0x2566927e;
pub const NTQUERYSYSTEMINFORMATION_HASH: u32 = 0x2c3aea1b;
pub const NTOPENPROCESSTOKEN_HASH: u32 = 0x3730e94a;
pub const NTQUERYINFORMATIONTOKEN_HASH: u32 = 0x0cbfdab7;
pub const NTDUPLICATETOKEN_HASH: u32 = 0xe5f07914;
pub const NTOPENTHREADTOKEN_HASH: u32 = 0x448ff865;
pub const NTADJUSTPRIVILEGESTOKEN_HASH: u32 = 0xef25763e;
pub const NTSETIOCOMPLETION_HASH: u32 = 0xa674e0b6;
pub const NTQUERYINFORMATIONWORKERFACTORY_HASH: u32 = 0xeae7b2c6;
pub const NTCREATEKEY_HASH: u32 = 0x2fbb9397;
pub const NTSETVALUEKEY_HASH: u32 = 0xdefc6d0a;
pub const NTOPENKEY_HASH: u32 = 0xab071a95;
pub const NTQUERYVALUEKEY_HASH: u32 = 0xb5be88f4;
pub const NTDELETEKEY_HASH: u32 = 0x856aa134;
pub const NTLOADDRIVER_HASH: u32 = 0x1de19e64;
pub const NTUNLOADDRIVER_HASH: u32 = 0x987fffe9;
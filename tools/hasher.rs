use std::env;

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
        h = ((h << 5)).wrapping_add(h).wrapping_add(c as u32);
        i += 1
    }
    h ^ HASH_XOR
}

fn hash_module_wide(name: &str) -> u32 {
    let mut h: u32 = HASH_SEED;
    for ch in name.chars() {
        let byte = (ch as u32 & 0xFF) as u8;
        let c = if byte >= b'A' && byte <= b'Z' {
            byte + 32
        } else {
            byte
        };
        h = ((h << 5).wrapping_add(h)).wrapping_add(c as u32);
    }
    h ^ HASH_XOR
}

fn usage() {
    println!("Usage:");
    println!("  engine-hash [OPTIONS] <name1> [name2] ...");
    println!("\nOptions:");
    println!("  --function, -f   Compute function hash (ASCII, default)");
    println!("  --module, -m     Compute module hash (wide/UTF16)");
    println!("  --all, -a        Auto-detect: .dll/.exe -> module, else -> function");
    println!("  --rust, -r       Output as Rust constants");
    println!("  --help, -h       Show this help");
    println!("\nExamples:");
    println!("  engine-hash NtClose NtOpenProcess");
    println!("  engine-hash --module ntdll.dll kernel32.dll");
    println!("  engine-hash --all NtClose ntdll.dll NtAllocateVirtualMemory");
    println!("  engine-hash --rust NtClose NtOpenProcess");
}

#[derive(PartialEq)]
enum Mode {
    Function,
    Module,
    Auto
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return;
    }

    let mut mode = Mode::Function;
    let mut rust_output = false;
    let mut names: Vec<&str> = Vec::new();

    for arg in &args {
        match arg.as_str() {
            "--function" | "-f" => mode = Mode::Function,
            "--module" | "-m" => mode = Mode::Module,
            "--all" | "-a" => mode = Mode::Auto,
            "--rust" | "-r" => rust_output = true,
            _ if arg.starts_with('-') => {
                eprint!("Unkown option: {}", arg);
                std::process::exit(1);
            }
            _ => names.push(arg),
        }
    }

    if names.is_empty() {
        eprintln!("Error: no names provided");
        usage();
        std::process::exit(1);
    }

    if !rust_output {
        println!("{:<40} {:>12}  {}", "Name", "Hash", "Type");
        println!("{}", "-".repeat(60));
    }

    for name in &names {
        let is_module = match mode {
            Mode::Function => false,
            Mode::Module => true,
            Mode::Auto => {
                let lower = name.to_lowercase();
                lower.ends_with(".dll") || lower.ends_with(".exe") || lower.ends_with(".sys")
            },
        };

        let hash = if is_module {
            hash_module_wide(name)
        } else {
            hash_function(name.as_bytes())
        };

        let kind = if is_module { "module" } else { "function" };

        if rust_output {
            let const_name = name.replace('.', "_").to_uppercase();
            println!("pub const {}_HASH: u32 = 0x{:08x};", const_name, hash);
        } else {
            println!("{:<40} 0x{:08x}  {}", name, hash, kind);
        }
    }
}
# SysHaze: Indirect Syscall Engine

Rust indirect syscall engine. Runtime SSN resolution, obfuscated trampoline, per function `syscall;ret` addresses.

No static tables. No version dependencies. No strings. No imports. Zero external crates.

## How It Works

```
1. PEB Walk          → Find ntdll base (gs:[0x60] → InLoadOrderModuleList)
2. Export Parsing     → Walk PE export table, match by DJB2 hash
3. SSN Extraction     → Read stub pattern: 4C 8B D1 B8 [SSN_LO] [SSN_HI] 00 00
4. Gadget Search      → Locate per function 0F 05 C3 (syscall;ret) in the stub
5. Halo's Gate        → If stub is hooked, walk ±500 neighbors to recover SSN
6. Trampoline         → xchg rcx,r10 → xor eax,eax → mov ax,SSN → push addr → ret
7. Execution          → Lands on ntdll's own syscall instruction
```

**The return address on the stack points into ntdll** - not in the binary.

## Key Features

- **Runtime SSN resolution** — works on any Windows version, no hardcoded tables
- **Per function syscall address** — each Nt function uses its own `syscall;ret` gadget, not a shared one
- **Obfuscated trampoline** — `xchg rcx,r10` (49 87 CA) instead of `mov r10,rcx` (4C 8B D1), `push+ret` instead of `jmp`
- **Halo's Gate** — recovers SSNs from hooked stubs by walking neighboring stubs (±500)
- **Zero strings in binary** — all resolution by hash, no function names, no module names
- **Batch resolution** — single pass O(exports) resolver instead of O(exports × targets)
- **`no_std`** — no external crates, no allocator needed

//! Proof-of-concept: ELF call graph extraction + BFS reachability.
//!
//! Pipeline:
//!   1. Parse .symtab         → addr → local function name
//!   2. Parse .rela.dyn (GLOB_DAT) + .rela.plt (JUMP_SLOT)
//!                            → GOT addr → imported symbol name
//!   3. Disassemble .text with capstone:
//!      - call <imm>          → direct call to local function
//!      - call [rip+off]      → GOT dispatch (Rust/full-RELRO pattern)
//!      - call <plt_addr>     → classic PLT stub (C/GCC pattern)
//!      - indirect reg/mem    → mark caller as "has indirect call"
//!   4. BFS from main → target symbol
//!
//! Usage:
//!   cargo run --bin callgraph-spike -- <elf_binary> <target_symbol>

use std::{
    collections::{HashMap, HashSet, VecDeque},
    env,
    path::Path,
};

use anyhow::{Context, Result};
use capstone::prelude::*;
use goblin::elf::Elf;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

enum CallTarget {
    /// Direct call/jmp to a known address (resolved to a symbol).
    Direct(u64),
    /// RIP-relative GOT dispatch: call [rip+off] → GOT address.
    Got(u64),
    /// Indirect: call reg or call [mem] with non-RIP base — chain may break.
    Indirect,
}

enum Reachability {
    Reachable(Vec<String>),
    NotReachable,
    Unknown { broken_at: String },
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <elf_binary> <target_symbol>", args[0]);
        std::process::exit(1);
    }
    let binary_path = Path::new(&args[1]);
    let target_symbol = &args[2];

    let data = std::fs::read(binary_path)
        .with_context(|| format!("failed to read {}", binary_path.display()))?;

    println!("=== Parsing ELF: {} ===", binary_path.display());
    let elf = Elf::parse(&data).context("failed to parse ELF")?;

    // ------------------------------------------------------------------
    // Step 1: .symtab — local function symbols (addr → name).
    // ------------------------------------------------------------------
    let mut addr_to_name: HashMap<u64, String> = HashMap::new();

    for sym in &elf.syms {
        if sym.st_value == 0 || !sym.is_function() {
            continue;
        }
        if let Some(raw) = elf.strtab.get_at(sym.st_name) {
            if !raw.is_empty() {
                addr_to_name.insert(sym.st_value, demangle(raw));
            }
        }
    }
    println!("  .symtab functions : {}", addr_to_name.len());

    // ------------------------------------------------------------------
    // Step 2: GOT imports.
    //
    // Two sources for dynamic symbols:
    //   A) .rela.plt  with JUMP_SLOT  → classic PLT, entry = plt_base + (i+1)*16
    //   B) .rela.dyn  with GLOB_DAT   → full-RELRO / Rust pattern, entry = r_offset
    //
    // We build got_addr → symbol_name for both, then on call [rip+off] we
    // resolve the effective address and look it up here.
    // ------------------------------------------------------------------
    let mut got_to_name: HashMap<u64, String> = HashMap::new();

    // A) PLT entries (classic C/GCC layout).
    //
    // Modern toolchains with IBT/CET produce *three* PLT sections:
    //   .plt      — resolver stub (16 B) + classic stubs (not called directly)
    //   .plt.sec  — IBT-protected stubs *actually called* from code (16 B each)
    //   .plt.got  — GOT stubs (may overlap with GLOB_DAT handling below)
    //
    // We prefer .plt.sec (stubs called by code). Fall back to classic .plt layout
    // when .plt.sec does not exist.
    let plt_sec = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".plt.sec"));
    let plt_classic = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".plt"));

    let (plt_base, plt_entry_offset) = if let Some(sec) = plt_sec {
        // .plt.sec: entry i is at base + i * 16 (no leading resolver stub)
        (sec.sh_addr, 0u64)
    } else if let Some(sec) = plt_classic {
        // classic .plt: entry 0 is the resolver; imports start at base + 16
        (sec.sh_addr, 1u64)
    } else {
        (0u64, 0u64)
    };

    if plt_base != 0 {
        let plt_entry_size = 16u64;
        for (i, reloc) in elf.pltrelocs.iter().enumerate() {
            let sym_idx = reloc.r_sym;
            if let Some(sym) = elf.dynsyms.get(sym_idx) {
                if let Some(raw) = elf.dynstrtab.get_at(sym.st_name) {
                    if !raw.is_empty() {
                        let plt_addr =
                            plt_base + ((i as u64) + plt_entry_offset) * plt_entry_size;
                        let name = demangle(strip_version(raw));
                        got_to_name.insert(plt_addr, name.clone());
                        addr_to_name.insert(plt_addr, format!("{name}@plt"));
                    }
                }
            }
        }
        println!("  .plt imports      : {}", elf.pltrelocs.len());
    }

    // B) GLOB_DAT in .rela.dyn (Rust/full-RELRO, eager binding)
    // goblin already parses r_sym/r_type as struct fields.
    const R_X86_64_GLOB_DAT: u32 = 6;
    let mut glob_dat_count = 0;
    for reloc in &elf.dynrelas {
        if reloc.r_type == R_X86_64_GLOB_DAT {
            let sym_idx = reloc.r_sym;
            if let Some(sym) = elf.dynsyms.get(sym_idx) {
                if let Some(raw) = elf.dynstrtab.get_at(sym.st_name) {
                    if !raw.is_empty() {
                        let got_addr = reloc.r_offset;
                        let name = demangle(strip_version(raw));
                        got_to_name.insert(got_addr, name);
                        glob_dat_count += 1;
                    }
                }
            }
        }
    }
    println!("  GLOB_DAT imports  : {}", glob_dat_count);
    println!("  total GOT entries : {}", got_to_name.len());

    // Check whether the target is importable at all.
    if got_to_name.values().any(|n| n == target_symbol.as_str()) {
        println!("  target '{target_symbol}' found in GOT imports ✓");
    } else if addr_to_name.values().any(|n| n == target_symbol.as_str()) {
        println!("  target '{target_symbol}' found in .symtab ✓");
    } else {
        println!("  WARNING: target '{target_symbol}' not in GOT or .symtab → will report Unknown");
    }

    // ------------------------------------------------------------------
    // Step 3: function address ranges (for "which function owns this addr?").
    // ------------------------------------------------------------------
    let mut func_ranges: Vec<(u64, u64, String)> = elf
        .syms
        .iter()
        .filter(|s| s.is_function() && s.st_value != 0 && s.st_size > 0)
        .filter_map(|s| {
            elf.strtab.get_at(s.st_name).map(|raw| {
                (s.st_value, s.st_value + s.st_size, demangle(raw))
            })
        })
        .collect();
    func_ranges.sort_by_key(|(start, _, _)| *start);

    // ------------------------------------------------------------------
    // Step 4: disassemble .text, build call graph.
    // ------------------------------------------------------------------
    let text_section = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))
        .context("no .text section")?;

    let off = text_section.sh_offset as usize;
    let sz = text_section.sh_size as usize;
    let vaddr = text_section.sh_addr;
    let text_bytes = &data[off..off + sz];

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .context("failed to build Capstone")?;

    let insns = cs.disasm_all(text_bytes, vaddr).context("disassembly failed")?;
    println!("  disassembled {} instructions", insns.len());

    // call_graph[caller] = set of callee names
    let mut call_graph: HashMap<String, HashSet<String>> = HashMap::new();
    let mut indirect_callers: HashSet<String> = HashSet::new();

    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let is_call = mnemonic == "call" || mnemonic == "callq";
        let is_jmp = mnemonic == "jmp" || mnemonic == "jmpq";
        if !is_call && !is_jmp {
            continue;
        }

        let Some(caller) = find_function(insn.address(), &func_ranges) else {
            continue;
        };

        match extract_target(&cs, &insn) {
            Some(CallTarget::Direct(target)) => {
                let in_same_func = is_jmp
                    && find_function(target, &func_ranges)
                        .map(|f| f == caller)
                        .unwrap_or(false);
                if in_same_func {
                    continue;
                }
                if let Some(callee) = addr_to_name.get(&target) {
                    // Strip @plt suffix so graph edges use canonical symbol names.
                    let name = callee.strip_suffix("@plt").unwrap_or(callee.as_str());
                    call_graph
                        .entry(caller.to_string())
                        .or_default()
                        .insert(name.to_string());
                }
            }
            Some(CallTarget::Got(got_addr)) => {
                if let Some(callee) = got_to_name.get(&got_addr) {
                    call_graph
                        .entry(caller.to_string())
                        .or_default()
                        .insert(callee.clone());
                } else {
                    // GOT addr not in our import map — could be a local function
                    // pointer or unresolved import; treat as indirect.
                    indirect_callers.insert(caller.to_string());
                }
            }
            Some(CallTarget::Indirect) => {
                indirect_callers.insert(caller.to_string());
            }
            None => {}
        }
    }

    let total_edges: usize = call_graph.values().map(|s| s.len()).sum();
    println!(
        "  call graph: {} callers, {} edges, {} functions with indirect calls",
        call_graph.len(),
        total_edges,
        indirect_callers.len()
    );

    // ------------------------------------------------------------------
    // Debug: show direct callers of target.
    // ------------------------------------------------------------------
    let direct_callers: Vec<&str> = call_graph
        .iter()
        .filter(|(_, callees)| callees.contains(target_symbol.as_str()))
        .map(|(caller, _)| caller.as_str())
        .collect();
    if direct_callers.is_empty() {
        println!("  DEBUG: no direct callers of '{target_symbol}' in call graph");
    } else {
        println!("  DEBUG: direct callers of '{target_symbol}': {:?}", direct_callers);
    }

    // ------------------------------------------------------------------
    // Step 5: BFS from entry point.
    // ------------------------------------------------------------------
    let entry = find_entry_name(&elf, &addr_to_name);
    let entry_callees_list: Vec<&str> = call_graph
        .get(&entry)
        .map(|s| s.iter().map(String::as_str).collect())
        .unwrap_or_default();
    println!("\n=== Reachability: {entry} → {target_symbol} ===");
    println!("  entry has {} direct callees:", entry_callees_list.len());
    for c in &entry_callees_list {
        println!("    {c}");
    }

    match bfs(&call_graph, &indirect_callers, &entry, target_symbol) {
        Reachability::Reachable(chain) => {
            println!("REACHABLE");
            println!("  {}", chain.join("\n  → "));
        }
        Reachability::NotReachable => {
            println!("NOT REACHABLE");
        }
        Reachability::Unknown { broken_at } => {
            println!("UNKNOWN — chain may continue past indirect call in '{broken_at}'");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_target(cs: &Capstone, insn: &capstone::Insn) -> Option<CallTarget> {
    let detail = cs.insn_detail(insn).ok()?;
    let arch = detail.arch_detail();
    let x86 = arch.x86()?;

    for op in x86.operands() {
        return Some(match op.op_type {
            arch::x86::X86OperandType::Imm(addr) => CallTarget::Direct(addr as u64),

            arch::x86::X86OperandType::Mem(mem) => {
                use capstone::arch::x86::X86Reg;
                use capstone::RegId;
                let rip = RegId::from(X86Reg::X86_REG_RIP);
                // RIP-relative: call [rip + disp] → GOT entry
                if mem.base() == rip && mem.index() == RegId::INVALID_REG {
                    let next_addr = insn.address() + insn.bytes().len() as u64;
                    let got_addr = (next_addr as i64 + mem.disp()) as u64;
                    CallTarget::Got(got_addr)
                } else {
                    CallTarget::Indirect
                }
            }

            arch::x86::X86OperandType::Reg(_) => CallTarget::Indirect,

            _ => return None,
        });
    }
    None
}

fn find_function<'a>(addr: u64, ranges: &'a [(u64, u64, String)]) -> Option<&'a str> {
    let idx = ranges.partition_point(|(start, _, _)| *start <= addr);
    if idx == 0 {
        return None;
    }
    let (start, end, name) = &ranges[idx - 1];
    if addr >= *start && addr < *end {
        Some(name.as_str())
    } else {
        None
    }
}

fn find_entry_name(elf: &Elf, addr_to_name: &HashMap<u64, String>) -> String {
    // Prefer a Rust-mangled "::main" function over the ELF C wrapper (which
    // calls the real main via a function pointer and has no direct edges).
    if let Some(name) = addr_to_name
        .values()
        .find(|n| n.ends_with("::main") || n.contains("::main::h"))
    {
        return name.clone();
    }
    if let Some(name) = addr_to_name.values().find(|n| n.as_str() == "main") {
        return name.clone();
    }
    if let Some(name) = addr_to_name.get(&elf.entry) {
        return name.clone();
    }
    format!("entry@{:#x}", elf.entry)
}

fn bfs(
    call_graph: &HashMap<String, HashSet<String>>,
    indirect_callers: &HashSet<String>,
    start: &str,
    target: &str,
) -> Reachability {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut parent: HashMap<String, String> = HashMap::new();

    queue.push_back(start.to_string());
    visited.insert(start.to_string());

    while let Some(current) = queue.pop_front() {
        let empty = HashSet::new();
        let callees = call_graph.get(&current).unwrap_or(&empty);

        for callee in callees {
            if callee.as_str() == target {
                let mut chain = vec![callee.clone()];
                let mut cur = current.clone();
                chain.push(cur.clone());
                while let Some(p) = parent.get(&cur) {
                    chain.push(p.clone());
                    cur = p.clone();
                }
                chain.reverse();
                return Reachability::Reachable(chain);
            }

            if !visited.contains(callee.as_str()) {
                visited.insert(callee.clone());
                parent.insert(callee.clone(), current.clone());
                queue.push_back(callee.clone());
            }
        }
    }

    if let Some(broken) = visited.iter().find(|v| indirect_callers.contains(v.as_str())) {
        Reachability::Unknown { broken_at: broken.clone() }
    } else {
        Reachability::NotReachable
    }
}

/// Strip GLIBC version suffix, e.g. "execvp@GLIBC_2.2.5" → "execvp".
fn strip_version(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

fn demangle(raw: &str) -> String {
    if let Ok(sym) = cpp_demangle::Symbol::new(raw) {
        return sym.to_string();
    }
    rustc_demangle::demangle(raw).to_string()
}

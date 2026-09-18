use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use anyhow::{Context, Result};
use capstone::prelude::*;
use goblin::elf::Elf;

use super::demangle::demangle;
use super::extractor::{ArtifactCallGraph, CallGraphExtractor};

const R_X86_64_GLOB_DAT: u32 = 6;

enum CallTarget {
    Direct(u64),
    Got(u64),
    Indirect,
}

pub struct ElfExtractor;

impl CallGraphExtractor for ElfExtractor {
    fn extract(&self, artifact: &Path) -> Result<ArtifactCallGraph> {
        let data = std::fs::read(artifact)
            .with_context(|| format!("failed to read {}", artifact.display()))?;
        let elf = Elf::parse(&data).context("failed to parse ELF")?;
        extract_from(&data, &elf)
    }
}

fn extract_from(data: &[u8], elf: &Elf) -> Result<ArtifactCallGraph> {
    // -----------------------------------------------------------------------
    // Step 1: local function symbols from .symtab.
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // Step 2: GOT imports — two sources:
    //   A) .rela.plt  JUMP_SLOT → classic PLT (.plt or .plt.sec with IBT/CET)
    //   B) .rela.dyn  GLOB_DAT  → full-RELRO / Rust eager binding
    // -----------------------------------------------------------------------
    let mut got_to_name: HashMap<u64, String> = HashMap::new();

    // A) PLT entries.
    //    Modern IBT/CET toolchains produce .plt.sec (stubs actually called from code);
    //    classic toolchains produce .plt with a leading resolver stub at entry 0.
    let plt_sec = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".plt.sec"));
    let plt_classic = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".plt"));

    let (plt_base, plt_entry_offset) = if let Some(sec) = plt_sec {
        (sec.sh_addr, 0u64)
    } else if let Some(sec) = plt_classic {
        (sec.sh_addr, 1u64) // skip the resolver stub at entry 0
    } else {
        (0u64, 0u64)
    };

    if plt_base != 0 {
        for (i, reloc) in elf.pltrelocs.iter().enumerate() {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                if let Some(raw) = elf.dynstrtab.get_at(sym.st_name) {
                    if !raw.is_empty() {
                        let plt_addr = plt_base + ((i as u64) + plt_entry_offset) * 16;
                        let name = demangle(strip_version(raw));
                        got_to_name.insert(plt_addr, name.clone());
                        addr_to_name.insert(plt_addr, format!("{name}@plt"));
                    }
                }
            }
        }
    }

    // B) GLOB_DAT in .rela.dyn.
    for reloc in &elf.dynrelas {
        if reloc.r_type == R_X86_64_GLOB_DAT {
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                if let Some(raw) = elf.dynstrtab.get_at(sym.st_name) {
                    if !raw.is_empty() {
                        got_to_name.insert(reloc.r_offset, demangle(strip_version(raw)));
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: function address ranges for "which function owns this addr?".
    //   Built from .symtab first; supplement with .dynsym defined entries
    //   so that partially-stripped binaries still produce usable ranges.
    // -----------------------------------------------------------------------
    let mut func_ranges: Vec<(u64, u64, String)> = Vec::new();

    for sym in &elf.syms {
        if sym.is_function() && sym.st_value != 0 && sym.st_size > 0 {
            if let Some(raw) = elf.strtab.get_at(sym.st_name) {
                func_ranges.push((sym.st_value, sym.st_value + sym.st_size, demangle(raw)));
            }
        }
    }

    // .dynsym entries with st_shndx != 0 are defined in this binary (not UND imports).
    for sym in &elf.dynsyms {
        if sym.is_function() && sym.st_value != 0 && sym.st_size > 0 && sym.st_shndx != 0 {
            if !addr_to_name.contains_key(&sym.st_value) {
                if let Some(raw) = elf.dynstrtab.get_at(sym.st_name) {
                    if !raw.is_empty() {
                        let name = demangle(raw);
                        addr_to_name.insert(sym.st_value, name.clone());
                        func_ranges.push((sym.st_value, sym.st_value + sym.st_size, name));
                    }
                }
            }
        }
    }

    func_ranges.sort_by_key(|(start, _, _)| *start);
    func_ranges.dedup_by_key(|(start, _, _)| *start);

    // -----------------------------------------------------------------------
    // Build known_symbols: the union of all observable names.
    // -----------------------------------------------------------------------
    let mut known_symbols: HashSet<String> = HashSet::new();
    for name in got_to_name.values() {
        known_symbols.insert(name.clone());
    }
    for name in addr_to_name.values() {
        known_symbols.insert(name.strip_suffix("@plt").unwrap_or(name).to_string());
    }

    // -----------------------------------------------------------------------
    // Exported entries (for shared library mode).
    // -----------------------------------------------------------------------
    let exported_entries: Vec<String> = elf
        .dynsyms
        .iter()
        .filter(|s| s.is_function() && s.st_value != 0 && s.st_shndx != 0)
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
        .filter(|r| !r.is_empty())
        .map(demangle)
        .collect();

    // Main entry point.
    let main_entry = find_entry_name(elf, &addr_to_name);

    let has_symbol_table = !func_ranges.is_empty();
    if !has_symbol_table {
        return Ok(ArtifactCallGraph {
            edges: vec![],
            indirect_callers: vec![],
            known_symbols,
            has_symbol_table: false,
            main_entry,
            exported_entries,
        });
    }

    // -----------------------------------------------------------------------
    // Step 4: disassemble .text, build call graph.
    // -----------------------------------------------------------------------
    let text_section = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))
        .context("no .text section")?;

    let off = text_section.sh_offset as usize;
    let sz = text_section.sh_size as usize;
    let text_bytes = &data[off..off + sz];

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .context("failed to build Capstone")?;

    let insns = cs
        .disasm_all(text_bytes, text_section.sh_addr)
        .context("disassembly failed")?;

    let mut edges: Vec<(String, String)> = Vec::new();
    let mut indirect_set: HashSet<String> = HashSet::new();

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
            Some(CallTarget::Direct(target_addr)) => {
                if is_jmp
                    && find_function(target_addr, &func_ranges)
                        .map(|f| f == caller)
                        .unwrap_or(false)
                {
                    continue; // tail-jump within the same function
                }
                if let Some(callee) = addr_to_name.get(&target_addr) {
                    let name = callee.strip_suffix("@plt").unwrap_or(callee.as_str());
                    edges.push((caller.to_string(), name.to_string()));
                }
            }
            Some(CallTarget::Got(got_addr)) => {
                if let Some(callee) = got_to_name.get(&got_addr) {
                    edges.push((caller.to_string(), callee.clone()));
                } else {
                    // GOT address not in our import map — local fn pointer or
                    // unresolved import; treat as indirect to be safe.
                    indirect_set.insert(caller.to_string());
                }
            }
            Some(CallTarget::Indirect) => {
                indirect_set.insert(caller.to_string());
            }
            None => {}
        }
    }

    Ok(ArtifactCallGraph {
        edges,
        indirect_callers: indirect_set.into_iter().collect(),
        known_symbols,
        has_symbol_table: true,
        main_entry,
        exported_entries,
    })
}

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

fn find_entry_name(elf: &Elf, addr_to_name: &HashMap<u64, String>) -> Option<String> {
    if let Some(n) = addr_to_name.values().find(|n| n.as_str() == "main") {
        return Some(n.clone());
    }
    // Rust binaries: the real entry is a mangled ::main function.
    if let Some(n) = addr_to_name
        .values()
        .find(|n| n.ends_with("::main") || n.contains("::main::h"))
    {
        return Some(n.clone());
    }
    addr_to_name.get(&elf.entry).cloned()
}

fn strip_version(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

//! Symbol demangling shared by call-graph extractors.
//!
//! Both `ElfExtractor` (reads `.symtab`/`.dynsym`) and `LlvmExtractor`
//! (parses `opt`'s call-graph dump) see raw, mangled symbol names — the
//! LLVM call-graph printer emits Itanium-mangled C++ names, not demangled
//! ones — so demangling lives here and is reused by both.

/// Best-effort demangle: try C++ (Itanium) first, then Rust, else return as-is.
pub fn demangle(raw: &str) -> String {
    if let Ok(sym) = cpp_demangle::Symbol::new(raw) {
        return sym.to_string();
    }
    rustc_demangle::demangle(raw).to_string()
}

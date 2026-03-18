  build_analyzer/
  ├── Cargo.toml                          ← workspace (excludes ebpf crate)
  ├── ebpf-component-tracer-common/
  │   ├── Cargo.toml
  │   └── src/lib.rs                      ← FileEvent (no_std / user dual)
  ├── ebpf-component-tracer-ebpf/         ← kernel space (nightly + bpf-linker)
  │   ├── .cargo/config.toml              ← target = bpfel-unknown-none
  │   ├── rust-toolchain.toml             ← channel = nightly
  │   ├── Cargo.toml
  │   └── src/main.rs                     ← 3 tracepoints + 2 maps
  └── ebpf-component-tracer/              ← user space binary
      ├── build.rs                        ← компилирует eBPF-крейт
      ├── Cargo.toml
      └── src/
          ├── main.rs                     ← оркестрация, Aya, JSON-вывод
          ├── resolver.rs                 ← фильтрация путей, нормализация
          └── identity.rs                 ← dpkg/pacman/rpm + SHA-256

  ---
  Что реализовано

  Kernel space (ebpf-component-tracer-ebpf/src/main.rs)

  ┌────────────────────┬───────────────────────────┬────────────────────────────────────────────────────────────────────────┐
  │     Программа      │        Трейспойнт         │                               Назначение                               │
  ├────────────────────┼───────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ sched_process_fork │ sched/sched_process_fork  │ Если parent_pid в PID_FILTER → добавить child_pid (рекурсивное дерево) │
  ├────────────────────┼───────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ sched_process_exit │ sched/sched_process_exit  │ Удалить PID из фильтра при завершении                                  │
  ├────────────────────┼───────────────────────────┼────────────────────────────────────────────────────────────────────────┤
  │ sys_enter_openat   │ syscalls/sys_enter_openat │ Захватить путь → FileEvent в RingBuf                                   │
  └────────────────────┴───────────────────────────┴────────────────────────────────────────────────────────────────────────┘

  Maps: PID_FILTER: HashMap<u32, u8> + FILE_EVENTS: RingBuf (16 MiB)

  User space

  - build.rs — компилирует eBPF через rustup run nightly cargo, сбрасывает RUSTC/RUSTFLAGS от внешнего stable cargo
  - resolver.rs — фильтрация по расширениям (включая *.so.3), исключение /proc/, /sys/, /tmp/, нормализация ..
  - identity.rs — dpkg -S → dpkg-query -W (с кешем), fallback на pacman/rpm, SHA-256 для локальных файлов
  - main.rs — AsyncFd<RingBuf> + tokio::select! для неблокирующего чтения событий, вывод в JSON

  Требования для запуска

  rustup toolchain install nightly --component rust-src
  cargo install bpf-linker

  cargo build -p ebpf-component-tracer
  sudo ./target/debug/ebpf-tracer -- cmake --build ./build

  Бинарь требует CAP_BPF (запуск через sudo или с соответствующими capabilities).

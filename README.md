## solnix-examples

This repository contains runnable, Solnix programs with userspace loaders.

### Examples

- `tracepoint-execve-filename/`: Trace every `execve()` and stream filenames to Go via a ring buffer.
- `tracepoint-execve-counter/`: Trace every `execve()` and count per-PID in a hash map (Go prints counters).
- `raw-tracepoint-sysenter-demo/`: Minimal `raw_tracepoint/sys_enter` stub with Go loader.

### Recommended folder structure (copy to add more)

Each example is a self-contained folder:

- `bpf/`: one or more `.snx` programs
- `cmd/loader/`: userspace loader (Go)
- `build/`: build outputs (`.o`, loader binary) (generated)
- `Makefile`: `build-bpf`, `build`, `run`, `clean`

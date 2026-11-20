# Findings — Intel Xe-LPG resume session

## Build environment
- Repo root: `/Users/jay/Documents/Stela` (symlink) -> `/Volumes/未命名/Stela`
  (removable volume, **not** a git repo; no `git diff`).
- Rust: must use `RUSTUP_TOOLCHAIN=stable-x86_64-apple-darwin` (that channel
  *is* 1.99.1; the pinned `1.99.1` toolchain is broken and the tsinghua mirror
  404s). Plain `cargo` triggers a 1.99.1 sync that fails.
- Disk: APFS container ~3.9 GB free; `cargo clean` before builds.
- `cargo xtask gpu fetch` cannot run (its root `git ls-files` step fails on the
  non-git root). Apply `third_party/*.sparse` inside each submodule by hand:
  `cd third_party/linux && git sparse-checkout set --no-cone --stdin < ../../third_party/linux.sparse`.
  Note the sparse file lives at **repo root** (`third_party/linux.sparse`), not
  inside `third_party/linux`.

## What was already in place (tasks 1-5 of spec)
- `linux.sparse` had `/drivers/gpu/drm/xe/`, `/drivers/gpu/drm/i915/display/`;
  `libdrm.sparse` had `/xe/*.h`; `CONFIG_DRM_XE 1` in `autoconf.h:69`;
  `build/xe.rs` + `xe-port` feature + `OPEN_XE` list exist.
- Residual gaps: `/mm/vma_internal.h` (added), `asm/tlb.h` (added).

## Root-cause chain for the link failure
`mm/vma.c` was added to `stela-linux/build/native.rs` upstream list (line 141)
but **could never compile** before this session (missing `vma_internal.h`).
Once it compiles, `mm/vma.o` lands in `liblinux-hosted.a` and the hosted
`linux_drm_vma` test (links that archive) needs 25 MM symbols that Stela's
environment intentionally does not build:

| Symbol | Upstream provider (not in Stela list) |
|--------|----------------------------------------|
| `__anon_vma_prepare`, `anon_vma_clone`, `unlink_anon_vmas`, `anon_vma_interval_tree_{insert,remove}` | `mm/rmap.c` |
| `find_vma_{prev,intersection}`, `may_expand_vm`, `stack_guard_gap`, `vm_stat_account`, `vma_interval_tree_{insert,remove}`, `vma_set_page_prot`, `unmap_vmas` | `mm/mmap.c` |
| `tlb_gather_mmu`, `tlb_finish_mmu` | `mm/mmap.c` (via `mm/mmu_gather.c`) |
| `mlock_future_ok` | `mm/mlock.c` |
| `shmem_zero_setup` | `mm/shmem.c` |
| `cap_vm_enough_memory`, `compat_vma_mmap`, `mmap_action_{prepare,complete}`, `mmap_min_addr`, `sysctl_max_map_count` | `mm/util.c` / `mm/mmap.c` |

None of the 25 is trapped today; `STELA_UNSUPPORTED` (`__builtin_trap`) and
`STELA_UNSUPPORTED_OBJECT` exist in `crates/stela-linux/src/compat/unsupported.h`
and are used from `src/compat/kernel/unsupported.c` (shmem/seq/platform family).

## Why `vma.o` is pulled in at all
`drm_vma_manager.c` (in `DRM_SOURCES`) exercises the VMA offset/permission
manager and, transitively via the shared archives, the link pulls `vma.o`.
The test `drm_vma_test.c` itself only touches `drm_vma_*` bookkeeping.

## Fix-shape options (decision needed)
1. **Traps**: add the 25 symbols to a compat `unsupported.c`-style provider so
   the hosted test links; any real call traps. Cheapest, matches the
   "trap = required native provider" discipline (cf. `tlbflush.h`, `pci.c`).
2. **Provider files**: add `mm/rmap.c`, `mm/mmap.c`, `mm/mmu_gather.c`,
   `mm/mlock.c`, `mm/shmem.c`, `mm/util.c`, `mm/vmstat.c` to the stela-linux
   upstream list. Much larger surface, likely cascades into still-more deps.
3. **Trim the test link**: stop linking `vma.o` into the drm test archive —
   but `vma.o` is needed by the environment generally, not just the test.

Working hypothesis: option 1 (traps) is the intended Stela pattern — the
environment deliberately excludes whole mm provider files and satisfies
cross-references with traps; the `mm/vma.c` compile was only just unmasked.

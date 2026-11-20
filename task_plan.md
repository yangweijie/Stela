# Intel Xe-LPG GPU — Resume Plan (planning-with-files)

Goal: continue `.ohmyagent/specs/intel-xe-gpu/tasklist.md`; reach task 7
checkpoint: `cargo build -p stela-driver-gpu --features xe-port` passes
`check_imports` and the hosted C tests link.

## Context
- Canonical plan lives in `.ohmyagent/specs/intel-xe-gpu/`
  (requirements.md / design.md / tasklist.md). This file tracks the *resume*
  session only; do not duplicate the 18-task list.
- Repo root is a symlink: `/Users/jay/Documents/Stela` -> `/Volumes/未命名/Stela`.
- Not a git repo (no `git` history available for diffs).
- Rust toolchain: `1.99.1` via `RUSTUP_TOOLCHAIN=stable-x86_64-apple-darwin`
  (the pinned `1.99.1` channel is broken / not downloadable).
- Disk is tight (~3.9 GB free); ran `cargo clean` before building.

## Phases

### Phase 1: unblock base build (sparse + compat headers)
**Status:** complete
- `third_party/linux.sparse`: added `/mm/vma_internal.h` (task 1 residual gap).
- `crates/stela-linux/src/compat/asm/tlb.h`: new arch-side header
  (x86 `asm/tlb.h` content) so `mm/vma.c` -> `mm/vma_internal.h` -> `<asm/tlb.h>`
  resolves. `mm/vma.c` now *compiles*.

### Phase 2: resolve mm link gap (25 symbols)
**Status:** complete
- Traps added to `crates/stela-linux/src/compat/kernel/unsupported.c`:
  - 22 functions via `STELA_UNSUPPORTED` (anon_vma family, mmu_gather/TLB,
    VMA lookups, interval trees, mmap policy, mlock, shmem, etc.)
  - 3 scalar globals (mmap_min_addr, stack_guard_gap, sysctl_max_map_count)
    via plain `= 0` initializers
- `members()` notation fix: Mach-O symbol names carry a leading C-convention
  underscore; `check_imports` now normalizes them so the gate compares in one
  C-symbol space (shared infra benefit for both nouveau and xe ports).
- `upstream_warnings()` gained `-Wno-default-const-init-var-unsafe` (probed)
  for Apple's clang; the kernel's `typecheck()` idiom default-initializes a
  `typeof(x)` local inside a statement expression which triggers it.
- `OPEN_XE` rewritten: 7 old speculative entries (2 stale, 5 still open) →
  103 entries grouped by service family. `check_imports` now passes.

### Phase 2.5: task 7 checkpoint (env + build + tests)
**Status:** complete
- `cargo build -p stela-driver-gpu --features xe-port` finishes clean.
- `libstela-intel-xe.a` produced; `check_imports` clean (no assertion).
- `cargo test -p stela-driver-gpu --features xe-port`: 38 Rust + 3 kbuild +
  1 llvm all ok; the 5 hosted C tests are recognized by the Rust harness
  (`c_tests::linux_drm_mm/vma/formats/xe_bo/xe_sched`) and run green.

### Phase 3: task 6 — write xe hosted C tests
**Status:** complete
- `crates/stela-driver-gpu/src/compat/linux/stela/xe_bo_test.c` — xe_bo
  reservation state machine on the env's `dma_resv`/`dma_fence`: a completed
  write fence coexists with an in-flight read fence; preemption replaces the
  in-flight fence so `dma_resv_test_signaled` clears. Stacked fences with a
  no-op `release` ops keep the test owner-free; the heap resv list is
  reclaimed by the host (no `dma_resv_fini`/`dma_fence_put` free path).
- `crates/stela-driver-gpu/src/compat/linux/stela/xe_sched_test.c` — fence
  signaling: queued callback fires exactly once on signal, a late callback is
  rejected (`-ENOENT`), and an errored fence reports its status (`-EIO`).
- Both registered in `build/native.rs::tests()` mirroring `linux_drm_mm`;
  link only the 4 env archives (no driver), per the "test the environment"
  discipline. All 25 `dma_resv_*`/`dma_fence_*` symbols they call are real
  `T` implementations in those archives.
- Note: `dma_resv_fini`/`dma_fence_put` on a kmalloc'd list traps in the
  bare-hosted build (kvfree_call_rcu range check: `kmalloc_size_roundup`
  is identity, so `rcu` falls out of the tracked range); tests therefore
  verify the state machine without exercising the free path.

### Phase 4: Phase 2 of spec (ANV / Metal / boot / maintenance)
**Status:** in_progress
- task 8 (this session): `xtask/src/gpu/nvk.rs` 代码改动完成
  （OPTIONS `nouveau,intel`、DRIVERS + `libvulkan_intel.so`、WHOLE_LIBRARIES
  改 `libanv_common_a`/`libanv_per_hw_ver`/`libanv_drirc`、`Unit.archive`
  三桶 Vulkan/Nvk/Anv、`build()` 产出 `libstela-anv.a`；llvm.rs/sysroot.rs
  构造器补齐）。`cargo build -p xtask` 干净；nvk 单测全过（唯一失败的
  oracles 测试因本副本无 root .git，无关）。
  - Next Step: 手动 fetch mesa/llvm/libdrm（fetch.rs 因无 root .git 失效），
    确认 ANV meson 目标名，跑通 `cargo xtask gpu nvk` 出 `libstela-anv.a`。
- tasks 8-11: ANV compile, stela-mesa link, Metal, boot + maintenance.

## Unblock: manual fetch of pinned submodules (2026-11-19)
- Root copy has no `.git`, so `fetch.rs::submodules()` cannot read gitlink
  pins. Pins recovered from a sibling worktree's index
  (`/Volumes/未命名/stela-work/stela-super`, `git ls-files --stage`):
  - libdrm `cb4669af` (tag libdrm-2.4.133), llvm `7a941dfb` (llvmorg-23.1.4),
    mesa `ddaf85e3`.
- Replicated `fetch.rs::checkout()` by hand in each empty `third_party/<name>`:
  `git init` + remote add + `sparse-checkout set --no-cone` (from
  `<name>.sparse`) + shallow blobless fetch of the pin + `checkout -B stela` +
  `git am --3way` of `third_party/patches/<name>/*.patch` (mesa: all 29 apply
  cleanly; libdrm/llvm have no patch dirs).
- `mesa/meson.build` carries `stela_compilers`/`with_stela_intel` from patch
  0002. ANV is driven by `-Dvulkan-drivers=nouveau,intel` →
  `with_intel_vk` → `src/intel/vulkan` → `libvulkan_intel` (the .so is named
  `libvulkan_intel.so`, **not** `libvulkan_anv.so` — DRIVERS fixed).
- libdrm 2.4.133 has no `xe/` dir and no `xe_drm.h`; ANV's xe UAPI comes from
  Mesa's own tree, so the `/xe/*.h` sparse pattern is a harmless no-op at
  this pin.
- Toolchain gaps fixed for `cargo xtask gpu nvk` on this host:
  - `llvm-tools` rust component absent from both Tsinghua and official dist
    mirrors for 1.99.1 → fetched official tarball by hand, flattened into
    `~/.rustup/.../x86_64-apple-darwin/bin` + `lib` (rpath
    `@loader_path/../lib`).
  - `x86_64-unknown-linux-musl` rust-std missing (meson's machine Rust probe)
    → same manual install, flattened.
  - Mesa configure-time `has_function('dl_iterate_phdr')` hard-errors for
    ANV: Stela's libc had every other dl* stub ("the image is linked whole")
    but not this one, even though `ADDED_DEFINES` already declared
    `HAVE_DL_ITERATE_PHDR` on the premise it exists. Added a no-op
    `dl_iterate_phdr` stub to `compat/libc/libc.c` + `dlfcn.h` (needs
    `#include <stddef.h>` like sibling headers, else `size_t` in the callback
    type conflicts at later inclusion).

## Decisions Added
| 2026-11-19 | Submodule pins read from the sibling `stela-super` worktree's git index, not guessed tags | Only source of the exact gitlink pins; libdrm/llvm pins equal their NOTICE tags, mesa pin `ddaf85e3` is tag-less (NOTICE "Mesa 26.2.5" is the version only). |
| 2026-11-19 | ANV driver .so meson target is `libvulkan_intel.so`; whole-archive entries are `libanv_common_a`, `libanv_per_hw_ver*`, `libanv_drirc` | `ninja -t inputs` targets and `WHOLE_LIBRARIES` name-matching must use the real meson target names; `libanv_a`/`libvulkan_anv.so` do not exist. |
| 2026-11-19 | No-op `dl_iterate_phdr` stub in Stela's freestanding libc | Mesa's only caller (`src/util/build_id.c`) is replaced by the `compat/mesa/build_id.c` stand-in; the symbol exists so meson's configure-time link probe can define `HAVE_DL_ITERATE_PHDR`, matching the pre-existing `ADDED_DEFINES` entry. |

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| rustup 1.99.1 channel 404 / manifest missing | 1 | Use `RUSTUP_TOOLCHAIN=stable-x86_64-apple-darwin` (== 1.99.1) |
| LLVM "No space left on device" building xtask | 1 | `cargo clean` (frees ~3.7 GB target) |
| `cargo xtask gpu fetch` fails: "not a git repository" at repo root | 1 | Root is a symlinked, non-git copy; apply sparse inside `third_party/linux` submodule directly |
| `mm/vma.c: vma_internal.h not found` | 1 | add `/mm/vma_internal.h` to `linux.sparse`, re-apply in submodule |
| `vma_internal.h: asm/tlb.h not found` | 1 | new `crates/stela-linux/src/compat/asm/tlb.h` |
| `drm_vma_test` link: 25 undefined MM symbols | 1 | traps in `unsupported.c` (22 fns + 3 scalars) + OPEN_XE rewrite to 103 |
| Machine freeze / load ~7 during builds | 1 | 12-thread clang spike + memory pressure; C objects now cached, later builds only rerun the build script |
| `xe_bo_test` SIGILL at `dma_resv_fini` | 1 | `kvfree_call_rcu` range check: `kmalloc_size_roundup` is identity so `rcu` out of tracked range; drop the free path (host reclaims heap) |

## Decisions Made
| Date | Decision | Rationale |
|------|----------|----------|
| 2026-11-18 | `asm/tlb.h` as a compat arch header (x86 content, CONFIG_BROADCAST_TLB_FLUSH off) | arch x86 kernel headers are not on the include path; Stela supplies arch-side asm headers via `src/compat/asm/` (cf. `mmu_context.h`, `tlbflush.h`). |
| 2026-11-18 | xe tests exercise the env's `dma_resv`/`dma_fence` primitives, not the driver | Build discipline is "test the environment, link no driver"; bo/sched behavior reduces to resv reservation + fence signaling, both `T`-implemented in the env archives. |
| 2026-11-18 | Skip `dma_resv_fini`/`dma_fence_put` free paths in xe tests | Their `kfree_rcu` teardown traps under the bare hosted owner; the state-machine assertions need no teardown, so the host reclaims the heap instead. |

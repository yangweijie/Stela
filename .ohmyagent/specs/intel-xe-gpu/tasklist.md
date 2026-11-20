# 需求实施计划 — Intel Xe-LPG GPU 全链路

## Phase 1 — 内核层：xe 驱动进入 Stela Linux 环境

- [ ] 1. 增补 `third_party/linux.sparse` 与 `third_party/libdrm.sparse`
  - `linux.sparse` 加入 `/drivers/gpu/drm/xe/`
  - 按 xe Kbuild 实际 `#include` 收敛增补 `i915/display` 相关条目
  - `libdrm.sparse` 增补 `xe_drm.h` UAPI 头（ANV 所需）
  - 与 NOTICE 条目对齐：创建 `crates/stela-driver-gpu/src/intel/wopcm/storage/` 占位目录
  - 运行 `cargo xtask gpu fetch` 验证 sparse 模式有效且 xe 树完整

- [ ] 2. 定义 Kconfig 并校验 xe 编译单元
  - 在 `stela-linux/src/compat/generated/autoconf.h` 增加 `#define CONFIG_DRM_XE 1`
  - 按 xe Kbuild 的 `ifdef CONFIG_*` 解析结果补全依赖符号（`CONFIG_DRM_I915` 等）
  - 确认现有 `CONFIG_DRM_XE_*` 参数值（L74–90）与新定义无冲突

- [ ] 3. 扩展 Kbuild 子集解析器（仅在需要时）
  - 用 xe 目录下的 Makefile/Kbuild 运行 `kbuild.rs` 解析，记录拒绝语句
  - 在 `build/kbuild.rs` 中**最小化**扩展接受的语句形式，保持拒绝策略不变
  - 记录每个扩展的理由（构建期文档）
  - 参考：design.md 第 2 节（`stela-linux`）

- [ ] 4. 新建 `build/xe.rs` — xe 端口模块
  - 仿 `build/nouveau.rs` 结构：
    - `Kbuild::read(third_party/linux/drivers/gpu/drm/xe, config)` 解析 xe Kbuild
    - 定义 `OPEN_XE` 清单（服务名 → 符号），覆盖 xe 引用而环境缺失的所有符号
    - initcall 单元 `xe_drm`：`UnitSpec` 挂 gpu slice、group `xe`（ordinal 顺延）
    - `check_imports` 校验新 archive `libstela-intel-xe.a` 的未满足导入
    - `port(&mut Linux)` 入口，编译并输出 archive 路径
  - 在 `build/native.rs` 的 `Linux` 结构体增加 xe 相关字段（仿 `captured` 字段）
  - 在 `build.rs` 增加 `#[cfg(feature = "xe-port")] mod xe` 与 `port` 调用
  - 在 `Cargo.toml` 增加 feature `xe-port = ["linux-kernel"]`
  - 透传到 `stela-drivers/Cargo.toml`
  - 参考：design.md 第 2、3 节

- [ ] 5. 注册 xe 的 initcall 捕获单元与共享 DRM 单元
  - 在 `build/native.rs` 的 `DRM_UNITS` 末尾或新建 `XE_UNITS` 常量
  - 确认 `COMMON` 共享队列与 xe 依赖的 `drm_exec`/`drm_gpuvm`/`drm_sched`/`ttm` 已在 `DRM_SOURCES` 中
  - 若 xe 需要新的 DRM 公共文件，增补 `DRM_SOURCES`
  - 确保 `environment_units()` 链式包含 xe 单元

- [ ] 6. 编写 xe 的 hosted C 测试
  - `src/compat/linux/stela/xe_bo_test.c`：xe_bo 页表分配/状态机（对齐 `drm_mm_test.c` 位置）
  - `src/compat/linux/stela/xe_sched_test.c`：fence 信号/`xe_sched` 行为
  - 在 `build/native.rs::tests` 中仿 `linux_drm_mm` 注册到 `Tests`
  - 参考：requirements.md R5.3

- [ ] 7. 检查点 — 内核层
  - 确保所有测试通过，如有疑问请询问用户
  - `cargo build -p stela-driver-gpu --features xe-port` 通过 `check_imports`
  - `cargo test -p stela-driver-gpu --features xe-port` 的 C 测试通过

## Phase 2 — Vulkan/Metal 层：ANV 作为第二后端

- [ ] 8. 扩展 Mesa xtask 构建 — ANV 编译
  - `xtask/src/gpu/nvk.rs`：
    - `OPTIONS` 的 `-Dvulkan-drivers=nouveau` 改为 `-Dvulkan-drivers=nouveau,intel`
    - `DRIVERS` 增补 `src/intel/vulkan/libvulkan_anv.so`
    - 归档产物增加 `libstela-anv.a`（与 `libstela-nvk.a` 并列）
  - 确认 `src/intel/vulkan/` 的 meson 目标在本项目 `meson.build` 子集下可解析
  - 若 ANV 需要额外 libdrm 符号，确认 `libdrm.sparse` 已包含
  - 参考：design.md 第 4 节

- [ ] 9. 扩展 `stela-mesa` 链接
  - `crates/stela-mesa/build.rs`：
    - 链接清单增补 `libstela-anv`（与 `libstela-nvk` 并列）
    - `stela_fingerprint` 的输入列表增补 `libstela-anv.a`
  - 确认 whole-archive 链接策略对 ANV 适用（ANV 的入口点是否由弱引用表驱动）

- [ ] 10. 扩展 `stela-driver-gpu::metal` — ANV 后端
  - `metal/open.rs`：
    - 在 Intel device 下走 ANV 入口路径（由 `GpuStack` vendor 判定）
    - 保持 `metal/vulkan.rs` 内部 Vulkan 边界**零改动**
  - `stack.rs`：
    - `Vendor::Intel` 分支在 `xe-port` feature 下返回 xe 栈
    - 非 Xe-LPG device 维持拒绝
  - 确认 `AirCompiler` 的 `gfx_verx10` 选择器覆盖 Xe-LPG 的 120 代（`src/intel/dispatch/compute120.c` 已存在）
  - 参考：design.md 第 3、4 节

- [ ] 11. 新建 Intel Xe-LPG device 表
  - 创建 `crates/stela-driver-gpu/src/intel/devices.rs`
  - 内容：TGL/ADL/RLC 的 device ID 三元组（家族 + PCI device + iGPU 判定）
  - 导出为 `pub` 供 boot 文案与维护层复用
  - 参考：design.md 第 3 节（device 表）

- [ ] 12. 更新 `Adapter::unavailable_reason` 与 `gpu_status.rs`
  - `stela-driver-gpu/src/lib.rs`：
    - `Vendor::Intel` 的 `unavailable_reason` 改为按 device 判定
    - Xe-LPG 表内 → 返回空字符串（可用）
    - 表外 → "Intel GPU 仅支持 Xe-LPG（11–13 代 iGPU）"
  - `stela-boot-core/src/gpu_status.rs`：
    - 新增 `XguStart` 结构（解析 xe `gu`/`guc` 日志行）
    - `Reason` 复用 `MissingFirmware` 语义
    - `unused` 文案按 R4.2
    - 仿现有测试逐字符串断言
  - 参考：design.md 第 3、5 节；requirements.md R1.4、R4

- [ ] 13. 检查点 — Vulkan/Metal 层
  - 确保所有测试通过，如有疑问请询问用户
  - `cargo xtask gpu` 构建出 `libstela-anv.a`
  - `cargo test -p stela-driver-gpu --features xe-port,metal` 通过
  - `cargo test -p stela-boot-core` 的 `gpu_status` 测试通过

## Phase 3 — Boot 引擎与维护层

- [ ] 14. 扩展 `stela-boot` 引擎 — xe 栈的 probe/固件/启动路径
  - `stela-boot/src/engine/gpu.rs` 及其子模块：
    - xe 栈的 probe 入口：通过 `catalogue::PciFirmware` 租约机制授予固件
    - GuC/HuC/DMC 固件缺失时记录 `MissingFirmware`（同 GSP 路径）
    - `firmware_requests.rs`：`fixable` 语义扩展到 GuC 缺失
  - `stela-boot/Cargo.toml`：增加 `xe-port` feature 透传
  - 参考：design.md 第 5 节；requirements.md R2、R4.1

- [ ] 15. 扩展 `stela-gpu-maintenance` — `stela repair` 支持 Xe-LPG 固件
  - `stela-gpu-maintenance/main.rs` + `executable.rs`：
    - 新增 Xe-LPG 家族固件清单（TGL/ADL/RLC 的 GuC/HuC/DMC 文件）
    - 固件 SHA 与版本匹配校验（对齐 `catalogue::FirmwareTarget` 校验）
    - 写 USB 前校验 `FirmwareTarget` 名称与 xe 驱动请求一致
  - `stela-gpu-maintenance/policy.rs`：若固件清单在 policy 层定义，在此增补
  - 参考：design.md 第 5 节；requirements.md R2.4

- [ ] 16. 更新 boot 屏支持面文案
  - `stela-boot-core/src/gpu_status.rs`：
    - `SUPPORTED` 常量扩展（当前仅 NVIDIA GTX 16/RTX 20-50）
    - `none` 文案在 Intel Xe-LPG 存在时说明支持
    - 非 Xe-LPG Intel device 的 `unused` 文案引用 device 表
  - 参考：requirements.md R4.2

- [ ] 17. 更新 NOTICE
  - 创建 `crates/stela-driver-gpu/src/intel/wopcm/storage/` 目录
  - 内容：GuC 固件 backing 参考说明（对齐 NOTICE L380 预留条目）
  - 在 NOTICE 中补充 xe 驱动与 ANV 的许可证条目

- [ ] 18. 检查点 — 全链路
  - 确保所有测试通过，如有疑问请询问用户
  - `cargo xtask dist`（完整 `stela.efi`）在启用 `xe-port` 的 feature 组合下编译通过
  - 各层 C/Rust 测试全部通过
  - `check_imports` OPEN_XE 清单与实际导入一致

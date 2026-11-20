# Requirements Document — Intel Xe-LPG iGPU 支持（全链路）

Feature Name: intel-xe-gpu
Updated: 2026-11-16

## Introduction

Stela 目前在 x86-64 PC 上运行 macOS（M2 Mac mini 型号），GPU 支持仅限 NVIDIA
（Turing–Blackwell），通过 Linux 环境中的 nouveau + Mesa NVK（Vulkan）驱动
NVIDIA GPU，经内部 Vulkan 边界支撑 guest 的 Metal 设备。Intel 平台在 boot 屏
被报告为 "Intel i915/xe are not ported to Stela"，但编译器侧的 Intel AIR 端口
（`crates/stela-driver-gpu/src/intel/`）、Kconfig 参数值、NOTICE 固件条目
（`src/intel/wopcm/storage/` GuC 固件 backing 参考）已经就位。

本特性把 Intel Xe 驱动栈补全到与 NVIDIA 等价的全链路：

1. **内核层**：Linux 环境（stela-linux）运行未改动的 `drivers/gpu/drm/xe`，
   参照 nouveau 端口的 Kbuild + initcall 捕获 + OPEN 符号缺口模式。
2. **Vulkan 层**：Mesa ANV（`src/intel/vulkan`）加入 xtask gpu 构建，
   与 NVK 并列作为内部 Vulkan 边界的一个后端。
3. **Metal 层**：Stela 的 Metal 设备经 `AirCompiler`（AIR→NIR，Intel 代
   编码器已存在于 `src/intel/hosted`）服务 ANV。
4. **boot 层**：`stela-boot` 引擎为 Intel 走 xe 栈的探测、固件（USB）、
   启动流程；boot 屏文案区分 Xe-LPG 支持/不支持。
5. **维护层**：`stela-gpu-maintenance`（`stela repair`）把 GuC/HuC/DMC
   固件装入 USB。

## Glossary

- **Xe-LPG**：内核 xe 驱动对 Intel 第 11–13 代 iGPU（Tiger Lake、
  Alder Lake、Raptor Lake）的平台代号。
- **GuC / HuC / DMC**：xe 驱动加载的 GPU 微控制器/显示固件；由
  `CONFIG_FW_LOADER` 的固件加载器从主机文件系统取用。
- **OPEN 符号**：nouveau 端口模式（`build/nouveau.rs::OPEN`）中，驱动
  引用而 Stela Linux 环境未提供（或仅为 trap）的内核服务符号清单；
  构建期由 `check_imports` 对照校验。
- **内部 Vulkan 边界**：`stela-driver-gpu/src/metal/vulkan.rs` 声明的
  设备/命令/对象边界，NVK/ANV 作为后端实现。
- **stela repair**：`stela-gpu-maintenance` 在 macOS 侧校验并安装 guest
  GPU 组件（含 USB 固件）的维护通道。

## Requirements

### R1. Intel Xe-LPG 探测与内核绑定

**User Story:** AS 在带 11–13 代 Intel iGPU 的 PC 上 boot 的用户, I want
Stela 的内核环境加载 xe 驱动并绑定该 iGPU, so that guest 的 Metal 有
真实 GPU 后端。

#### Acceptance Criteria

1. WHEN Linux 环境启动，系统 SHALL 在 `third_party/linux` 的
   `drivers/gpu/drm/xe` 源码上完成 Kbuild 子集解析、编译与 initcall
   捕获，参照 `build/nouveau.rs` 的模式。
2. IF 适配器为 Xe-LPG（TGL/ADL/RLC iGPU，PCI vendor `0x8086` +
   对应 device 表），系统 SHALL 由 xe 驱动 probe 并注册 DRM 设备。
3. IF 适配器为 Xe-LPG 以外的 Intel 显示设备（Arc dGPU、第 14 代及以后
   iGPU、i915 世代），系统 SHALL 拒绝 probe 并在 boot 屏说明该设备
   不在 Xe-LPG 支持面内。
4. WHEN 驱动完成 probe，系统 SHALL 使 `stela-drivers::gpu` 的
   `Adapter::unavailable_reason` 对 Intel 不再报告 "not ported"，
   而报告驱动实际遇到的启动失败原因（固件缺失、reset 失败等）。

### R2. GuC/HuC/DMC 固件经 USB 提供

**User Story:** AS 缺少 GPU 固件的 USB 用户, I want 通过 `stela repair`
把 Xe 固件补进 USB, so that 无需改动镜像即可修复。

#### Acceptance Criteria

1. WHEN Linux 环境的固件加载器请求 `intel/guc_*.uc`、`intel/huc_*.uc`、
   `intel/lnl_dmc_*`（及 Xe-LPG 对应家族名）时，系统 SHALL 从 USB 的
   `stela` 固件区读取并以 catalogue 的 `PciFirmware` 租约机制托管。
2. IF 对应固件缺失，系统 SHALL 记录 boot 屏可操作文案（指向
   `stela repair`），行为与 NVIDIA GSP 固件缺失一致。
3. IF 固件版本与 device 不匹配（如 ADL 载 TGL 的 GuC），系统 SHALL
   拒绝加载并报告版本不符。
4. WHEN `stela-gpu-maintenance` 执行 repair，系统 SHALL 把 Xe-LPG
   各家族所需的 GuC/HuC/DMC 固件写入 USB，并在 NOTICE 中保留
   `src/intel/wopcm/storage/`（xe GuC 固件 backing 参考）条目。

### R3. Mesa ANV 作为内部 Vulkan 后端

**User Story:** AS Stela 维护者, I want `cargo xtask gpu` 构建
`libvulkan_anv.so` 并与 NVK 并列归档, so that Metal 设备可以经
ANV 服务 Intel GPU。

#### Acceptance Criteria

1. WHEN `xtask gpu` 构建 Mesa，系统 SHALL 编译
   `src/intel/vulkan/libvulkan_anv`（meson option
   `-Dvulkan-drivers=intel`），并归档 `libstela-anv.a` 到
   `target/gpu/nvk/`（或并行目录）供 `stela-mesa` 链接。
2. WHEN 链接内部 Vulkan 边界，系统 SHALL 保持
   `metal/vulkan.rs` 的 API 不变：ANV 经同一
   `Backend`/`NativeBackend` 边界服务，NIR 直通不重译。
3. IF 构建缺少 libdrm 的 `xe_drm.h` UAPI 头，系统 SHALL 通过
   `third_party/libdrm.sparse` 增补该头（与 `amdgpu/*.h` 并列）。
4. WHEN 编译器路径运行，系统 SHALL 使用
   `crates/stela-driver-gpu/src/compiler/meson.build` 中已有的
   `stela_intel_*` 目标（AIR 编译/验证、dispatch 打包器 gen 70–120），
   不复制其源码。

### R4. Boot 引擎与 boot 屏

**User Story:** AS 用 Intel iGPU 的 PC 的 boot 用户, I want boot 屏
准确说明 GPU 状态, so that 我在另一台电脑上能判断如何修复。

#### Acceptance Criteria

1. WHEN `stela-boot` 引擎的 GPU 栈选择器面对 Intel 适配器且 xe 栈启用，
   系统 SHALL 以 xe 驱动 + ANV 组成 `GpuStack`，并在缺固件时报告
   `MissingFirmware` 语义（`gpu_requests.rs`/`gpu_status.rs` 现有
   `Reason` 枚举复用）。
2. WHEN xe 栈未启用（非 Xe-LPG device），系统 SHALL 沿用
   "unused" 文案并说明支持面（Xe-LPG 11–13 代 iGPU）。
3. WHEN 固件加载失败或 GuC boot 失败，系统 SHALL 输出与 GSP 失败
   等价的 boot 日志行（xe 的 `xe_guc` 日志解析），使
   `driver_stopped` 一类文案可复用。

### R5. 正确性与可测性

**User Story:** AS 审查者, I want 每个层的行为都有 hosted 测试, so that
回归在 CI 中可发现。

#### Acceptance Criteria

1. WHEN Linux 环境构建，系统 SHALL 为 xe 编译单元提供
   `linux_capture` 的 initcall 捕获与 `check_imports` OPEN 清单，
   OPEN 清单的任何漂移使构建失败（与 nouveau 相同纪律）。
2. WHEN 运行 xtask 测试，系统 SHALL 保留
   `src/intel/tests/` 全部 meson 测试（AIR 编译、渲染、dispatch、
   surface/sampler/image）在 `stela` suite 中通过。
3. WHEN 内核测试运行，系统 SHALL 至少覆盖 xe_bo 页表/分配与
   fence 信号两个 hosted C 测试（置于
   `src/compat/linux/stela/` 与现有 `drm_mm_test` 并列）。
4. IF 任一新增 OPEN 符号被 xe 引用且环境未提供，系统 SHALL 在构建期
   报出符号名而非静默链接空实现。

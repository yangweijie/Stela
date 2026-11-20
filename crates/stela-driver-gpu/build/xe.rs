//! The Xe driver's Kbuild composite, compiled unchanged in Stela's Linux
//! environment, and the kernel services it imports that the environment does
//! not yet supply.
use super::kbuild::{Config, Kbuild};
use super::native::{self, Linux};
use std::{env, fs, path::Path, thread};
use stela_c_build::linux::Module;
use stela_c_build::linux_capture::{self as initcalls, Projection, Unit, UnitSpec};

const XE: &str = "../../third_party/linux/drivers/gpu/drm/xe";
const AUTOCONF: &str = "../stela-linux/src/compat/generated/autoconf.h";
const MODULE: Module<'static> = Module {
    name: "xe",
    file: "drivers/gpu/drm/xe/xe",
};
/// The Kbuild composite: the `xe` module built-in.
const COMPOSITES: [&str; 1] = ["xe"];

/// The kernel services the composite imports that Stela's Linux environment
/// lacks, or defines only as a trap, by service. Building fails when the
/// imports change, so each supplied service leaves this list with its change.
/// The set must equal `check_imports`' computed open symbols exactly.
const OPEN_XE: &[(&str, &[&str])] = &[
    // I2C: xe_amc polls its AMC mailbox and xe_i2c wires its adapter over an
    // I2C bus. The environment's `i2c.c` supplies the client helpers and the
    // bus transfer (`i2c_master_send`/`_recv` are `static inline` over
    // `i2c_transfer`), but not the adapter check, the bus type constant, nor
    // the buffered transfer with flags.
    (
        "I2C",
        &[
            "i2c_verify_adapter",
            "i2c_bus_type",
            "i2c_transfer_buffer_flags",
        ],
    ),
    // The platform device the I2C adapter registers as; `i2c.c` traps only
    // the unregister half.
    (
        "platform devices",
        &[
            "platform_device_alloc",
            "platform_device_add",
            "platform_device_put",
            "platform_device_unregister",
        ],
    ),
    // PCIe and platform resource probing for the device's BARs, PME and
    // reBAR sizing.
    (
        "PCIe and platform resources",
        &[
            "pci_alloc_irq_vectors",
            "pci_assign_unassigned_bus_resources",
            "pci_bus_resource_n",
            "pci_iomap",
            "pci_iounmap",
            "pci_irq_vector",
            "pci_msix_vec_count",
            "pci_pme_capable",
            "pci_rebar_bytes_to_size",
            "pci_rebar_get_max_size",
            "pci_rebar_get_possible_sizes",
            "pci_rebar_size_supported",
            "pci_rebar_size_to_bytes",
            "pci_resize_resource",
            "pcim_enable_device",
        ],
    ),
    // IRQ wiring the driver requests and tears down.
    (
        "IRQ wiring",
        &[
            "__irq_alloc_descs",
            "irq_free_descs",
            "irq_set_chip_and_handler_name",
            "irq_set_chip_data",
            "synchronize_irq",
            "handle_simple_irq",
            "generic_handle_irq_safe",
        ],
    ),
    // devres-allocated device resources and the DMA maps xe_bo installs.
    (
        "devres and DMA",
        &[
            "__devm_regmap_init",
            "devm_kmalloc",
            "devm_ioremap_wc",
            "devm_device_add_group",
            "devm_remove_action_nowarn",
            "dma_map_resource",
            "dma_unmap_resource",
        ],
    ),
    // VMA, anon_vma and shmem maintenance that `mm/vma.o` references and the
    // MM provider files Stela deliberately does not build; the environment
    // traps them so a reached path stops rather than inventing an answer.
    (
        "mm, VMA and shmem (trapped)",
        &[
            "__anon_vma_prepare",
            "anon_vma_clone",
            "anon_vma_interval_tree_insert",
            "anon_vma_interval_tree_remove",
            "cap_vm_enough_memory",
            "compat_vma_mmap",
            "find_vma_intersection",
            "find_vma_prev",
            "folio_clear_dirty_for_io",
            "free_pgtables",
            "may_expand_vm",
            "mmap_action_complete",
            "mmap_action_prepare",
            "mlock_future_ok",
            "mm_get_unmapped_area",
            "__vm_enough_memory",
            "shmem_read_folio_gfp",
            "shmem_read_mapping_page_gfp",
            "shmem_truncate_range",
            "shmem_writeout",
            "shmem_zero_setup",
            "tlb_finish_mmu",
            "tlb_gather_mmu",
            "unlink_anon_vmas",
            "unmap_vmas",
            "vm_stat_account",
            "vma_interval_tree_insert",
            "vma_interval_tree_remove",
            "vma_set_page_prot",
        ],
    ),
    // The GPU's own memory allocators: the buddy and suballoc pools and the
    // mempool Stela leaves to the platform.
    (
        "buddy, suballoc and mempool",
        &[
            "gpu_buddy_alloc_blocks",
            "gpu_buddy_fini",
            "gpu_buddy_free_list",
            "gpu_buddy_init",
            "drm_buddy_print",
            "drm_suballoc_alloc",
            "drm_suballoc_free",
            "drm_suballoc_insert",
            "drm_suballoc_manager_fini",
            "drm_suballoc_manager_init",
            "drm_suballoc_new",
            "mempool_alloc_noprof",
            "mempool_exit",
            "mempool_free",
            "mempool_init_noprof",
            "mempool_kfree",
            "mempool_kmalloc",
        ],
    ),
    // Auxiliary device registration for the AMC mailbox and the bus notifiers
    // that observe it.
    (
        "auxiliary bus and notifiers",
        &[
            "auxiliary_device_init",
            "__auxiliary_device_add",
            "bus_register_notifier",
            "bus_unregister_notifier",
        ],
    ),
    // File handles, device attributes and small allocator helpers.
    (
        "files, attributes and helpers",
        &[
            "anon_inode_getfd",
            "device_create_file",
            "device_remove_file",
            "mmput",
            "string_get_size",
            "bsearch",
            "bitmap_free",
            "bitmap_zalloc",
            "stela_linux_reopen_unowned_path",
            "__bzero",
        ],
    ),
    // A kthread that runs with a user mm, raw time, and fwnode software
    // nodes.
    (
        "kthread, time and firmware nodes",
        &[
            "kthread_use_mm",
            "kthread_unuse_mm",
            "ktime_get_raw",
            "fwnode_create_software_node",
            "fwnode_remove_software_node",
            "down_read_interruptible",
            "vmf_insert_pfn",
        ],
    ),
];

/// The unit of the xe driver's own `module_init`.
const INITCALLS: UnitSpec = UnitSpec {
    scope: stela_c_build::linux_capture::Scope {
        slice: "gpu",
        group: "xe",
        group_ordinal: 9,
        unit_ordinal: 1,
        global_ordinal: 9,
    },
    source: "drivers/gpu/drm/xe/xe_module",
    module: MODULE.name,
    file: MODULE.file,
};
fn initcalls_unit() -> Unit {
    INITCALLS.into()
}

pub fn port(linux: &mut Linux) {
    let config = Config::parse(&fs::read_to_string(AUTOCONF).expect("read Stela's Kconfig header"))
        .unwrap_or_else(|error| panic!("{AUTOCONF}: {error}"));
    let kbuild = Kbuild::read(Path::new(XE), &config).unwrap_or_else(|error| panic!("{error}"));
    for file in &kbuild.files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    let mut sources = Vec::new();
    for composite in COMPOSITES {
        let objects = kbuild
            .objects(composite)
            .unwrap_or_else(|error| panic!("{error}"));
        sources.extend(
            objects
                .iter()
                .map(|object| Path::new(XE).join(object).with_extension("c")),
        );
    }
    let includes = kbuild
        .includes
        .iter()
        .map(|directory| {
            let relative = directory
                .strip_prefix(XE)
                .expect("Kbuild includes lie in the xe tree");
            Path::new("xe").join(relative).display().to_string()
        })
        .collect::<Vec<_>>();
    let includes = includes.iter().map(String::as_str).collect::<Vec<_>>();
    // Compiled below, with its registrations captured.
    sources.retain(|source| *source != initcalls_unit().path());
    let mut build = stela_c_build::native::configure();
    linux.environment.apply(
        &mut build,
        None,
        &native::drm_includes(&includes),
        Some(&MODULE),
    );
    stela_c_build::linux_build::upstream_warnings(&mut build);
    // As Kbuild builds every profile: Linux relies on the optimizer to drop
    // the calls its configuration disables.
    build.opt_level(2).cargo_metadata(false);
    let jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|jobs| jobs.parse().ok())
        .unwrap_or(1)
        .max(1);
    let objects = thread::scope(|scope| {
        sources
            .chunks(sources.len().div_ceil(jobs))
            .map(|chunk| {
                let build = &build;
                scope.spawn(move || build.clone().files(chunk).compile_intermediates())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|compiling| compiling.join().expect("a compiling thread"))
            .collect::<Vec<_>>()
    });
    let mut captured = linux.take_captured();
    let environment_count = captured.len();
    let compiler = initcalls::compiler(&build);
    let placement = initcalls::Placement::new(
        &initcalls_unit().path(),
        &stela_c_build::linux_build::out_dir(),
        &[
            Path::new("../.."),
            compiler.parent().expect("compiler root"),
        ],
    )
    .expect("xe source placement");
    captured.push(initcalls::compile(
        &build,
        Path::new("../stela-linux/src/compat/stela/registration.h"),
        INITCALLS,
        &placement,
    ));
    let mut expected = native::environment_units();
    expected.push(INITCALLS);
    let image = initcalls::source(
        &captured,
        Projection {
            symbol: "stela_linux_xe_image",
            expected: &expected,
            imported_units: environment_count,
            descriptors_only: false,
        },
    );
    build
        .objects(objects)
        .objects(
            captured
                .iter()
                .skip(environment_count)
                .map(|unit| unit.object()),
        )
        .file(image)
        .compile("stela-intel-xe");
    let archive = stela_c_build::linux_build::out_dir().join("libstela-intel-xe.a");
    native::check_imports(
        &archive,
        &[&linux.archive, &linux.common_archive],
        OPEN_XE,
        "xe",
    );
    let output = stela_c_build::linux_build::out_dir();
    let digest = initcalls::write(
        &output.join("captured-units.bin"),
        &captured[initcalls::COMMON.len()..],
    );
    println!("cargo:output={}", output.display());
    println!("cargo:cohort_sha256={digest}");
    // Hosted programs test the environment and link no driver.
    if env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "uefi") {
        println!("cargo:rustc-link-lib=static=stela-intel-xe");
    }
}

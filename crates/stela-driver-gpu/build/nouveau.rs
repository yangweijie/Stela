//! nouveau: the `nouveau-y` composite of its own Kbuild, compiled unchanged in
//! Stela's Linux environment, and the kernel services it imports that the
//! environment does not yet supply.
use super::kbuild::{Config, Kbuild};
use super::native::{self, Linux};
use std::{env, fs, path::Path, thread};
use stela_c_build::linux::Module;
use stela_c_build::linux_capture::{self as initcalls, Projection, Unit, UnitSpec};

const NOUVEAU: &str = "../../third_party/linux/drivers/gpu/drm/nouveau";
const AUTOCONF: &str = "../stela-linux/src/compat/generated/autoconf.h";
const MODULE: Module<'static> = Module {
    name: "nouveau",
    file: "drivers/gpu/drm/nouveau/nouveau",
};
/// Kbuild's composite: nouveau's DRM layer over NVIF and NVKM.
const COMPOSITES: [&str; 1] = ["nouveau"];

/// The kernel services the composites import that Stela's Linux environment
/// lacks, or defines only as a trap, by service. Building fails when the
/// imports change, so each supplied service leaves this list with its change.
const OPEN: &[(&str, &[&str])] = &[
    // Traps nothing nouveau runs reaches. Shmem-backed pages: TTM allocates
    // from its own pool and Stela never swaps it out.
    (
        "shmem and page cache",
        &[
            "folio_clear_dirty_for_io",
            "mm_get_unmapped_area",
            "shmem_read_folio_gfp",
            "shmem_read_mapping_page_gfp",
            "shmem_truncate_range",
            "shmem_writeout",
        ],
    ),
    // Nothing tears a pseudo filesystem's superblock down.
    (
        "reopening a file without a VFS path",
        &["stela_linux_reopen_unowned_path"],
    ),
    (
        "HDMI audio",
        &["device_link_add", "platform_device_unregister"],
    ),
    // Process VMA, anon_vma and TLB bookkeeping TTM's GEM and shmem paths
    // reference: Stela's GPU keeps its memory in its own TTM pool and never
    // maps a process address space, so these link but never run.
    (
        "process VMA and TLB bookkeeping",
        &[
            "__anon_vma_prepare",
            "__vm_enough_memory",
            "anon_vma_clone",
            "anon_vma_interval_tree_insert",
            "anon_vma_interval_tree_remove",
            "cap_vm_enough_memory",
            "compat_vma_mmap",
            "find_vma_intersection",
            "find_vma_prev",
            "free_pgtables",
            "may_expand_vm",
            "mlock_future_ok",
            "mmap_action_complete",
            "mmap_action_prepare",
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
];

/// The unit of nouveau's own `module_init`.
const INITCALLS: UnitSpec = UnitSpec {
    scope: stela_c_build::linux_capture::Scope {
        slice: "gpu",
        group: "nouveau",
        group_ordinal: 8,
        unit_ordinal: 1,
        global_ordinal: 8,
    },
    source: "drivers/gpu/drm/nouveau/nouveau_drm",
    module: MODULE.name,
    file: MODULE.file,
};
fn initcalls_unit() -> Unit {
    INITCALLS.into()
}

pub fn port(linux: &mut Linux) {
    let config = Config::parse(&fs::read_to_string(AUTOCONF).expect("read Stela's Kconfig header"))
        .unwrap_or_else(|error| panic!("{AUTOCONF}: {error}"));
    let kbuild =
        Kbuild::read(Path::new(NOUVEAU), &config).unwrap_or_else(|error| panic!("{error}"));
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
                .map(|object| Path::new(NOUVEAU).join(object).with_extension("c")),
        );
    }
    let includes = kbuild
        .includes
        .iter()
        .map(|directory| {
            let relative = directory
                .strip_prefix(NOUVEAU)
                .expect("Kbuild includes lie in nouveau's tree");
            Path::new("nouveau").join(relative).display().to_string()
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
    .expect("Nouveau source placement");
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
            symbol: "stela_linux_nouveau_image",
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
        .compile("stela-nouveau-nvkm");
    let archive = stela_c_build::linux_build::out_dir().join("libstela-nouveau-nvkm.a");
    native::check_imports(
        &archive,
        &[&linux.archive, &linux.common_archive],
        OPEN,
        "nouveau",
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
        println!("cargo:rustc-link-lib=static=stela-nouveau-nvkm");
    }
}

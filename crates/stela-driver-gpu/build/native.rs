//! GPU Linux class sources over the canonical shared kernel archive.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
use std::path::Path;
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};
#[cfg(feature = "linux-kernel")]
use std::{env, path::PathBuf};
#[cfg(feature = "linux-kernel")]
use stela_c_build::linux_build::{archive, linux_archive, out_dir, sources};
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
use stela_c_build::{
    linux_build::{upstream_build, upstream_warnings},
    linux_capture::{self, COMMON, Captured, Import, Projection, Unit, UnitSpec},
};
#[cfg(feature = "linux-kernel")]
pub const LINUX: &str = "../../third_party/linux";

pub fn require_sources() {
    #[cfg(feature = "linux-kernel")]
    require_source(LINUX);
}
fn require_source(source: &str) {
    assert!(
        Path::new(source).join(".git").exists(),
        "{source} is missing; run `cargo xtask gpu fetch`"
    );
}
#[cfg(feature = "linux-kernel")]
const DRM: &str = "../../third_party/linux/drivers/gpu/drm";
#[cfg(feature = "linux-kernel")]
const COMPAT: &str = "../stela-linux/src/compat";

#[cfg(feature = "linux-kernel")]
pub struct Linux {
    pub environment: stela_c_build::linux::Environment,
    #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
    pub archive: PathBuf,
    #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
    pub common_archive: PathBuf,
    #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
    pub captured: Vec<Captured>,
    pub hosted: Vec<PathBuf>,
}
/// DRM's core and the helpers nouveau selects, as Linux's `drm-y`,
/// `drm_kms_helper-y`, `ttm-y`, `gpu-sched-y` and `drm_display_helper-y`
/// compose them under Stela's Kconfig.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
const DRM_SOURCES: &[&str] = &[
    "drm_atomic",
    "drm_atomic_uapi",
    "drm_auth",
    "drm_blend",
    "drm_bridge",
    "drm_cache",
    "drm_color_mgmt",
    "drm_colorop",
    "drm_connector",
    "drm_crtc",
    "drm_displayid",
    "drm_drv",
    "drm_dumb_buffers",
    "drm_edid",
    "drm_eld",
    "drm_encoder",
    "drm_file",
    "drm_framebuffer",
    "drm_gem",
    "drm_ioctl",
    "drm_lease",
    "drm_managed",
    "drm_mode_config",
    "drm_mode_object",
    "drm_modes",
    "drm_modeset_lock",
    "drm_panel_orientation_quirks",
    "drm_pci",
    "drm_plane",
    "drm_prime",
    "drm_print",
    "drm_property",
    "drm_rect",
    "drm_syncobj",
    "drm_sysfs",
    "drm_vblank",
    "drm_vblank_work",
    "drm_writeback",
    "drm_exec",
    "drm_gpuvm",
    "drm_gem_ttm_helper",
    "drm_atomic_helper",
    "drm_atomic_state_helper",
    "drm_bridge_helper",
    "drm_crtc_helper",
    "drm_damage_helper",
    "drm_flip_work",
    "drm_format_helper",
    "drm_gem_atomic_helper",
    "drm_gem_framebuffer_helper",
    "drm_kms_helper_common",
    "drm_modeset_helper",
    "drm_plane_helper",
    "drm_probe_helper",
    "drm_self_refresh_helper",
    "drm_simple_kms_helper",
    "drm_vblank_helper",
    "ttm/ttm_tt",
    "ttm/ttm_bo",
    "ttm/ttm_bo_util",
    "ttm/ttm_bo_vm",
    "ttm/ttm_module",
    "ttm/ttm_execbuf_util",
    "ttm/ttm_range_manager",
    "ttm/ttm_resource",
    "ttm/ttm_pool",
    "ttm/ttm_device",
    "ttm/ttm_sys_manager",
    "ttm/ttm_backup",
    "scheduler/sched_main",
    "scheduler/sched_fence",
    "scheduler/sched_entity",
    "scheduler/sched_rq",
    "display/drm_display_helper_mod",
    "display/drm_dp_dual_mode_helper",
    "display/drm_dp_helper",
    "display/drm_dp_mst_topology",
    "display/drm_hdmi_helper",
    "display/drm_scdc_helper",
];

/// Class-owned registration prefix after the shared common cohort.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
const DRM_UNITS: &[UnitSpec] = &[
    UnitSpec {
        scope: stela_c_build::linux_capture::Scope {
            slice: "gpu",
            group: "drm",
            group_ordinal: 5,
            unit_ordinal: 1,
            global_ordinal: 5,
        },
        source: "drivers/gpu/drm/drm_drv",
        module: "drm",
        file: "drivers/gpu/drm/drm",
    },
    UnitSpec {
        scope: stela_c_build::linux_capture::Scope {
            slice: "gpu",
            group: "gpusched",
            group_ordinal: 6,
            unit_ordinal: 1,
            global_ordinal: 6,
        },
        source: "drivers/gpu/drm/scheduler/sched_fence",
        module: "gpu_sched",
        file: "drivers/gpu/drm/scheduler/gpu-sched",
    },
    UnitSpec {
        scope: stela_c_build::linux_capture::Scope {
            slice: "gpu",
            group: "drmdisplayhelper",
            group_ordinal: 7,
            unit_ordinal: 1,
            global_ordinal: 7,
        },
        source: "drivers/gpu/drm/display/drm_display_helper_mod",
        module: "drm_display_helper",
        file: "drivers/gpu/drm/display/drm_display_helper",
    },
];

/// Reviewed common-first/DRM-next prefix, used again by the final class image.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
pub fn environment_units() -> Vec<UnitSpec> {
    COMMON.iter().chain(DRM_UNITS).copied().collect()
}

#[cfg(feature = "linux-kernel")]
impl Linux {
    pub fn new() -> Self {
        require_sources();
        let shared = PathBuf::from(
            env::var_os("DEP_STELA_LINUX_OUTPUT").expect("shared Linux build output"),
        );
        let environment = stela_c_build::linux::Environment::new(stela_c_build::linux::Roots {
            linux: LINUX.into(),
            compat: COMPAT.into(),
            output: out_dir(),
        });
        let kernel = sources("src/compat/linux/kernel");
        let upstream = [
            format!("{LINUX}/drivers/video/hdmi.c"),
            format!("{DRM}/drm_fourcc.c"),
            format!("{DRM}/drm_mm.c"),
            format!("{DRM}/drm_vma_manager.c"),
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
        #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
        let mut upstream = upstream;
        #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
        upstream.extend(
            DRM_SOURCES
                .iter()
                .map(|source| PathBuf::from(format!("{DRM}/{source}.c"))),
        );
        let hosted_upstream = upstream[..4].to_vec();
        let mut build = stela_c_build::native::configure();
        environment.apply(&mut build, None, &[], None);
        #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
        let (captured, shared_count) = {
            let mut captured_build = upstream_build(&build, Path::new(COMPAT));
            upstream_warnings(&mut captured_build);
            let compiler = linux_capture::compiler(&captured_build);
            let digest =
                env::var("DEP_STELA_LINUX_COHORT_SHA256").expect("shared cohort producer digest");
            let common_placements = COMMON
                .iter()
                .map(|spec| {
                    linux_capture::Placement::new(
                        &Unit::from(*spec).path(),
                        &shared,
                        &[
                            Path::new("../.."),
                            compiler.parent().expect("compiler root"),
                        ],
                    )
                    .expect("shared source placement")
                })
                .collect::<Vec<_>>();
            // Reconstruct the common producer's literal command paths and
            // working directory; no artifact option vector is authoritative.
            let common_environment =
                stela_c_build::linux::Environment::from_existing(stela_c_build::linux::Roots {
                    linux: PathBuf::from(LINUX),
                    compat: PathBuf::from("src/compat"),
                    output: shared.clone(),
                });
            let mut common_build = stela_c_build::native::configure();
            common_environment.profile(&mut common_build, None, &[], None);
            let mut common_build = upstream_build(&common_build, Path::new("src/compat"));
            upstream_warnings(&mut common_build);
            let common_profiles = COMMON
                .iter()
                .map(|spec| {
                    linux_capture::profile(
                        &common_build,
                        Path::new("src/compat/stela/registration.h"),
                        *spec,
                        Path::new("../stela-linux"),
                    )
                })
                .collect::<Vec<_>>();
            let mut captured = linux_capture::read(Import {
                output: &shared,
                compiler: &compiler,
                units: COMMON,
                placements: &common_placements,
                profiles: &common_profiles,
                sha256: &digest,
            })
            .unwrap_or_else(|error| panic!("shared Linux cohort refused: {error}"));
            let shared_count = captured.len();
            for spec in DRM_UNITS {
                let unit = Unit::from(*spec);
                upstream.retain(|source| *source != unit.path());
                let placement = linux_capture::Placement::new(
                    &unit.path(),
                    &stela_c_build::linux_build::out_dir(),
                    &[
                        Path::new("../.."),
                        compiler.parent().expect("compiler root"),
                    ],
                )
                .expect("DRM source placement");
                captured.push(linux_capture::compile(
                    &captured_build,
                    &Path::new(COMPAT).join("stela/registration.h"),
                    *spec,
                    &placement,
                ));
            }
            (captured, shared_count)
        };
        #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
        {
            let source = linux_capture::source(
                &captured,
                Projection {
                    symbol: "stela_linux_drm_image",
                    expected: &environment_units(),
                    imported_units: shared_count,
                    descriptors_only: true,
                },
            );
            let descriptors = build.clone().file(source).compile_intermediates();
            build.objects(descriptors);
            build.objects(captured.iter().skip(shared_count).map(Captured::object));
        }
        let _class_archive = linux_archive(
            &build,
            "stela-linux-drm",
            &kernel,
            &upstream,
            Path::new(COMPAT),
        );
        let mut linux = Self {
            environment,
            #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
            archive: _class_archive,
            #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
            common_archive: shared.join("libstela-linux.a"),
            #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
            captured,
            hosted: Vec::new(),
        };
        if let Some(mut host) = stela_c_build::native::hosted() {
            linux.environment.apply(&mut host, None, &[], None);
            let drm_host = linux_archive(
                &host,
                "linux-drm-hosted",
                &kernel,
                &hosted_upstream,
                Path::new(COMPAT),
            );
            let helper = archive(
                &stela_c_build::native::hosted().expect("hosted compiler"),
                "linux-drm-host-services",
                &[PathBuf::from("src/compat/linux/stela/drm_test_host.c")],
            );
            linux.hosted = vec![
                drm_host,
                helper,
                shared.join("liblinux-hosted.a"),
                shared.join("liblinux-host.a"),
            ];
        }
        linux
    }

    #[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
    pub fn take_captured(&mut self) -> Vec<Captured> {
        self.captured.clone()
    }

    pub fn tests(&self, tests: &mut stela_c_build::linux_build::Tests) {
        super::nouveau_firmware::tests(self, tests);
        let Some(mut build) = stela_c_build::native::hosted() else {
            return;
        };
        self.environment.apply(&mut build, None, &[], None);
        let archives = self.hosted.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        for (name, source) in [
            ("linux_drm_mm", "drm_mm_test.c"),
            ("linux_drm_vma", "drm_vma_test.c"),
            ("linux_xe_bo", "xe_bo_test.c"),
            ("linux_xe_sched", "xe_sched_test.c"),
        ] {
            tests.add(
                &build,
                name,
                &format!("src/compat/linux/stela/{source}"),
                &archives,
            );
        }
        build.define("STELA_LINUX_DRM_FORMAT_TEST", None);
        tests.add(
            &build,
            "linux_drm_formats",
            "src/compat/linux/kernel/drm.c",
            &archives,
        );
    }
}
#[cfg(feature = "linux-kernel")]
pub fn drm_includes(directories: &[&str]) -> Vec<PathBuf> {
    directories
        .iter()
        .map(|directory| Path::new(DRM).join(directory))
        .collect()
}

/// What one archive member defines and imports.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
struct Member {
    defined: BTreeSet<String>,
    imported: BTreeSet<String>,
}

#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
fn members(archive: &Path) -> Vec<Member> {
    let data = fs::read(archive).unwrap_or_else(|error| panic!("{}: {error}", archive.display()));
    let archive = ArchiveFile::parse(&*data).expect("an archive");
    archive
        .members()
        .map(|member| {
            let member = member.expect("an archive member");
            let object = object::File::parse(member.data(&*data).expect("member data"))
                .expect("an object file");
            // Mach-O stores symbol names with a leading C-convention
            // underscore (`foo` -> `_foo`, kernel `__foo` -> `___foo`); ELF and
            // COFF don't. Strip that one underscore so the whole gate compares
            // one C-symbol space against the reference lists (traps, RUNTIME,
            // PLATFORM, OPEN_*), which are all written in plain C names.
            let macho = object.format() == object::BinaryFormat::MachO;
            let (mut defined, mut imported) = (BTreeSet::new(), BTreeSet::new());
            for symbol in object.symbols() {
                let Ok(name) = symbol.name() else {
                    continue;
                };
                let name = if macho {
                    name.strip_prefix('_').unwrap_or(name)
                } else {
                    name
                };
                if symbol.is_undefined() {
                    imported.insert(name.to_owned());
                } else if symbol.is_global() {
                    defined.insert(name.to_owned());
                }
            }
            Member { defined, imported }
        })
        .collect()
}

/// What the environment defines without serving: functions that trap
/// (`STELA_UNSUPPORTED`), placeholder objects (`STELA_UNSUPPORTED_OBJECT`)
/// and functions that report themselves unsupported and fail.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
fn traps() -> BTreeSet<String> {
    let mut traps = BTreeSet::new();
    for source in stela_c_build::linux_build::sources("../stela-linux/src/compat/kernel")
        .into_iter()
        .chain(stela_c_build::linux_build::sources(
            "src/compat/linux/kernel",
        ))
    {
        let text = fs::read_to_string(&source).expect("read a kernel-API source");
        for (marker, field) in [
            ("STELA_UNSUPPORTED(", 1),
            ("STELA_UNSUPPORTED_OBJECT(", 1),
            ("stela_linux_unsupported(\"", 0),
        ] {
            for definition in text.split(marker).skip(1) {
                let end = definition.find([')', '"']).unwrap_or(definition.len());
                if let Some(name) = definition[..end].split(',').nth(field) {
                    traps.insert(name.trim().to_owned());
                }
            }
        }
    }
    traps
}

/// What one driver composite imports that nothing supplies, compared with
/// its reviewed open list: the build fails when the imports change.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
pub fn check_imports(
    port: &Path,
    environment: &[&Path],
    open: &[(&str, &[&str])],
    port_name: &str,
) {
    let port = members(port);
    let environment = environment
        .iter()
        .flat_map(|archive| members(archive))
        .collect::<Vec<_>>();
    let definers = environment
        .iter()
        .flat_map(|member| member.defined.iter().map(move |symbol| (symbol, member)))
        .collect::<BTreeMap<_, _>>();
    let defined = port
        .iter()
        .flat_map(|member| &member.defined)
        .collect::<BTreeSet<_>>();
    let traps = traps();
    let harness = env::var_os("DEP_STELA_LINUX_HOSTED_FIXTURES").is_some();
    let mut reached = port
        .iter()
        .flat_map(|member| &member.imported)
        .filter(|symbol| !defined.contains(symbol))
        .collect::<Vec<_>>();
    let mut seen = reached.iter().copied().collect::<BTreeSet<_>>();
    let mut open_set = BTreeSet::new();
    while let Some(symbol) = reached.pop() {
        if traps.contains(symbol) {
            open_set.insert(symbol.clone());
        }
        match definers.get(symbol) {
            Some(member) => reached.extend(
                member
                    .imported
                    .iter()
                    .filter(|&import| !defined.contains(import) && seen.insert(import)),
            ),
            None if RUNTIME.contains(&symbol.as_str())
                || symbol.starts_with(PLATFORM)
                || (harness && symbol.starts_with(HARNESS)) => {}
            None => {
                open_set.insert(symbol.clone());
            }
        }
    }
    let mut stale = Vec::new();
    for symbol in open.iter().flat_map(|(_, symbols)| symbols.iter()) {
        if !open_set.remove(*symbol) {
            stale.push(*symbol);
        }
    }
    assert!(
        open_set.is_empty() && stale.is_empty(),
        "{port_name}'s imports changed: newly open {open_set:?}; now supplied {stale:?}"
    );
}

/// What the compiler itself calls, which every platform's runtime supplies.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
const RUNTIME: [&str; 4] = ["memcpy", "memmove", "memset", "memcmp"];
/// The prefix of what Stela's Rust side exports to the environment.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
const PLATFORM: &str = "stela_linux_";
/// The prefix of the hosted test harness (`stela/test.h`). Only a hosted
/// environment built with its source fixtures reaches it, from fixture code
/// sharing archive members with the services a port imports.
#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
const HARNESS: &str = "stela_test_";

//! `--profile`'s GPU time per pass, from the command buffers' timestamps.
//!
//! Without the profile a command buffer marks the ends of its first
//! [`PASS_MARKS`](super::queue) passes and dispatch groups. With it, it
//! marks up to [`PROFILE_MARKS`] times: also wherever its work changes kind
//! (a render pass, a dispatch group, a texel conversion, a transfer, the
//! device's own kernels), so a pass's start and end conversions and the
//! copies around it are timed apart from its draws. A mark between two kinds
//! of work the GPU would have overlapped serializes them, so the profile's
//! totals are an upper bound of what the work costs without it.
//!
//! The spans are summed per beat by what they did: their kind, the entry
//! points of the pipelines they bound, and for a render pass the first
//! attachment's size, format and memory. [`PassTimes`] makes the
//! `GPU PASSES` line of the most expensive ones, with per command buffer
//! counts of submissions, passes and copies, and the `GPU SAMPLED` line of
//! what the longest render pass of each samples ([`PassNote`]).
use crate::metal::{
    pixel_format::PixelFormat,
    vulkan::{AttachmentLoadOp, AttachmentStoreOp, command::Command},
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

/// Marks a command buffer's timestamps make under the profile.
pub(super) const PROFILE_MARKS: u32 = 1022;

/// Distinct entries a beat keeps; later new ones are summed as `other`.
const MAX_ENTRIES: usize = 512;

/// Entries the line shows.
const SHOWN: usize = 8;

/// Textures a pass note keeps; it counts those past them.
pub(super) const NOTED_TEXTURES: usize = 6;

static PROFILE: AtomicBool = AtomicBool::new(false);

/// Turns the per-pass timing on for every device, for `--profile`.
pub fn set_pass_profile(on: bool) {
    PROFILE.store(on, Ordering::Relaxed);
}

/// Whether `--profile` asked for per-pass timing.
pub fn pass_profile() -> bool {
    PROFILE.load(Ordering::Relaxed)
}

/// What kind of work a span between marks did.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum SpanKind {
    /// Barriers, resets, timestamps: nothing of its own.
    #[default]
    None,
    /// A render pass instance and its draws.
    Render,
    /// Dispatches, including a pass's tile dispatches.
    Compute,
    /// The store texels kernel: a texture of another encoding filled from
    /// a buffer, such as a pass's start decoding an IOSurface's planes.
    StoreTexels,
    /// The load texels kernel: such a texture copied out to a buffer, such
    /// as a pass's end encoding the planes.
    LoadTexels,
    /// The device's other kernels: resolves, block decodes, averaging,
    /// query accumulation.
    Internal,
    /// Copies, blits, clears and fills.
    Transfer,
}

impl SpanKind {
    /// The kind of `command`'s work; [`SpanKind::None`] for commands that
    /// only order, bind or set state.
    pub fn of(command: &Command) -> Self {
        match command {
            Command::BeginRendering(_)
            | Command::EndRendering
            | Command::Draw { .. }
            | Command::DrawIndexed { .. }
            | Command::DrawIndirect { .. }
            | Command::DrawIndexedIndirect { .. }
            | Command::DrawMeshTasks(_)
            | Command::DrawMeshTasksIndirect { .. } => Self::Render,
            Command::Dispatch(_) | Command::DispatchIndirect { .. } => Self::Compute,
            Command::StoreTexels { .. } => Self::StoreTexels,
            Command::LoadTexels { .. } => Self::LoadTexels,
            Command::AccumulateResults { .. }
            | Command::SelectCommands { .. }
            | Command::ResolveDraws { .. }
            | Command::ResolveDispatches { .. }
            | Command::DecodeBlocks { .. }
            | Command::ReorderBlocks { .. }
            | Command::AverageSamples { .. } => Self::Internal,
            Command::CopyBuffer { .. }
            | Command::CopyBufferRegions { .. }
            | Command::CopyBufferToImage { .. }
            | Command::CopyImageToBuffer { .. }
            | Command::CopyImage { .. }
            | Command::BlitImage { .. }
            | Command::ClearColorImage { .. }
            | Command::FillBuffer { .. }
            | Command::CopyQueryResults { .. } => Self::Transfer,
            _ => Self::None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "idle",
            Self::Render => "render",
            Self::Compute => "compute",
            Self::StoreTexels => "store_texels",
            Self::LoadTexels => "load_texels",
            Self::Internal => "internal",
            Self::Transfer => "transfer",
        }
    }
}

/// Texels a copy or conversion command moves, and whether it copies a
/// whole image region or converts texels (the copies the line counts).
pub fn copied_texels(command: &Command) -> Option<u64> {
    let volume = |extent: [u32; 3]| extent.iter().map(|&side| u64::from(side)).product::<u64>();
    match command {
        Command::CopyImage { regions, .. } => {
            Some(regions.iter().map(|region| volume(region.extent)).sum())
        }
        Command::BlitImage { regions, .. } => Some(
            regions
                .iter()
                .map(|region| {
                    let [low, high] = region.dst_bounds;
                    (0..3)
                        .map(|axis| u64::from(high[axis].abs_diff(low[axis])))
                        .product::<u64>()
                })
                .sum(),
        ),
        Command::CopyBufferToImage { region, .. } | Command::CopyImageToBuffer { region, .. } => {
            Some(volume(region.extent))
        }
        Command::StoreTexels { count, .. } | Command::LoadTexels { count, .. } => {
            Some(u64::from(*count))
        }
        _ => None,
    }
}

/// Where a render pass's first attachment's texels are.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetMemory {
    /// An optimally tiled image of the device's own.
    Optimal,
    /// A linear image in a buffer's memory the CPU reaches through its
    /// cache: system memory, which the GPU reaches across the bus.
    LinearShared,
    /// A linear image in write-combined CPU-visible memory, normally
    /// device memory behind the BAR.
    LinearWriteCombined,
    /// A linear image in a private buffer's device memory.
    LinearPrivate,
    /// An IOSurface's extended-range planes, rendered in a working image
    /// that the pass's start and end convert.
    Planes,
}

impl TargetMemory {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Optimal => "optimal",
            Self::LinearShared => "linear-sys",
            Self::LinearWriteCombined => "linear-wc",
            Self::LinearPrivate => "linear-vram",
            Self::Planes => "planes",
        }
    }
}

/// A render pass's first attachment, as the line names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetInfo {
    pub format: PixelFormat,
    pub memory: TargetMemory,
}

/// A texture a render pass binds for its functions, as the `GPU SAMPLED`
/// line names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampledTexture {
    pub extent: [u32; 2],
    pub format: PixelFormat,
    pub memory: TargetMemory,
    pub levels: u32,
    pub samples: u32,
}

impl fmt::Display for SampledTexture {
    /// `WxH/format/memory`, then `/mips=N` and `/xN` past one.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}x{}/{:?}/{}",
            self.extent[0],
            self.extent[1],
            self.format,
            self.memory.name()
        )?;
        if self.levels > 1 {
            write!(formatter, "/mips={}", self.levels)?;
        }
        if self.samples > 1 {
            write!(formatter, "/x{}", self.samples)?;
        }
        Ok(())
    }
}

/// What one profiled render pass samples and how it begins and ends: the
/// textures bound for its functions by `set*Texture:atIndex:` (not those an
/// argument buffer reaches), its sample count and layers, and its first
/// attachment's load and store operations and whether it resolves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassNote {
    pub textures: Vec<SampledTexture>,
    /// Distinct textures bound past [`NOTED_TEXTURES`].
    pub more: u32,
    pub samples: u32,
    pub layers: u32,
    pub load: AttachmentLoadOp,
    pub store: AttachmentStoreOp,
    pub resolves: bool,
}

impl PassNote {
    /// Notes `texture` bound, once.
    pub fn bind(&mut self, texture: SampledTexture) {
        if self.textures.contains(&texture) {
            return;
        }
        if self.textures.len() < NOTED_TEXTURES {
            self.textures.push(texture);
        } else {
            self.more = self.more.saturating_add(1);
        }
    }
}

impl fmt::Display for PassNote {
    /// `xS/layers=L/load/store[/resolve]/textures=a,b,…[+N]`, `-` for none.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let load = match self.load {
            AttachmentLoadOp::Load => "load",
            AttachmentLoadOp::Clear => "clear",
            AttachmentLoadOp::DontCare => "dontcare",
        };
        let store = match self.store {
            AttachmentStoreOp::Store => "store",
            AttachmentStoreOp::DontCare => "dontcare",
        };
        write!(
            formatter,
            "x{}/layers={}/{load}/{store}{}/textures=",
            self.samples,
            self.layers,
            if self.resolves { "/resolve" } else { "" }
        )?;
        if self.textures.is_empty() {
            formatter.write_str("-")?;
        }
        for (index, texture) in self.textures.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{texture}")?;
        }
        if self.more != 0 {
            write!(formatter, "+{}", self.more)?;
        }
        Ok(())
    }
}

/// One kind of span's times in a beat.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Entry {
    pub count: u64,
    pub total_ns: u64,
    pub longest_ns: u64,
    pub draws: u64,
    pub dispatches: u64,
    pub texels: u64,
}

/// What one span did, as [`PassTimes::span`] sums it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpanWork {
    pub ns: u64,
    pub draws: u64,
    pub dispatches: u64,
    pub texels: u64,
}

/// A sum and the largest of one count per command buffer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tally {
    pub total: u64,
    pub most: u64,
}

impl Tally {
    fn add(&mut self, value: u64) {
        self.total += value;
        self.most = self.most.max(value);
    }
}

/// One command buffer's counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommandBufferCounts {
    /// `vkQueueSubmit2` calls, and the Vulkan command buffers (segments)
    /// they submitted.
    pub submits: u64,
    pub segments: u64,
    /// Render pass instances (a Metal pass split by barriers or tile
    /// dispatches is several).
    pub passes: u64,
    /// Whole-region copies and texel conversions, and the texels they
    /// moved.
    pub copies: u64,
    pub copied_texels: u64,
    /// Whether its marks ran out before its work did: the last span holds
    /// the rest.
    pub out_of_marks: bool,
}

/// What committed passes converted of IOSurface two-plane extended-range
/// textures: the encodes into the planes, how each wrote them, and the
/// decodes from them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlaneCounts {
    /// Encodes whose kernel wrote the planes in guest RAM, and their texels.
    pub direct: u64,
    pub direct_texels: u64,
    /// Encodes into staging memory that copies moved into the planes
    /// ([`PlaneStaging`](crate::metal::pass::PlaneStaging)), and their
    /// texels.
    pub copied: u64,
    pub copied_texels: u64,
    /// Encodes of a pass's dirty tiles, and the tiles they looked at.
    pub stamped: u64,
    pub stamped_tiles: u64,
    /// Decodes, and their texels.
    pub decoded: u64,
    pub decoded_texels: u64,
}

impl PlaneCounts {
    pub fn add(&mut self, other: Self) {
        self.direct += other.direct;
        self.direct_texels += other.direct_texels;
        self.copied += other.copied;
        self.copied_texels += other.copied_texels;
        self.stamped += other.stamped;
        self.stamped_tiles += other.stamped_tiles;
        self.decoded += other.decoded;
        self.decoded_texels += other.decoded_texels;
    }
}

/// The beat's spans by what they did, and the command buffers' counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassTimes {
    pub entries: BTreeMap<String, Entry>,
    pub command_buffers: u64,
    pub spans: u64,
    pub busy_ns: u64,
    pub out_of_marks: u64,
    pub submits: Tally,
    pub segments: Tally,
    pub passes: Tally,
    pub copies: Tally,
    pub copied_texels: Tally,
    pub planes: PlaneCounts,
    /// By key, the note of its longest span that had one, and that span's
    /// time.
    pub notes: BTreeMap<String, (u64, String)>,
}

impl PassTimes {
    /// Adds a span that did what `key` names.
    pub fn span(&mut self, key: String, work: SpanWork) {
        self.spans += 1;
        self.busy_ns += work.ns;
        let entry = if self.entries.len() < MAX_ENTRIES || self.entries.contains_key(&key) {
            self.entries.entry(key).or_default()
        } else {
            self.entries.entry(String::from("other")).or_default()
        };
        entry.count += 1;
        entry.total_ns += work.ns;
        entry.longest_ns = entry.longest_ns.max(work.ns);
        entry.draws += work.draws;
        entry.dispatches += work.dispatches;
        entry.texels += work.texels;
    }

    /// Keeps `note` as what `key`'s span of `ns` sampled when it is the
    /// longest of the key's spans noted so far.
    pub fn note(&mut self, key: &str, ns: u64, note: &PassNote) {
        if !self.entries.contains_key(key) {
            return;
        }
        match self.notes.get_mut(key) {
            Some(kept) if kept.0 >= ns => {}
            Some(kept) => *kept = (ns, alloc::format!("{note}")),
            None => {
                self.notes
                    .insert(String::from(key), (ns, alloc::format!("{note}")));
            }
        }
    }

    /// Adds a timed command buffer's counts.
    pub fn command_buffer(&mut self, counts: CommandBufferCounts) {
        self.command_buffers += 1;
        self.out_of_marks += u64::from(counts.out_of_marks);
        self.submits.add(counts.submits);
        self.segments.add(counts.segments);
        self.passes.add(counts.passes);
        self.copies.add(counts.copies);
        self.copied_texels.add(counts.copied_texels);
    }

    pub fn take(&mut self) -> Self {
        core::mem::take(self)
    }

    /// The entries by GPU time, most first.
    pub fn top(&self) -> Vec<(&str, Entry)> {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(key, entry)| (key.as_str(), *entry))
            .collect();
        entries.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns).then(a.0.cmp(b.0)));
        entries
    }
}

/// `kind:names@WxH/format/memory`, or `kind:names` without a target.
pub fn span_key(
    kind: SpanKind,
    names: &str,
    extent: [u32; 2],
    target: Option<TargetInfo>,
) -> String {
    let names = if names.is_empty() { "-" } else { names };
    match target {
        Some(target) => alloc::format!(
            "{}:{names}@{}x{}/{:?}/{}",
            kind.name(),
            extent[0],
            extent[1],
            target.format,
            target.memory.name()
        ),
        None => alloc::format!("{}:{names}", kind.name()),
    }
}

/// `GPU PASSES command_buffers=… spans=… busy_us=… out_of_marks=…
/// per_cb=submits:avg/max segments:… passes:… copies:… copied_ktexels:…
/// planes=direct:count/ktexels copied:count/ktexels stamped:count/tiles
/// decoded:count/ktexels top=key:count/total_us/longest_us/draws/dispatches/ktexels …`,
/// then on a line of its own `GPU SAMPLED longest key:us:note …` of the
/// keys' longest noted spans, longest first.
impl fmt::Display for PassTimes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let average = |tally: Tally| {
            let count = self.command_buffers.max(1);
            alloc::format!(
                "{}.{}/{}",
                tally.total / count,
                tally.total % count * 10 / count,
                tally.most
            )
        };
        write!(
            formatter,
            "GPU PASSES command_buffers={} spans={} busy_us={} out_of_marks={} per_cb=submits:{} \
             segments:{} passes:{} copies:{} copied_ktexels:{}/{} planes=direct:{}/{} \
             copied:{}/{} stamped:{}/{} decoded:{}/{} top",
            self.command_buffers,
            self.spans,
            self.busy_ns / 1000,
            self.out_of_marks,
            average(self.submits),
            average(self.segments),
            average(self.passes),
            average(self.copies),
            self.copied_texels.total / self.command_buffers.max(1) / 1000,
            self.copied_texels.most / 1000,
            self.planes.direct,
            self.planes.direct_texels / 1000,
            self.planes.copied,
            self.planes.copied_texels / 1000,
            self.planes.stamped,
            self.planes.stamped_tiles,
            self.planes.decoded,
            self.planes.decoded_texels / 1000,
        )?;
        for (key, entry) in self.top().into_iter().take(SHOWN) {
            write!(
                formatter,
                " {key}:{}/{}/{}/{}/{}/{}",
                entry.count,
                entry.total_ns / 1000,
                entry.longest_ns / 1000,
                entry.draws,
                entry.dispatches,
                entry.texels / 1000,
            )?;
        }
        // The longest noted passes, longest first.
        let mut notes: Vec<_> = self.notes.iter().collect();
        notes.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(b.0)));
        if !notes.is_empty() {
            formatter.write_str("\nGPU SAMPLED longest")?;
        }
        for (key, (ns, note)) in notes.into_iter().take(SHOWN) {
            write!(formatter, " {key}:{}:{note}", ns / 1000)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::vulkan::{
        ImageAspects,
        command::{ImageCopy, Subresource},
    };

    #[test]
    fn sums_spans_by_key_and_shows_the_costliest_first() {
        let mut times = PassTimes::default();
        let target = TargetInfo {
            format: PixelFormat::Bgra8Unorm,
            memory: TargetMemory::LinearShared,
        };
        let render = span_key(SpanKind::Render, "a+b", [2560, 1440], Some(target));
        assert_eq!(render, "render:a+b@2560x1440/Bgra8Unorm/linear-sys");
        let store = span_key(SpanKind::StoreTexels, "", [0, 0], None);
        assert_eq!(store, "store_texels:-");
        let work = |ns, draws, texels| SpanWork {
            ns,
            draws,
            dispatches: 0,
            texels,
        };
        times.span(render.clone(), work(3_000_000, 4, 0));
        times.span(render, work(1_000_000, 2, 0));
        times.span(store, work(2_500_000, 0, 3_686_400));
        times.command_buffer(CommandBufferCounts {
            submits: 1,
            segments: 1,
            passes: 2,
            copies: 1,
            copied_texels: 3_686_400,
            out_of_marks: false,
        });
        times.planes.add(PlaneCounts {
            direct: 2,
            direct_texels: 5_000,
            copied: 1,
            copied_texels: 3_686_400,
            stamped: 1,
            stamped_tiles: 920,
            decoded: 1,
            decoded_texels: 2_000,
        });
        let top = times.top();
        assert_eq!(top[0].0, "render:a+b@2560x1440/Bgra8Unorm/linear-sys");
        assert_eq!(
            top[0].1,
            Entry {
                count: 2,
                total_ns: 4_000_000,
                longest_ns: 3_000_000,
                draws: 6,
                dispatches: 0,
                texels: 0,
            }
        );
        let line = alloc::format!("{times}");
        assert_eq!(
            line,
            "GPU PASSES command_buffers=1 spans=3 busy_us=6500 out_of_marks=0 \
             per_cb=submits:1.0/1 segments:1.0/1 passes:2.0/2 copies:1.0/1 \
             copied_ktexels:3686/3686 planes=direct:2/5 copied:1/3686 stamped:1/920 \
             decoded:1/2 top render:a+b@2560x1440/Bgra8Unorm/linear-sys:2/4000/3000/6/0/0 \
             store_texels:-:1/2500/2500/0/0/3686"
        );
        assert_eq!(times.take().spans, 3);
        assert_eq!(times, PassTimes::default());
    }

    #[test]
    fn notes_what_the_longest_pass_of_a_key_samples() {
        let texture = |width, memory, levels| SampledTexture {
            extent: [width, 1440],
            format: PixelFormat::Bgra8Unorm,
            memory,
            levels,
            samples: 1,
        };
        let mut note = PassNote {
            textures: Vec::new(),
            more: 0,
            samples: 4,
            layers: 3,
            load: AttachmentLoadOp::Load,
            store: AttachmentStoreOp::DontCare,
            resolves: true,
        };
        assert_eq!(
            alloc::format!("{note}"),
            "x4/layers=3/load/dontcare/resolve/textures=-"
        );
        note.bind(texture(2560, TargetMemory::LinearShared, 1));
        note.bind(texture(2560, TargetMemory::LinearShared, 1));
        note.bind(texture(1280, TargetMemory::Optimal, 5));
        for width in 0..NOTED_TEXTURES as u32 {
            note.bind(texture(width, TargetMemory::Optimal, 1));
        }
        assert_eq!(note.textures.len(), NOTED_TEXTURES);
        assert_eq!(note.more, 2);
        let line = alloc::format!("{note}");
        assert!(
            line.starts_with(
                "x4/layers=3/load/dontcare/resolve/textures=2560x1440/Bgra8Unorm/linear-sys,\
                 1280x1440/Bgra8Unorm/optimal/mips=5,"
            ),
            "{line}"
        );
        assert!(line.ends_with("+2"), "{line}");

        let mut times = PassTimes::default();
        let key = "render:a@2560x1440/Bgra8Unorm/planes";
        let work = |ns| SpanWork {
            ns,
            ..SpanWork::default()
        };
        // A key the beat does not keep notes nothing.
        times.note(key, 5, &note);
        assert!(times.notes.is_empty());
        let short = PassNote {
            textures: Vec::new(),
            more: 0,
            ..note.clone()
        };
        times.span(String::from(key), work(2_000_000));
        times.note(key, 2_000_000, &short);
        times.span(String::from(key), work(9_000_000));
        times.note(key, 9_000_000, &note);
        times.span(String::from(key), work(1_000_000));
        times.note(key, 1_000_000, &short);
        assert_eq!(times.notes[key], (9_000_000, line.clone()));
        let report = alloc::format!("{times}");
        let sampled = report.lines().nth(1).unwrap();
        assert_eq!(
            sampled,
            alloc::format!("GPU SAMPLED longest {key}:9000:{line}")
        );
    }

    #[test]
    fn keeps_a_bounded_number_of_entries() {
        let mut times = PassTimes::default();
        for index in 0..MAX_ENTRIES + 3 {
            times.span(alloc::format!("compute:k{index}"), SpanWork::default());
        }
        assert_eq!(times.entries.len(), MAX_ENTRIES + 1);
        assert_eq!(times.entries["other"].count, 3);
    }

    #[test]
    fn classifies_commands_and_counts_copied_texels() {
        assert_eq!(SpanKind::of(&Command::EndRendering), SpanKind::Render);
        assert_eq!(
            SpanKind::of(&Command::Dispatch([1, 1, 1])),
            SpanKind::Compute
        );
        let store = Command::StoreTexels {
            arguments: 0,
            count: 7,
        };
        assert_eq!(SpanKind::of(&store), SpanKind::StoreTexels);
        assert_eq!(copied_texels(&store), Some(7));
        assert_eq!(
            SpanKind::of(&Command::SetBlendConstants([0.0; 4])),
            SpanKind::None
        );
        let layer = Subresource {
            aspects: ImageAspects::COLOR,
            mip_level: 0,
            base_array_layer: 0,
            layer_count: 1,
        };
        let copy = Command::CopyImage {
            src: crate::metal::vulkan::object::Image(1),
            dst: crate::metal::vulkan::object::Image(2),
            regions: alloc::vec![ImageCopy {
                src: layer,
                src_offset: [0; 3],
                dst: layer,
                dst_offset: [0; 3],
                extent: [4, 3, 1],
            }],
        };
        assert_eq!(SpanKind::of(&copy), SpanKind::Transfer);
        assert_eq!(copied_texels(&copy), Some(12));
        assert_eq!(copied_texels(&Command::EndRendering), None);
    }
}

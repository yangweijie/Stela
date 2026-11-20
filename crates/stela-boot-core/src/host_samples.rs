//! What `--profile`'s host samples are (`PES WHERE`): the classes a sample
//! of a PE's host instruction pointer falls in, the arena's region tags that
//! classify native code by a table lookup, and the line. The boot's NMI
//! sampler (`engine::host::sampling`) takes the samples.
//!
//! A sample in native code takes the region of the code at its instruction
//! pointer from the arena's tags ([`Tags`]): every install the engine
//! describes tags each 16 bytes with its [`CodeRegion`] in four bits.
//! Outside the arena, native code is in a routine it called: a shadow
//! page-fault fill ([`FILL`]), the translated-access helper ([`HELPER`]),
//! or a routine named by the first return address into the arena on the
//! stack: the PAC service ([`PAC_CALL`], the cipher of memo misses), whose
//! calls end with known bytes, or another ([`CALL`]); [`NATIVE_OTHER`] when
//! no return address is found. A sample outside native code is charged to
//! the step loop's phase that holds it ([`charged`]).

use alloc::{boxed::Box, format, string::String};
use core::sync::atomic::{AtomicU8, Ordering::Relaxed};
use stela_engine::machine::engine::step_timing::{CodeRegion, EXIT_SLOTS, Phase};

/// The counters that sample: cycles (0) and retired instructions (1).
pub const SAMPLED: usize = 2;
/// Arena bytes one tag covers.
pub const GRANULE_SHIFT: u32 = 4;
/// The stack a return address into the arena is looked for in, at most.
pub const SCAN_BYTES: u64 = 8 * 1024;

/// Sample classes: the arena's regions ([`CodeRegion`] values), then these.
pub const PAC_CALL: usize = CodeRegion::COUNT;
pub const CALL: usize = PAC_CALL + 1;
pub const HELPER: usize = PAC_CALL + 2;
pub const FILL: usize = PAC_CALL + 3;
pub const NATIVE_OTHER: usize = PAC_CALL + 4;
/// Not in native code: charged by phase ([`charged`]). The classes from it
/// on exist only once charged.
pub const OUTSIDE: usize = PAC_CALL + 5;
/// The classes an NMI counts before a charge.
pub const PENDING: usize = OUTSIDE + 1;
pub const GLUE: usize = OUTSIDE;
pub const SCHEDULE: usize = GLUE + 1;
pub const DEVICES: usize = GLUE + 2;
pub const FETCH: usize = GLUE + 3;
pub const EXIT_OTHER: usize = GLUE + 4;
/// The exits by `step_timing` exit slot.
pub const EXITS: usize = GLUE + 5;
/// Between slices: host service.
pub const HOST: usize = EXITS + EXIT_SLOTS;
pub const CLASSES: usize = HOST + 1;

/// Events (cycles, instructions) by class.
pub type Counts = [[u64; SAMPLED]; CLASSES];

/// A class's name in the line; `exit_names` names the exit slots.
pub fn class_name(class: usize, exit_names: &[&str; EXIT_SLOTS]) -> String {
    match class {
        region if region < CodeRegion::COUNT => String::from(CodeRegion::ALL[region].name()),
        PAC_CALL => String::from("pac-call"),
        CALL => String::from("call"),
        HELPER => String::from("helper"),
        FILL => String::from("fill"),
        NATIVE_OTHER => String::from("nat-other"),
        GLUE => String::from("glue"),
        SCHEDULE => String::from("sch"),
        DEVICES => String::from("dev"),
        FETCH => String::from("fetch"),
        EXIT_OTHER => String::from("x:other"),
        HOST => String::from("host"),
        exit => format!("x:{}", exit_names[exit - EXITS]),
    }
}

/// Whether `class` is inside native code.
pub fn native(class: usize) -> bool {
    class < OUTSIDE
}

/// The class a pending sample of `class` takes when charged to `phase`
/// (exit slot `slot` for an exit), or to host service with no phase.
pub fn charged(class: usize, phase: Option<Phase>, slot: Option<usize>) -> usize {
    if class != OUTSIDE {
        return class;
    }
    match phase {
        None => HOST,
        Some(Phase::Native) => GLUE,
        Some(Phase::Schedule) => SCHEDULE,
        Some(Phase::Devices) => DEVICES,
        Some(Phase::Fetch) => FETCH,
        Some(Phase::Exit) => slot
            .filter(|&slot| slot < EXIT_SLOTS)
            .map_or(EXIT_OTHER, |slot| EXITS + slot),
    }
}

/// A range of code and its region tags, four bits for each 16 bytes.
pub struct Tags {
    start: u64,
    bytes: u64,
    tags: Box<[AtomicU8]>,
}

impl Tags {
    /// Tags for `bytes` of code at `start`, all [`CodeRegion::Untagged`].
    pub fn new(start: u64, bytes: u64) -> Option<Self> {
        if bytes == 0 {
            return None;
        }
        let granules = bytes.div_ceil(1 << GRANULE_SHIFT);
        let tags = (0..granules.div_ceil(2))
            .map(|_| AtomicU8::new(0))
            .collect();
        Some(Self { start, bytes, tags })
    }

    /// The heap bytes the tags take.
    pub fn table_bytes(&self) -> usize {
        self.tags.len()
    }

    pub fn contains(&self, address: u64) -> bool {
        address.wrapping_sub(self.start) < self.bytes
    }

    /// The region of the code at `address`, which it contains.
    pub fn region(&self, address: u64) -> u8 {
        let granule = (address - self.start) >> GRANULE_SHIFT;
        let byte = self.tags[(granule >> 1) as usize].load(Relaxed);
        (byte >> ((granule & 1) * 4)) & 0xf
    }

    /// Tag `start..end`, which it contains: each granule takes the region
    /// of its middle byte.
    pub fn tag(&self, start: u64, end: u64, region: CodeRegion) {
        if start >= end {
            return;
        }
        let first = (start - self.start) >> GRANULE_SHIFT;
        let last = (end - 1 - self.start) >> GRANULE_SHIFT;
        for granule in first..=last {
            let middle = self.start + (granule << GRANULE_SHIFT) + 8;
            if middle < start || middle >= end {
                continue;
            }
            let shift = (granule & 1) * 4;
            let byte = &self.tags[(granule >> 1) as usize];
            byte.fetch_and(!(0xf << shift), Relaxed);
            byte.fetch_or((region as u8) << shift, Relaxed);
        }
    }

    /// Tag the `bytes` of code at `code` as `regions`, `(offset, region)`
    /// pairs in ascending offsets each running to the next one's offset
    /// and the last to `bytes` (`Host::profile_code`). Whether it holds
    /// the code.
    pub fn describe(&self, code: u64, bytes: usize, regions: &[(u32, CodeRegion)]) -> bool {
        let end = code.wrapping_add(bytes as u64);
        if bytes == 0 || !self.contains(code) || !self.contains(end - 1) {
            return false;
        }
        for (index, &(offset, region)) in regions.iter().enumerate() {
            let next = regions
                .get(index + 1)
                .map_or(end, |&(next, _)| code + u64::from(next));
            let start = code + u64::from(offset);
            if next <= end {
                self.tag(start, next, region);
            }
        }
        true
    }
}

/// Where a sample in native code was taken, and how to read what it needs.
pub struct NativeSample<'a, R, W, C>
where
    R: Fn(u64) -> Option<u8>,
    W: Fn(u64) -> u64,
    C: Fn(u64, usize) -> Option<&'a [u8]>,
{
    pub rip: u64,
    /// The interrupted stack pointer, and where native code was entered,
    /// above which the stack is the host's.
    pub rsp: u64,
    pub top: u64,
    /// Inside a shadow page-fault fill, or the translated-access helper.
    pub filling: bool,
    pub helper: bool,
    /// The arena region at an address, if it is in an arena.
    pub region: R,
    /// The stack word at an address.
    pub word: W,
    /// The code bytes at an address in the arena, this many.
    pub code: C,
    /// The bytes the PAC service's calls end with, up to their return
    /// address (`step_timing::pointer_service_calls`).
    pub service_calls: &'a [&'a [u8]],
}

impl<'a, R, W, C> NativeSample<'a, R, W, C>
where
    R: Fn(u64) -> Option<u8>,
    W: Fn(u64) -> u64,
    C: Fn(u64, usize) -> Option<&'a [u8]>,
{
    /// The sample's class.
    pub fn class(&self) -> usize {
        if self.filling {
            return FILL;
        }
        if let Some(region) = (self.region)(self.rip) {
            return usize::from(region);
        }
        if self.helper {
            return HELPER;
        }
        let end = self.top.min(self.rsp.saturating_add(SCAN_BYTES));
        let mut at = self.rsp & !7;
        while at + 8 <= end {
            let word = (self.word)(at);
            if (self.region)(word).is_some() {
                return self.call_class(word);
            }
            at += 8;
        }
        NATIVE_OTHER
    }

    /// The class of the call returning to `address` in the arena.
    fn call_class(&self, address: u64) -> usize {
        let service = self.service_calls.iter().any(|end| {
            let start = address.wrapping_sub(end.len() as u64);
            !end.is_empty()
                && (self.region)(start).is_some()
                && (self.code)(start, end.len()) == Some(*end)
        });
        if service { PAC_CALL } else { CALL }
    }
}

/// `share` of `total` in percent with one decimal.
fn percent(share: u64, total: u64) -> String {
    let permille = (u128::from(share) * 1000)
        .checked_div(u128::from(total))
        .unwrap_or(0);
    format!("{}.{}", permille / 10, permille % 10)
}

/// The shares part of a `PES WHERE` line for `counts`: the instructions and
/// cycles the samples stand for, in all and in native code, in millions
/// (` ins= cyc= nat_ins= nat_cyc=`), ` native=I/C`, then
/// ` name=I/C` for each class that took at least 0.1% of the instructions
/// or the cycles, in percent of each.
pub fn shares(counts: &Counts, exit_names: &[&str; EXIT_SLOTS]) -> String {
    let totals = [0, 1].map(|counter| counts.iter().map(|class| class[counter]).sum::<u64>());
    let natives = [0, 1].map(|counter| {
        (0..CLASSES)
            .filter(|&class| native(class))
            .map(|class| counts[class][counter])
            .sum::<u64>()
    });
    // Counter 0 counts cycles, 1 instructions: instructions first. The
    // events in millions: each sample weighs its period.
    let mut line = format!(
        " ins={}M cyc={}M nat_ins={}M nat_cyc={}M native={}/{}",
        totals[1] / 1_000_000,
        totals[0] / 1_000_000,
        natives[1] / 1_000_000,
        natives[0] / 1_000_000,
        percent(natives[1], totals[1]),
        percent(natives[0], totals[0])
    );
    for (class, events) in counts.iter().enumerate() {
        let shown = [0, 1].map(|counter| events[counter] * 1000 >= totals[counter].max(1));
        if shown.contains(&true) {
            line.push_str(&format!(
                " {}={}/{}",
                class_name(class, exit_names),
                percent(events[1], totals[1]),
                percent(events[0], totals[0])
            ));
        }
    }
    line
}

#[cfg(test)]
mod tests;

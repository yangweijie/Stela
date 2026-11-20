//! `--profile`'s host samples: where each PE's host instructions and cycles
//! go, by region of the code they ran (the `PES WHERE` heartbeat line).
//!
//! The two counters `PES PMU` keeps on every set ([`super::pmu`]: cycles
//! and retired instructions, counters 0 and 1) also interrupt on overflow:
//! each is loaded `period` events short of overflowing, and the local
//! APIC's performance counter entry delivers its overflow as an NMI. The
//! NMI gate ([`overflow`]) classifies the interrupted instruction pointer
//! and reloads the counter, a few hundred events of its own, before it
//! answers shootdowns. A reload moves the counter back by `period`, which
//! the counter reads `PES PMU` takes add back ([`read`]), so its counts stay
//! whole.
//!
//! A sample in native code (the PE is inside `stela_enter_block`) takes its
//! region from a table of the arena: every install the engine describes
//! ([`stela_engine::machine::Host::profile_code`]) tags each 16 bytes of
//! code with its [`CodeRegion`] in four bits, so classifying is one load.
//! Outside the arena, native code is in a routine it called: a shadow
//! page-fault fill (`fill`), the translated-access helper (`helper`), or a
//! routine found by the first return address into the arena on the stack,
//! the PAC service (`pac-call`, the cipher of memo misses) or another
//! (`call`); `nat-other` when none is found. A sample outside native code
//! waits for the step loop's next phase charge, as `PES PMU`'s counts do,
//! and is charged to that phase: the native phase's own engine code
//! (`glue`), scheduling, device work, fetches, or the exit it handled by
//! kind (`x:` and the `PROFILE` line's exit name); one taken between slices
//! is `host` service.
//!
//! Each sample weighs its counter's period, so the shares are of events.
//! The NMIs stay under 0.2% of a PE's time: the handler times itself with
//! the TSC and adds an estimate of the NMI's entry and return, the line
//! prints the beat's share as `overhead=`, and a PE over 0.1% in a beat
//! doubles its periods for the next. Without `--profile` no counter
//! interrupts and the gate's question is one load.
use super::super::run::EXIT_NAMES;
use super::local;
use crate::output;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering::Relaxed};
use stela_boot_core::host_samples::{
    CLASSES, Counts, NativeSample, OUTSIDE, PENDING, SAMPLED, Tags, charged, native, shares,
};
use stela_engine::machine::engine::step_timing::{self, CodeRegion, Phase};

/// Events between samples at first, per counter, and when RDPMC traps
/// (a hypervisor's NMIs and MSR writes cost far more).
const PERIOD: u64 = 1 << 24;
const TRAPPED_PERIOD: u64 = 1 << 28;
const MAX_PERIOD: u64 = 1 << 40;
/// A beat whose NMIs took more than 1/OVERHEAD_SHARE of the PE's ticks
/// doubles its periods.
const OVERHEAD_SHARE: u64 = 1_000;
/// TSC ticks an NMI's entry, gate and return take beyond its handler, at
/// least.
const ENTRY_TICKS: u64 = 1_000;
/// Counters are 48 bits wide; a loaded counter has its top bit set until
/// it overflows.
const MASK: u64 = (1 << 48) - 1;
const TOP: u64 = 1 << 47;
const MAX_CORES: usize = 256;
const LVT_PERFORMANCE: u32 = 0x340;
const LVT_NMI: u32 = 4 << 8;
/// TSC ticks between two looks for an overflow whose NMI never came: about
/// a second.
const LOST_CHECK_TICKS: u64 = 1 << 32;
/// The longest PAC service call end kept.
const CALL_END_BYTES: usize = 16;

/// The board's code window, shared by every PE.
static WINDOW: AtomicPtr<Tags> = AtomicPtr::new(core::ptr::null_mut());

fn window() -> Option<&'static Tags> {
    let pointer = WINDOW.load(Relaxed);
    // SAFETY: published once, leaked, never freed.
    (!pointer.is_null()).then(|| unsafe { &*pointer })
}

/// Whether a PE samples: set once, before its counters interrupt.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Whether counters 0 and 1 interrupt on overflow ([`enable`]).
static ENABLED: AtomicBool = AtomicBool::new(false);

/// One host processor's sampling state.
struct Sampler {
    pe: usize,
    /// The counters' MSRs, and the global status clear MSR, where there is
    /// one.
    counters: [u32; SAMPLED],
    clear: Option<u32>,
    /// The local APIC, as IA32_APIC_BASE and the xAPIC page's mapping.
    apic_base: u64,
    apic_registers: u64,
    /// Events each counter counts between samples from its next reload.
    period: [AtomicU64; SAMPLED],
    /// The period each counter was loaded with.
    armed: [AtomicU64; SAMPLED],
    /// What reloads took off each counter, modulo its width.
    adjust: [AtomicU64; SAMPLED],
    /// Events by class since the last charge, which NMIs add.
    pending: [[AtomicU64; SAMPLED]; PENDING],
    /// Events by class, which only charges add to.
    counts: [[AtomicU64; SAMPLED]; CLASSES],
    /// TSC ticks the NMIs took, measured and estimated, and their count.
    spent: AtomicU64,
    samples: AtomicU64,
    /// An NMI's entry and return beyond its handler, in TSC ticks.
    entry: u64,
    /// Inside a shadow page-fault fill ([`fill`]).
    filling: AtomicBool,
    /// An NMI added to `pending` since the last charge.
    sampled: AtomicBool,
    /// The processor's private arena.
    arena: Option<Tags>,
    /// The PAC service's call ends ([`step_timing::pointer_service_calls`]).
    service_calls: [([u8; CALL_END_BYTES], usize); 2],
    /// Overflows found with no NMI, and reloaded, and the TSC at the last
    /// look ([`host_service`]).
    lost: AtomicU64,
    checked: AtomicU64,
}

static CORES: [AtomicPtr<Sampler>; MAX_CORES] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CORES];

fn sampler() -> Option<&'static Sampler> {
    let pointer = CORES.get(local::processor() as usize)?.load(Relaxed);
    // SAFETY: leaked at `start`, never freed.
    (!pointer.is_null()).then(|| unsafe { &*pointer })
}

#[inline]
fn rdpmc(counter: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: ring 0, a counter `pmu::start` probed.
    unsafe {
        asm!("rdpmc", in("ecx") counter, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
    }
    u64::from(high) << 32 | u64::from(low)
}

#[inline]
fn wrmsr(index: u32, value: u64) {
    // SAFETY: ring 0, a counter or status register `pmu::start` probed.
    unsafe {
        asm!("wrmsr", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags));
    }
}

fn add(counter: &AtomicU64, value: u64) {
    counter.fetch_add(value, Relaxed);
}

/// Whether counters 0 and 1 should interrupt on overflow: `--profile`
/// asked for counters on a host whose layout has its two fixed events
/// there. Decided once, before any counter is programmed.
pub(super) fn enable(fixed: usize) -> bool {
    if fixed >= SAMPLED {
        ENABLED.store(true, Relaxed);
    }
    ENABLED.load(Relaxed)
}

/// Whether counters 0 and 1 interrupt on overflow.
pub(super) fn enabled() -> bool {
    ENABLED.load(Relaxed)
}

/// Start sampling on this processor for PE `pe`, its counters 0 and 1 at
/// `counters` programmed to interrupt, `clear` the global overflow status
/// clear register where there is one, `trapped` when RDPMC traps and one
/// read of a counter costs `read_ticks`.
pub(super) fn start(pe: usize, counters: [u32; SAMPLED], clear: Option<u32>, read_ticks: u64) {
    let slot = local::processor() as usize;
    if !enabled() || slot >= MAX_CORES {
        return;
    }
    let state = super::state();
    if window().is_none()
        && let Some(tags) = Tags::new(state.window_virtual, state.window_bytes)
    {
        let leaked = Box::into_raw(Box::new(tags));
        if WINDOW
            .compare_exchange(core::ptr::null_mut(), leaked, Relaxed, Relaxed)
            .is_err()
        {
            // SAFETY: ours, never published.
            drop(unsafe { Box::from_raw(leaked) });
        }
    }
    let trapped = read_ticks > super::pmu::WINDOW_READ_TICKS;
    let period = if trapped { TRAPPED_PERIOD } else { PERIOD };
    let mut service_calls = [([0u8; CALL_END_BYTES], 0); 2];
    for (kept, end) in service_calls
        .iter_mut()
        .zip(step_timing::pointer_service_calls())
    {
        if end.len() <= kept.0.len() {
            kept.0[..end.len()].copy_from_slice(&end);
            kept.1 = end.len();
        }
    }
    let apic_base = crate::apic::base_msr();
    let sampler = Box::new(Sampler {
        pe,
        counters,
        clear,
        apic_base,
        apic_registers: crate::layout::physical(apic_base & crate::apic::BASE_ADDRESS),
        period: [const { AtomicU64::new(0) }; SAMPLED],
        armed: [const { AtomicU64::new(0) }; SAMPLED],
        adjust: [const { AtomicU64::new(0) }; SAMPLED],
        pending: [const { [const { AtomicU64::new(0) }; SAMPLED] }; PENDING],
        counts: [const { [const { AtomicU64::new(0) }; SAMPLED] }; CLASSES],
        spent: AtomicU64::new(0),
        samples: AtomicU64::new(0),
        entry: ENTRY_TICKS.max(read_ticks),
        filling: AtomicBool::new(false),
        sampled: AtomicBool::new(false),
        arena: Tags::new(state.code_virtual, state.code_bytes),
        service_calls,
        lost: AtomicU64::new(0),
        checked: AtomicU64::new(0),
    });
    for counter in 0..SAMPLED {
        sampler.period[counter].store(period, Relaxed);
        sampler.reload(counter);
    }
    let record = Box::into_raw(sampler);
    CORES[slot].store(record, Relaxed);
    // SAFETY: just published, never freed.
    unsafe { &*record }.apic().write(LVT_PERFORMANCE, LVT_NMI);
    if !ACTIVE.swap(true, Relaxed) {
        let tables = window().map_or(0, Tags::table_bytes);
        output::arguments(format_args!(
            "PMU sampling: an NMI every {} cycles and every {} instructions per PE, arena tags {} KiB (PES WHERE)\n",
            period,
            period,
            tables / 1024
        ));
    }
}

impl Sampler {
    fn apic(&self) -> crate::apic::Apic {
        crate::apic::Apic::new(self.apic_base, self.apic_registers)
    }

    /// Load `counter` `period` events short of overflowing, keeping the
    /// events it counted since it overflowed, and note what that took off
    /// its count.
    fn reload(&self, counter: usize) {
        let period = self.period[counter].load(Relaxed);
        let now = rdpmc(counter as u32) & MASK;
        let loaded = now.wrapping_sub(period) & MASK;
        wrmsr(self.counters[counter], loaded);
        let adjust = &self.adjust[counter];
        adjust.store(adjust.load(Relaxed).wrapping_add(period) & MASK, Relaxed);
        self.armed[counter].store(period, Relaxed);
    }

    /// Whether `address` is in an arena, and its region there.
    fn region(&self, address: u64) -> Option<u8> {
        if let Some(tags) = window().filter(|tags| tags.contains(address)) {
            return Some(tags.region(address));
        }
        self.arena
            .as_ref()
            .filter(|tags| tags.contains(address))
            .map(|tags| tags.region(address))
    }

    /// The class of a sample in native code at `rip`, its stack at `rsp`,
    /// below `top`, where native code was entered.
    fn native_class(&self, rip: u64, rsp: u64, top: u64) -> usize {
        let [(first, first_bytes), (second, second_bytes)] = &self.service_calls;
        let ends: [&[u8]; 2] = [&first[..*first_bytes], &second[..*second_bytes]];
        NativeSample {
            rip,
            rsp,
            top,
            filling: self.filling.load(Relaxed),
            helper: slot(local::HELPER_RSP_OFFSET) != 0,
            region: |address| self.region(address),
            // SAFETY: the stack native code runs on, from the interrupted
            // stack pointer up to where it was entered.
            word: |address| unsafe { (address as *const u64).read_volatile() },
            code: |address, bytes| {
                // SAFETY: arena code, mapped readable for its whole range,
                // which `NativeSample` checks the start of; the ends are
                // shorter than any code before a return address in it.
                Some(unsafe { core::slice::from_raw_parts(address as *const u8, bytes) })
            },
            service_calls: &ends,
        }
        .class()
    }
}

/// The value of one of this processor's local slots.
fn slot(offset: usize) -> u64 {
    let value: u64;
    // SAFETY: the permanently pinned GS record; a read of one word.
    unsafe {
        asm!("mov {}, gs:[{}]", out(reg) value, in(reg) offset,
            options(readonly, nostack, preserves_flags));
    }
    value
}

/// The NMI gate's first question: whether a sampling counter overflowed,
/// now sampled at `rip` with the interrupted stack at `rsp` and reloaded.
/// Soft-float, lock-free and allocation-free, as the gate requires.
pub(crate) fn overflow(rip: u64, rsp: u64) -> bool {
    if !ACTIVE.load(Relaxed) {
        return false;
    }
    let Some(sampler) = sampler() else {
        return false;
    };
    let entered = crate::apic::rdtsc();
    let fired = [0, 1].map(|counter| rdpmc(counter) & TOP == 0);
    if fired == [false; SAMPLED] {
        return false;
    }
    let top = slot(local::RECOVERY_RSP_OFFSET);
    let class = match top {
        0 => OUTSIDE,
        top => sampler.native_class(rip, rsp, top),
    };
    let mut bits = 0;
    for (counter, &fired) in fired.iter().enumerate() {
        if fired {
            add(
                &sampler.pending[class][counter],
                sampler.armed[counter].load(Relaxed),
            );
            sampler.reload(counter);
            bits |= 1 << counter;
        }
    }
    sampler.sampled.store(true, Relaxed);
    if let Some(clear) = sampler.clear {
        wrmsr(clear, bits);
    }
    // Intel masks the entry at each delivery.
    sampler.apic().write(LVT_PERFORMANCE, LVT_NMI);
    add(&sampler.samples, 1);
    add(
        &sampler.spent,
        crate::apic::rdtsc().wrapping_sub(entered) + sampler.entry,
    );
    true
}

/// Counter `counter` read with `read` and what reloads took off it added
/// back, so that `PES PMU`'s deltas stay whole.
pub(super) fn read(counter: usize, read: impl Fn(u32) -> u64) -> u64 {
    let Some(sampler) = sampler().filter(|_| counter < SAMPLED) else {
        return read(counter as u32);
    };
    loop {
        let adjust = sampler.adjust[counter].load(Relaxed);
        let value = read(counter as u32);
        // An NMI between the two loads reloaded the counter: read again.
        if sampler.adjust[counter].load(Relaxed) == adjust {
            return value.wrapping_add(adjust);
        }
    }
}

/// Mark a shadow page-fault fill's start or end.
pub(super) fn fill(filling: bool) {
    if let Some(sampler) = sampler() {
        sampler.filling.store(filling, Relaxed);
    }
}

/// Charge the samples since the last charge to `phase` (exit slot `slot`
/// for an exit), or to host service between slices.
fn charge_to(sampler: &Sampler, phase: Option<Phase>, slot: Option<usize>) {
    // Cleared first: an NMI from here on marks its sample again.
    sampler.sampled.store(false, Relaxed);
    for class in 0..PENDING {
        let to = charged(class, phase, slot);
        for counter in 0..SAMPLED {
            let events = sampler.pending[class][counter].swap(0, Relaxed);
            if events != 0 {
                let total = &sampler.counts[to][counter];
                total.store(total.load(Relaxed).wrapping_add(events), Relaxed);
            }
        }
    }
}

/// The step loop charged `phase`, exit slot `slot` for an exit.
#[inline]
pub(super) fn charge(phase: Phase, slot: Option<usize>) {
    if ACTIVE.load(Relaxed)
        && let Some(sampler) = sampler()
        && sampler.sampled.load(Relaxed)
    {
        charge_to(sampler, Some(phase), slot);
    }
}

/// Before a slice: the samples since the last charge were host service.
#[inline]
pub(crate) fn host_service() {
    if !ACTIVE.load(Relaxed) {
        return;
    }
    let Some(sampler) = sampler() else {
        return;
    };
    if sampler.sampled.load(Relaxed) {
        charge_to(sampler, None, None);
    }
    // An overflow whose NMI never came would stop sampling: look once in
    // LOST_CHECK_TICKS, as each RDPMC may trap, and count the reads in the
    // overhead.
    let now = crate::apic::rdtsc();
    if now.wrapping_sub(sampler.checked.load(Relaxed)) < LOST_CHECK_TICKS {
        return;
    }
    sampler.checked.store(now, Relaxed);
    for counter in 0..SAMPLED {
        let value = rdpmc(counter as u32);
        if value & TOP == 0 && value & MASK > sampler.armed[counter].load(Relaxed) {
            add(&sampler.lost, 1);
            sampler.reload(counter);
        }
    }
    add(&sampler.spent, crate::apic::rdtsc().wrapping_sub(now));
}

/// The engine installed `bytes` of code at `code` as `regions`
/// ([`stela_engine::machine::Host::profile_code`]).
pub(super) fn tag(code: u64, bytes: usize, regions: &[(u32, CodeRegion)]) {
    if !ACTIVE.load(Relaxed) {
        return;
    }
    let described = window().is_some_and(|tags| tags.describe(code, bytes, regions));
    if !described && let Some(tags) = sampler().and_then(|sampler| sampler.arena.as_ref()) {
        tags.describe(code, bytes, regions);
    }
}

/// What the line compares against: each PE's counts, ticks and samples at
/// the last beat.
pub(crate) struct Seen {
    counts: Vec<Counts>,
    spent: Vec<u64>,
    samples: Vec<u64>,
    lost: Vec<u64>,
    at: u64,
}

impl Seen {
    pub(crate) const fn new() -> Self {
        Self {
            counts: Vec::new(),
            spent: Vec::new(),
            samples: Vec::new(),
            lost: Vec::new(),
            at: 0,
        }
    }
}

/// The share of `pe`'s cycles and of its instructions native code took
/// since the last `PES WHERE` line, in parts per million, from its samples;
/// `None` without samples. `PES PMU` scales its whole-PE counts by it where
/// no window measured native code alone ([`super::pmu::report`]).
pub(crate) fn native_share(seen: &Seen, pe: usize) -> Option<[u64; SAMPLED]> {
    let sampler = CORES.iter().find_map(|slot| {
        let pointer = slot.load(Relaxed);
        // SAFETY: leaked at `start`, never freed.
        (!pointer.is_null())
            .then(|| unsafe { &*pointer })
            .filter(|sampler| sampler.pe == pe)
    })?;
    let mut share = [0; SAMPLED];
    for (counter, share) in share.iter_mut().enumerate() {
        let (mut all, mut natives) = (0u64, 0u64);
        for class in 0..CLASSES {
            let before = seen
                .counts
                .get(pe)
                .map_or(0, |counts| counts[class][counter]);
            let events = sampler.counts[class][counter]
                .load(Relaxed)
                .wrapping_sub(before);
            all += events;
            if native(class) {
                natives += events;
            }
        }
        *share = (u128::from(natives) * 1_000_000).checked_div(u128::from(all))? as u64;
    }
    Some(share)
}

/// The `PES WHERE` lines for the beat that ends now: one per sampling PE,
/// then `all:` the machine's.
///
/// `PES WHERE pe=N samples=S overhead=X% period=C/I native=I/C name=I/C
/// ...`: of the PE's host instructions and cycles in the beat (each
/// sample weighs its period), the share in percent native code took, then
/// each class that took 0.1% or more of either: the arena regions
/// ([`CodeRegion::name`]), `pac-call`, `call`, `helper`, `fill`,
/// `nat-other`, then outside native code `glue`, `sch`, `dev`, `fetch`,
/// `x:KIND` per exit kind, `x:other` and `host`. `overhead=` is the NMIs'
/// share of the beat's TSC ticks; `lost=` overflows whose NMI never came.
pub(crate) fn report(seen: &mut Seen) {
    if !ACTIVE.load(Relaxed) {
        return;
    }
    let mut samplers: Vec<&Sampler> = CORES
        .iter()
        .filter_map(|slot| {
            let pointer = slot.load(Relaxed);
            // SAFETY: leaked at `start`, never freed.
            (!pointer.is_null()).then(|| unsafe { &*pointer })
        })
        .collect();
    samplers.sort_by_key(|sampler| sampler.pe);
    let pes = samplers.last().map_or(0, |sampler| sampler.pe + 1);
    if seen.counts.len() < pes {
        seen.counts.resize(pes, [[0; SAMPLED]; CLASSES]);
        seen.spent.resize(pes, 0);
        seen.samples.resize(pes, 0);
        seen.lost.resize(pes, 0);
    }
    let now = crate::apic::rdtsc();
    let elapsed = match seen.at {
        0 => 0,
        at => now.wrapping_sub(at),
    };
    seen.at = now;
    let mut machine = [[0u64; SAMPLED]; CLASSES];
    for sampler in &samplers {
        let pe = sampler.pe;
        let mut classes = [[0u64; SAMPLED]; CLASSES];
        for (class, events) in classes.iter_mut().enumerate() {
            for (counter, value) in events.iter_mut().enumerate() {
                let total = sampler.counts[class][counter].load(Relaxed);
                *value = total.wrapping_sub(seen.counts[pe][class][counter]);
                seen.counts[pe][class][counter] = total;
                machine[class][counter] += *value;
            }
        }
        let spent = sampler.spent.load(Relaxed);
        let beat_spent = spent.wrapping_sub(core::mem::replace(&mut seen.spent[pe], spent));
        let samples = sampler.samples.load(Relaxed);
        let beat_samples = samples.wrapping_sub(core::mem::replace(&mut seen.samples[pe], samples));
        let lost = sampler.lost.load(Relaxed);
        let beat_lost = lost.wrapping_sub(core::mem::replace(&mut seen.lost[pe], lost));
        // Over budget: the next periods double, each counter at its next
        // reload.
        if elapsed != 0 && beat_spent.saturating_mul(OVERHEAD_SHARE) > elapsed {
            for period in &sampler.period {
                let doubled = (period.load(Relaxed) * 2).min(MAX_PERIOD);
                period.store(doubled, Relaxed);
            }
        }
        let overhead = (u128::from(beat_spent) * 10_000)
            .checked_div(u128::from(elapsed))
            .unwrap_or(0);
        let mut line = format!(
            "PES WHERE pe={pe} samples={beat_samples} overhead={}.{:02}% period={}M/{}M",
            overhead / 100,
            overhead % 100,
            sampler.period[0].load(Relaxed) >> 20,
            sampler.period[1].load(Relaxed) >> 20,
        );
        if beat_lost != 0 {
            line.push_str(&format!(" lost={beat_lost}"));
        }
        line.push_str(&shares(&classes, &EXIT_NAMES));
        line.push('\n');
        output::arguments(format_args!("{line}"));
    }
    let mut line = String::from("PES WHERE all:");
    line.push_str(&shares(&machine, &EXIT_NAMES));
    line.push('\n');
    output::arguments(format_args!("{line}"));
}

//! `GPU PERF`: the GPU's performance state as GSP-RM reports it. nouveau
//! asks RM every second for the current P-state
//! (`nvkm/subdev/gsp/rm/r535/perf.c`) and adds it to a report this module
//! takes once a beat. The line comes at the first beat after GSP starts and
//! then only when the state changed, so an idle desktop stays quiet. If RM
//! refused the control, every line names its errno, as the state is unknown.
//! Each round also reads the GPU's PCIe link, which RM moves with the
//! P-state, so the line shows whether the link follows load too. Clocks are
//! not read: GSP-RM 570.144's headers define no clock control, and RM refused
//! the 615.78.08 one.
use alloc::{format, string::String};
use core::{
    fmt,
    sync::atomic::{AtomicI32, AtomicU32, Ordering},
};

/// `include/nvkm/core/counts.h`: `struct nvkm_perf_report`, which nouveau
/// updates only atomically.
#[repr(C)]
pub struct Report {
    started: AtomicU32,
    rounds: AtomicU32,
    pstate: AtomicU32,
    pstates: AtomicU32,
    pstate_status: AtomicI32,
    link_status: AtomicU32,
    link_control: AtomicU32,
    link_speeds: AtomicU32,
    link_cap: AtomicU32,
}

impl Report {
    /// As nouveau defines it: nothing sampled yet.
    pub const fn new() -> Self {
        Self {
            started: AtomicU32::new(0),
            rounds: AtomicU32::new(0),
            pstate: AtomicU32::new(0),
            pstates: AtomicU32::new(0),
            pstate_status: AtomicI32::new(0),
            link_status: AtomicU32::new(0),
            link_control: AtomicU32::new(0),
            link_speeds: AtomicU32::new(0),
            link_cap: AtomicU32::new(0),
        }
    }

    /// What nouveau sampled since the last take, cleared; `None` before GSP
    /// started or when no round ran since.
    pub fn take(&self) -> Option<Taken> {
        if self.started.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let rounds = self.rounds.swap(0, Ordering::Relaxed);
        let pstates = self.pstates.swap(0, Ordering::Relaxed);
        let link_speeds = self.link_speeds.swap(0, Ordering::Relaxed);
        (rounds != 0).then(|| Taken {
            rounds,
            pstate: self.pstate.load(Ordering::Relaxed),
            pstates,
            status: self.pstate_status.load(Ordering::Relaxed),
            link: Link {
                status: self.link_status.load(Ordering::Relaxed) as u16,
                control: self.link_control.load(Ordering::Relaxed) as u16,
                speeds: link_speeds,
                cap: self.link_cap.load(Ordering::Relaxed) as u16,
            },
        })
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

/// One beat's samples.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Taken {
    /// Rounds that asked RM.
    pub rounds: u32,
    /// The current P-state's bit (`NV2080_CTRL_PERF_PSTATES_P0` is bit 0),
    /// zero while unknown.
    pub pstate: u32,
    /// Every P-state bit a round saw.
    pub pstates: u32,
    /// The errno of the control RM refused, else zero.
    pub status: i32,
    /// The GPU's PCIe link.
    pub link: Link,
}

impl Taken {
    /// What a change is judged by: the P-states, the status and the link,
    /// not the count of rounds.
    fn state(&self) -> [u64; 2] {
        let link = &self.link;
        [
            u64::from(self.pstate) << 32 | u64::from(self.pstates),
            u64::from(self.status as u32) << 32
                | u64::from(link.speed()) << 24
                | u64::from(link.width()) << 16
                | u64::from(link.aspm()) << 14
                | u64::from(link.speeds & 0x3ff),
        ]
    }
}

/// The GPU's PCIe link as its capability reported it (PCIe Base 6.0,
/// 7.5.3.6-7.5.3.8), all zero when nothing was read.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Link {
    /// Link Status as last read.
    pub status: u16,
    /// Link Control as last read.
    pub control: u16,
    /// A bit per Link Status speed code seen; bit 1 is 2.5 GT/s.
    pub speeds: u32,
    /// Link Capabilities' low word: maximum speed and width.
    pub cap: u16,
}

impl Link {
    /// Current Link Speed: 1 for 2.5 GT/s (gen1) to 6 for 64 GT/s (gen6).
    fn speed(&self) -> u16 {
        self.status & 0xf
    }

    /// Negotiated Link Width.
    fn width(&self) -> u16 {
        self.status >> 4 & 0x3f
    }

    /// ASPM Control: bit 0 L0s, bit 1 L1.
    fn aspm(&self) -> u16 {
        self.control & 3
    }

    fn read(&self) -> bool {
        self.status != 0
    }
}

/// `gen5x16` for a speed code and a width.
struct Lane(u16, u16);

impl fmt::Display for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gen{}x{}", self.0, self.1)
    }
}

/// `pcie=gen5x16 pcie_seen=gen1+gen5 pcie_max=gen5x16 aspm=L1`, or
/// `pcie=unknown` when nothing was read.
impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.read() {
            return f.write_str("pcie=unknown");
        }
        write!(f, "pcie={} pcie_seen=", Lane(self.speed(), self.width()))?;
        let mut first = true;
        for speed in (1..16).filter(|speed| self.speeds & 1 << speed != 0) {
            if !first {
                f.write_str("+")?;
            }
            first = false;
            write!(f, "gen{speed}")?;
        }
        if first {
            f.write_str("-")?;
        }
        write!(
            f,
            " pcie_max={} aspm={}",
            Lane(self.cap & 0xf, self.cap >> 4 & 0x3f),
            ["off", "L0s", "L1", "L0s+L1"][usize::from(self.aspm())]
        )
    }
}

/// `P0+P8` for a set of P-state bits.
struct Pstates(u32);

impl fmt::Display for Pstates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for index in (0..16).filter(|index| self.0 & 1 << index != 0) {
            if !first {
                f.write_str("+")?;
            }
            first = false;
            write!(f, "P{index}")?;
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// `pstate=P8 seen=P5+P8 <link> rounds=N`, or
/// `pstate=unknown(error E) <link> rounds=N`.
impl fmt::Display for Taken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            0 => write!(
                f,
                "pstate={} seen={}",
                Pstates(self.pstate),
                Pstates(self.pstates)
            )?,
            error => write!(f, "pstate=unknown(error {error})")?,
        }
        write!(f, " {} rounds={}", self.link, self.rounds)
    }
}

/// The state the last line reported.
pub struct Reported {
    last: spin_cell::Cell,
}

impl Reported {
    pub const fn new() -> Self {
        Self {
            last: spin_cell::Cell::new(),
        }
    }

    /// `GPU PERF …` for `taken` when it is the first or its state changed
    /// since the last line.
    pub fn line(&self, taken: &Taken) -> Option<String> {
        self.last
            .replace(taken.state())
            .is_none_or(|last| last != taken.state())
            .then(|| format!("GPU PERF {taken}"))
    }
}

impl Default for Reported {
    fn default() -> Self {
        Self::new()
    }
}

/// The last reported state behind a spin lock: a beat's report is the only
/// writer, so it never waits in practice.
mod spin_cell {
    use core::{
        cell::UnsafeCell,
        sync::atomic::{AtomicBool, Ordering},
    };

    pub struct Cell {
        held: AtomicBool,
        value: UnsafeCell<Option<[u64; 2]>>,
    }

    // SAFETY: `replace` holds `held` for every access to the value.
    unsafe impl Sync for Cell {}

    impl Cell {
        pub const fn new() -> Self {
            Self {
                held: AtomicBool::new(false),
                value: UnsafeCell::new(None),
            }
        }

        /// Stores `value`, giving the one before.
        pub fn replace(&self, value: [u64; 2]) -> Option<[u64; 2]> {
            while self
                .held
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            // SAFETY: `held` excludes every other access until released.
            let last = unsafe { (*self.value.get()).replace(value) };
            self.held.store(false, Ordering::Release);
            last
        }
    }
}

#[cfg(test)]
mod tests;

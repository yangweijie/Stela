//! PCI ports whose slot power firmware left off (D3cold), powered on
//! through ACPI before the PCI census, as Linux powers each device on as it
//! adds it ([`stela_drivers::probe::d3cold`] says which and how). The
//! census, containment, the DMA remapping units and the drivers then see
//! what lies below such a port, a hybrid laptop's discrete GPU, as they see
//! what firmware left on.
//!
//! Per port: its ACPI companion's power resources, `_PS0` and `_REG`, in
//! one bounded firmware call that admits the AML's PCI configuration
//! writes; the PM capability to D0 (Linux `pci_power_up`); the link and
//! the first function below it (Linux `pci_bridge_wait_for_secondary_bus`
//! and `pci_dev_wait`, at most 1 s for the link and 60 s for the function);
//! then the same ACPI power-on for each function that answered. This runs
//! on the boot processor before the other processors start and before the
//! guest; every wait is bounded and taken in slices of [`SLICE_US`]. One
//! line per port says what happened and how long it took.
use super::{aml::HostAcpi, host};
use crate::{native_mmio::Source, output};
use alloc::{format, string::String, vec::Vec};
use stela_drivers::{
    block::BlockError,
    bus::{
        mmio::owned::Error,
        pci::{
            Address, ConfigError, ConfigFailure, ConfigSpace,
            bus_reset::{SecondaryBus, wait_for_secondary_bus},
            power_up_config,
        },
    },
    probe::d3cold::{self, PowerOnError, PoweredOn, Topology},
};

/// The longest one spin of a wait.
const SLICE_US: u64 = 10_000;

/// One function's configuration before the census, through the native
/// owner's scoped maps: reads as AML's are served, writes as
/// [`Source::write_before_census`] admits them.
struct Unclaimed {
    source: &'static Source,
    address: Address,
}

impl Unclaimed {
    fn read(&self, offset: u16, width: u16) -> Result<u32, ConfigError> {
        self.source
            .read_firmware_config(self.address, offset, width)
            .map_err(refused)
    }
    fn write(&mut self, offset: u16, width: u16, value: u32) -> Result<(), ConfigError> {
        self.source
            .write_before_census(self.address, offset, width, value)
            .map_err(refused)
    }
}

fn refused(error: Error) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Mapping(error))
}

impl ConfigSpace for Unclaimed {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.read(offset, 1).map(|value| value as u8)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.read(offset, 2).map(|value| value as u16)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.read(offset, 4)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.write(offset, 1, value.into())
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.write(offset, 2, value.into())
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.write(offset, 4, value)
    }
}

/// Wait `microseconds` on the TSC, in slices of at most [`SLICE_US`].
fn wait(tsc_hz: u64, microseconds: u64) -> Result<(), BlockError> {
    let mut left = microseconds;
    while left != 0 {
        let slice = left.min(SLICE_US);
        let start = host::rdtsc();
        let ticks = tsc_hz / 1_000_000 * slice;
        while host::rdtsc().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
        left -= slice;
    }
    Ok(())
}

/// What a port's power-on came to.
enum Came {
    /// The first function below the port answers.
    Up {
        done: PoweredOn,
        child: Address,
        identity: u32,
        class: u32,
        notes: Vec<String>,
    },
    /// The port's hot-plug slot is empty: nothing to wait for.
    EmptySlot { done: PoweredOn },
}

/// Why a port's power-on failed.
enum Failure {
    /// The firmware call did not finish or could not run; its line says.
    Unfinished,
    /// ACPI no longer reports the port's power off.
    NotOff,
    Firmware(PowerOnError),
    /// The port's PM capability did not reach D0.
    PowerState(BlockError),
    /// The port has no secondary bus the scan passed.
    NoBus,
    NoLink,
    Silent(u8),
    Wait(BlockError),
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unfinished => f.write_str("its firmware call did not finish"),
            Self::NotOff => f.write_str("ACPI no longer reports its power off"),
            Self::Firmware(error) => write!(f, "{error}"),
            Self::PowerState(error) => write!(f, "it did not enter D0 ({error:?})"),
            Self::NoBus => f.write_str("it has no secondary bus"),
            Self::NoLink => f.write_str("its link did not come up within 1 s"),
            Self::Silent(bus) => write!(
                f,
                "nothing answered on bus {bus:02x} within Linux's bound for it"
            ),
            Self::Wait(error) => write!(f, "its link could not be read ({error:?})"),
        }
    }
}

/// Power on each PCI port reachable from the ACPI host bridges whose
/// secondary bus answers nothing while ACPI reports its power off, and wait
/// for what lies below it, before the census. Nothing is logged where no
/// port qualifies.
pub(super) fn power_on_ports(acpi: &'static HostAcpi, source: &'static Source, tsc_hz: u64) {
    let Some(roots) = acpi.firmware(
        "PCI host bridge buses",
        "no PCI port is powered on",
        false,
        d3cold::roots,
    ) else {
        return;
    };
    // SAFETY: before the census and the other processors, the boot owns
    // every captured configuration bus, and nothing else writes them; the
    // scan only reads.
    let scanned = unsafe {
        source.with_config_inventory(|_, reader| {
            Ok::<_, Error>(Topology::scan(&roots, |address, offset| {
                reader.read32(address, offset).ok()
            }))
        })
    };
    let mut topology = match scanned {
        Ok(topology) => topology,
        Err(error) => {
            output::arguments(format_args!(
                "HOST PCI ports not scanned before the census ({error:?}): none is powered on\n"
            ));
            return;
        }
    };
    if topology.empty_ports().next().is_none() {
        return;
    }
    let ports = {
        let topology = topology.clone();
        acpi.firmware(
            "PCI port power check",
            "no PCI port is powered on",
            false,
            move |session| d3cold::powered_off(session, &topology),
        )
        .unwrap_or_default()
    };
    for port in ports {
        let started = host::rdtsc();
        let came = power_on(acpi, source, &mut topology, port, tsc_hz);
        let ms = host::rdtsc().wrapping_sub(started) / (tsc_hz / 1000).max(1);
        match came {
            Ok(Came::Up {
                done,
                child,
                identity,
                class,
                notes,
            }) => {
                let mut line = format!(
                    "HOST PCI {port} powered on through ACPI ({done}) in {ms} ms: {child} \
                     answers, {:04x}:{:04x} class {:06x}",
                    identity & 0xffff,
                    identity >> 16,
                    class >> 8
                );
                for note in notes {
                    line.push_str("; ");
                    line.push_str(&note);
                }
                output::arguments(format_args!("{line}\n"));
            }
            Ok(Came::EmptySlot { done }) => output::arguments(format_args!(
                "HOST PCI {port} powered on through ACPI ({done}) in {ms} ms: its hot-plug slot \
                 is empty\n"
            )),
            Err(failure) => output::arguments(format_args!(
                "HOST PCI {port} power-on through ACPI failed after {ms} ms: {failure}; what \
                 lies below it stays off and the PCI census does not see it\n"
            )),
        }
    }
}

/// Linux's power-on of one port as it adds it, then the wait for what is
/// below it, then the power-on of each function that answered.
fn power_on(
    acpi: &'static HostAcpi,
    source: &'static Source,
    topology: &mut Topology,
    port: Address,
    tsc_hz: u64,
) -> Result<Came, Failure> {
    let done = {
        let topology = topology.clone();
        acpi.firmware(
            "PCI port power-on",
            "the port stays off",
            true,
            move |session| d3cold::power_on(session, &topology, port),
        )
        .ok_or(Failure::Unfinished)?
        .map_err(Failure::Firmware)?
        .ok_or(Failure::NotOff)?
    };
    let delay = |microseconds| wait(tsc_hz, microseconds);
    let mut config = Unclaimed {
        source,
        address: port,
    };
    power_up_config(&mut config, delay).map_err(Failure::PowerState)?;
    let secondary = topology.secondary(port).ok_or(Failure::NoBus)?;
    if d3cold::slot_empty(&config).map_err(Failure::Wait)? {
        return Ok(Came::EmptySlot { done });
    }
    let child = Address {
        segment: port.segment,
        bus: secondary,
        device: 0,
        function: 0,
    };
    let first = Unclaimed {
        source,
        address: child,
    };
    match wait_for_secondary_bus(&config, &first, delay).map_err(Failure::Wait)? {
        SecondaryBus::Ready => {}
        SecondaryBus::NoLink => return Err(Failure::NoLink),
        SecondaryBus::Silent => return Err(Failure::Silent(secondary)),
    }
    let identity = first
        .read32(0)
        .map_err(|error| Failure::Wait(error.into()))?;
    let class = first
        .read32(8)
        .map_err(|error| Failure::Wait(error.into()))?;
    let found = topology.scan_below(port, |address, offset| {
        source.read_firmware_config(address, offset, 4).ok()
    });
    let mut notes = Vec::new();
    for function in found {
        let snapshot = topology.clone();
        match acpi.firmware(
            "PCI function power-on",
            "the function stays as it is",
            true,
            move |session| d3cold::power_on(session, &snapshot, function),
        ) {
            Some(Ok(Some(done))) => notes.push(format!("ACPI brought {function} to D0 ({done})")),
            Some(Ok(None)) => {}
            Some(Err(error)) => notes.push(format!("{function} stays as it is: {error}")),
            None => notes.push(format!("{function}'s firmware call did not finish")),
        }
        let mut config = Unclaimed {
            source,
            address: function,
        };
        if let Err(error) = power_up_config(&mut config, delay) {
            notes.push(format!("{function} did not enter D0 ({error:?})"));
        }
    }
    Ok(Came::Up {
        done,
        child,
        identity,
        class,
        notes,
    })
}

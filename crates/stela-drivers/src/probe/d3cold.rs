//! PCI ports whose slot power firmware left off (D3cold), and their
//! power-on through ACPI before the PCI census.
//!
//! Linux brings every PCI device it adds to D0 before it scans below it
//! (`pci_pm_init`, `pci_power_up`, `acpi_pci_set_power_state`,
//! `acpi_device_set_power`): each `_PR0` power resource of the device's
//! ACPI companion is turned on with `_ON`, in `_PR0` order, then `_PS0`
//! runs, then `_REG(PCI_Config, connect)`; then the PM capability is put in
//! D0. A hybrid laptop's discrete GPU sits below a root port whose slot
//! power firmware left off, so only that power-on makes it answer.
//!
//! Which devices are powered on: a PCI bridge reachable from an ACPI host
//! bridge whose secondary bus answers nothing, and then each function that
//! answers below it, when its ACPI companion is power-manageable (`_PR0`
//! or `_PS0`), has no `_EJ0` (Linux leaves such a device's power alone)
//! and reports its power off ([`power_off`]). Linux powers on every device
//! it enumerates; these are the only ones where that changes what the
//! census can see, so nothing is powered on that Linux leaves off. Nothing
//! is turned off again: Linux keeps a device without a driver in D0, and
//! turns no device power resource off at power-off or reboot.
use super::native::{Bridge, companion, integer};
use crate::block::BlockError;
use crate::bus::pci::{Address, CAPABILITY_EXPRESS, ConfigSpace, capability::capabilities};
use alloc::{string::String, vec::Vec};

/// Said of a PCI port whose secondary bus answers nothing while ACPI reports
/// the power below it off, which Stela powers on before the PCI census:
/// that power-on failed or did not run, and its own line says which.
pub(super) const POWERED_OFF_PORT: &str = "its secondary bus answers nothing and ACPI reports the \
     power below it off (D3cold); no function answered after Stela powered it on before the PCI \
     census, or that power-on did not run, as the HOST PCI line naming this port before the \
     census says";

/// What answers on the buses reachable from the root buses, as a
/// depth-first scan through bridges finds it.
#[derive(Clone, Debug, Default)]
pub struct Topology {
    bridges: Vec<Bridge>,
    found: Vec<(Address, [u8; 3])>,
}

/// The Vendor ID nothing answers with.
const ABSENT: u16 = 0xffff;
const HEADER_BRIDGE: u8 = 1;
const MULTIFUNCTION: u8 = 0x80;

impl Topology {
    /// Linux's `pci_scan_child_bus` from each of `roots`, each a segment
    /// and bus, down every bridge whose secondary bus lies above its own:
    /// functions 1 to 7 only of a multifunction device, and each bus once.
    /// `read` reads the dword at a register of a function, `None` where it
    /// cannot; such a function counts as absent. Reads only.
    pub fn scan(roots: &[(u16, u8)], mut read: impl FnMut(Address, u16) -> Option<u32>) -> Self {
        let mut topology = Self::default();
        topology.scan_from(roots, &mut read);
        topology
    }

    /// [`Self::scan`] of the buses below `port`, added to this topology;
    /// the functions newly found, upstream first.
    pub fn scan_below(
        &mut self,
        port: Address,
        mut read: impl FnMut(Address, u16) -> Option<u32>,
    ) -> Vec<Address> {
        let Some(secondary) = self.secondary(port) else {
            return Vec::new();
        };
        let before = self.found.len();
        self.scan_from(&[(port.segment, secondary)], &mut read);
        self.found[before..]
            .iter()
            .map(|&(address, _)| address)
            .collect()
    }

    fn scan_from(
        &mut self,
        roots: &[(u16, u8)],
        read: &mut dyn FnMut(Address, u16) -> Option<u32>,
    ) {
        let mut pending: Vec<(u16, u8)> = roots.iter().rev().copied().collect();
        let mut seen: Vec<(u16, u8)> = Vec::new();
        while let Some((segment, bus)) = pending.pop() {
            if seen.contains(&(segment, bus)) {
                continue;
            }
            seen.push((segment, bus));
            let mut below = Vec::new();
            for device in 0..32 {
                for function in 0..8 {
                    let address = Address {
                        segment,
                        bus,
                        device,
                        function,
                    };
                    let present = read(address, 0).is_some_and(|word| word as u16 != ABSENT);
                    if !present {
                        if function == 0 {
                            break;
                        }
                        continue;
                    }
                    let class = read(address, 8).unwrap_or(0).to_be_bytes();
                    let header = (read(address, 0x0c).unwrap_or(0) >> 16) as u8;
                    if !self.found.iter().any(|&(found, _)| found == address) {
                        self.found.push((address, [class[0], class[1], class[2]]));
                    }
                    if header & 0x7f == HEADER_BRIDGE {
                        let [_, secondary, subordinate, _] =
                            read(address, 0x18).unwrap_or(0).to_le_bytes();
                        if secondary > bus && subordinate >= secondary {
                            if !self.bridges.iter().any(|bridge| bridge.address == address) {
                                self.bridges.push(Bridge {
                                    address,
                                    secondary,
                                    aspm: 0,
                                });
                            }
                            below.push((segment, secondary));
                        }
                    }
                    if function == 0 && header & MULTIFUNCTION == 0 {
                        break;
                    }
                }
            }
            // Depth first, in device order: the first bridge's bus next.
            pending.extend(below.into_iter().rev());
        }
    }

    /// The secondary bus of the bridge at `port`, when the scan passed it.
    pub fn secondary(&self, port: Address) -> Option<u8> {
        self.bridges
            .iter()
            .find(|bridge| bridge.address == port)
            .map(|bridge| bridge.secondary)
    }

    /// Whether any function answers on the secondary bus of `port`.
    pub fn answers_below(&self, port: Address) -> bool {
        self.secondary(port).is_some_and(|secondary| {
            self.found
                .iter()
                .any(|(address, _)| address.segment == port.segment && address.bus == secondary)
        })
    }

    /// The bridges whose secondary bus holds none of the functions found.
    pub fn empty_ports(&self) -> impl Iterator<Item = Address> + '_ {
        empty_ports(&self.bridges, &self.found).map(|bridge| bridge.address)
    }
}

/// The bridges among `bridges` with a secondary bus that holds none of the
/// functions `found`.
pub(super) fn empty_ports<'a>(
    bridges: &'a [Bridge],
    found: &'a [(Address, [u8; 3])],
) -> impl Iterator<Item = &'a Bridge> + 'a {
    bridges.iter().filter(|bridge| {
        // A bridge without a bus number of its own forwards nothing yet.
        bridge.secondary > bridge.address.bus
            && !found.iter().any(|(address, _)| {
                address.segment == bridge.address.segment && address.bus == bridge.secondary
            })
    })
}

/// Whether a device's power is off as Linux's `acpi_bus_init_power` infers
/// it: `_PSC` above D0 when present, else any of its `_PR0` power
/// resources off (`_STA` 0); `resources` holds each resource's `_STA`,
/// `None` where it did not evaluate.
pub(super) fn power_off(psc: Option<u64>, resources: &[Option<u64>]) -> bool {
    match psc {
        Some(state) => state != 0,
        None => resources.contains(&Some(0)),
    }
}

/// The PCI Express capability's flags, slot capabilities and slot status,
/// and in them Slot Implemented, Hot-Plug Capable and Presence Detect
/// State.
const EXPRESS_FLAGS: u16 = 2;
const SLOT_IMPLEMENTED: u16 = 1 << 8;
const SLOT_CAPABILITIES: u16 = 0x14;
const HOT_PLUG_CAPABLE: u32 = 1 << 6;
const SLOT_STATUS: u16 = 0x1a;
const PRESENCE_DETECTED: u16 = 1 << 6;

/// Whether `port` reports a hot-plug slot with nothing in it: Slot
/// Implemented, Hot-Plug Capable and Presence Detect State clear. Such a
/// port's link is not waited for; pciehp would bring up what is plugged in
/// later. Reads only.
pub fn slot_empty<C: ConfigSpace>(port: &C) -> Result<bool, BlockError> {
    let mut express = None;
    for entry in capabilities(port) {
        let entry = entry?;
        if entry.id == CAPABILITY_EXPRESS {
            express = Some(entry.offset);
            break;
        }
    }
    let Some(express) = express else {
        return Ok(false);
    };
    Ok(
        port.read16(express + EXPRESS_FLAGS)? & SLOT_IMPLEMENTED != 0
            && port.read32(express + SLOT_CAPABILITIES)? & HOT_PLUG_CAPABLE != 0
            && port.read16(express + SLOT_STATUS)? & PRESENCE_DETECTED == 0,
    )
}

/// What bringing a device to D0 through ACPI did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoweredOn {
    /// The `_PR0` power resources turned on with `_ON`.
    pub resources: usize,
    /// `_PS0` ran.
    pub ps0: bool,
    /// `_REG(PCI_Config, connect)` ran and returned.
    pub reg: bool,
}

/// A plain account for the boot log.
impl core::fmt::Display for PoweredOn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} power resource{} turned on",
            self.resources,
            if self.resources == 1 { "" } else { "s" }
        )?;
        if self.ps0 {
            f.write_str(", _PS0")?;
        }
        if self.reg {
            f.write_str(", _REG")?;
        }
        Ok(())
    }
}

/// Why a device was not brought to D0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PowerOnError {
    /// `_PR0` evaluates to something other than a package of power
    /// resource references.
    Resources(String),
    /// A method failed with this ACPICA status.
    Method { path: String, status: u32 },
}

/// A plain account for the boot log.
impl core::fmt::Display for PowerOnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resources(path) => {
                write!(f, "{path}._PR0 is not a package of power resources")
            }
            Self::Method { path, status } => {
                write!(f, "{path} failed with ACPICA status {status:#x}")
            }
        }
    }
}

/// The root buses the ACPI host bridges declare by `_SEG` and `_BBN`.
pub fn roots(session: &crate::platform::acpi::Session) -> Vec<(u16, u8)> {
    super::native::roots(session)
        .into_iter()
        .map(|(_, segment, bus)| (segment, bus))
        .collect()
}

/// A device's ACPI companion as [`power_on`] judges it.
struct Companion<'a> {
    handle: crate::platform::acpi::Handle<'a>,
    resources: Vec<crate::platform::acpi::Handle<'a>>,
}

/// The companion of the function at `address`, when it is power-manageable,
/// has no `_EJ0` and reports its power off; `None` else, or when it has no
/// companion. Only `_PSC`, `_PR0` and its resources' `_STA` are evaluated.
fn off<'a>(
    session: &'a crate::platform::acpi::Session,
    bridges: &[Bridge],
    address: Address,
) -> Result<Option<Companion<'a>>, PowerOnError> {
    use crate::platform::acpi::Value;
    let Some(handle) = companion(session, address, bridges) else {
        return Ok(None);
    };
    let has = |name: &str| handle.child(name).is_ok();
    if has("_EJ0") || !(has("_PR0") || has("_PS0")) {
        return Ok(None);
    }
    let path = || handle.path().unwrap_or_default();
    let mut resources = Vec::new();
    if has("_PR0") {
        let listed = match handle.evaluate(Some("_PR0"), &[]) {
            Ok(Some(Value::Package(listed))) => listed,
            Ok(_) => return Err(PowerOnError::Resources(path())),
            Err(error) => {
                return Err(PowerOnError::Method {
                    path: path() + "._PR0",
                    status: error.0,
                });
            }
        };
        for resource in listed {
            let Value::Reference(resource) = resource else {
                return Err(PowerOnError::Resources(path()));
            };
            resources.push(resource.handle);
        }
    }
    let states: Vec<_> = resources
        .iter()
        .map(|&resource| integer(resource, "_STA"))
        .collect();
    if !power_off(integer(handle, "_PSC"), &states) {
        return Ok(None);
    }
    Ok(Some(Companion { handle, resources }))
}

/// The ports among `topology`'s bridges with an empty secondary bus whose
/// companion reports their power off, as [`power_on`] would turn on.
/// Nothing is turned on.
pub fn powered_off(session: &crate::platform::acpi::Session, topology: &Topology) -> Vec<Address> {
    powered_off_ports(session, &topology.bridges, &topology.found)
}

/// [`powered_off`] over a probe's bridges and the functions it found.
pub(super) fn powered_off_ports(
    session: &crate::platform::acpi::Session,
    bridges: &[Bridge],
    found: &[(Address, [u8; 3])],
) -> Vec<Address> {
    empty_ports(bridges, found)
        .filter(|bridge| matches!(off(session, bridges, bridge.address), Ok(Some(_))))
        .map(|bridge| bridge.address)
        .collect()
}

/// Bring the ACPI companion of the function at `address` to D0 as Linux's
/// `acpi_pci_set_power_state(D0)` does, when it reports its power off:
/// each `_PR0` power resource whose `_STA` does not read on gets `_ON`, in
/// `_PR0` order (Linux runs `_ON` on a resource's first reference), then
/// `_PS0` runs, then `_REG(PCI_Config, connect)`, whose failure Linux only
/// notes. `None` when there is nothing Linux would change: no companion,
/// one with `_EJ0` or without `_PR0` and `_PS0`, or one that reports its
/// power on. A method that fails stops here; what it did stays done.
pub fn power_on(
    session: &crate::platform::acpi::Session,
    topology: &Topology,
    address: Address,
) -> Result<Option<PoweredOn>, PowerOnError> {
    use crate::platform::acpi::Argument;
    /// `ACPI_ADR_SPACE_PCI_CONFIG` and `ACPI_REG_CONNECT`.
    const PCI_CONFIG: u64 = 2;
    const CONNECT: u64 = 1;
    let Some(Companion { handle, resources }) = off(session, &topology.bridges, address)? else {
        return Ok(None);
    };
    let failed =
        |handle: crate::platform::acpi::Handle<'_>, method: &str, status| PowerOnError::Method {
            path: handle.path().unwrap_or_default() + "." + method,
            status,
        };
    let mut done = PoweredOn::default();
    for resource in resources {
        if integer(resource, "_STA") != Some(1) {
            resource
                .evaluate(Some("_ON"), &[])
                .map_err(|error| failed(resource, "_ON", error.0))?;
            done.resources += 1;
        }
    }
    if handle.child("_PS0").is_ok() {
        handle
            .evaluate(Some("_PS0"), &[])
            .map_err(|error| failed(handle, "_PS0", error.0))?;
        done.ps0 = true;
    }
    if handle.child("_REG").is_ok() {
        done.reg = handle
            .evaluate(
                Some("_REG"),
                &[Argument::Integer(PCI_CONFIG), Argument::Integer(CONNECT)],
            )
            .is_ok();
    }
    Ok(Some(done))
}

#[cfg(test)]
mod tests;

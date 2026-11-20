//! A simulated PCI fabric of root ports, one whose slot power is off until
//! its ACPI power resource's `_ON` clears Link Disable in the port's
//! configuration space, with the GPU below it answering only once the link
//! is up and after a few Configuration RRS completions.
extern crate std;
use super::*;
use crate::bus::pci::ConfigError;
use alloc::vec::Vec;
use std::{collections::BTreeMap, sync::Mutex};

fn at(bus: u8, device: u8, function: u8) -> Address {
    Address {
        segment: 0,
        bus,
        device,
        function,
    }
}

const PORT: (u8, u8, u8) = (0, 0x1c, 0);
const GPU: (u8, u8, u8) = (1, 0, 0);
const AUDIO: (u8, u8, u8) = (1, 0, 1);
/// The port's PCI Express capability and in it Link Control and Status.
const EXPRESS: usize = 0x40;
const LINK_CONTROL: usize = EXPRESS + 0x10;
const LINK_DISABLE: u8 = 1 << 4;
const LINK_STATUS: usize = EXPRESS + 0x12;

/// The fabric: each function's 256 configuration bytes, the GPU's power,
/// and how many more reads find its link down or it initializing.
struct Fabric {
    spaces: BTreeMap<(u8, u8, u8), [u8; 256]>,
    link_down_reads: u32,
    retry_reads: u32,
    refuse_writes: bool,
    writes: Vec<Write>,
}

/// A configuration write: the function, its register, width and value.
type Write = ((u8, u8, u8), usize, u32, u32);

static FABRIC: Mutex<Option<Fabric>> = Mutex::new(None);

fn function(identity: u32, class: u32, header: u8) -> [u8; 256] {
    let mut space = [0; 256];
    space[0..4].copy_from_slice(&identity.to_le_bytes());
    space[8..12].copy_from_slice(&class.to_le_bytes());
    space[0x0e] = header;
    space
}

/// A root port leading to `secondary`, its PCI Express capability with a
/// slot that is not hot-plug capable, 8 GT/s and link active reporting.
fn port(device_id: u16, secondary: u8, link_disabled: bool) -> [u8; 256] {
    let mut space = function(u32::from(device_id) << 16 | 0x8086, 0x0604_0000, 1);
    space[0x18..0x1b].copy_from_slice(&[0, secondary, secondary]);
    // Status: Capabilities List.
    space[6] = 0x10;
    space[0x34] = EXPRESS as u8;
    space[EXPRESS..EXPRESS + 4].copy_from_slice(&[0x10, 0, 0x42, 1]);
    space[EXPRESS + 0x0c..EXPRESS + 0x10].copy_from_slice(&(3u32 | 1 << 20).to_le_bytes());
    if link_disabled {
        space[LINK_CONTROL] = LINK_DISABLE;
    } else {
        space[LINK_STATUS + 1] = 1 << 5;
    }
    space
}

fn install() {
    let mut spaces = BTreeMap::new();
    spaces.insert((0, 0, 0), function(0xa706_8086, 0x0600_0000, 0));
    spaces.insert(PORT, port(0x7ab8, 1, true));
    spaces.insert((0, 0x1d, 0), port(0x7ab9, 2, false));
    spaces.insert((0, 0x1e, 0), port(0x7aba, 3, false));
    spaces.insert((0, 0x1f, 0), port(0x7abb, 4, false));
    spaces.insert(GPU, function(0x25a2_10de, 0x0302_00a1, 0x80));
    spaces.insert(AUDIO, function(0x2291_10de, 0x0403_00a1, 0));
    *FABRIC
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Fabric {
        spaces,
        link_down_reads: 3,
        retry_reads: 3,
        refuse_writes: false,
        writes: Vec::new(),
    });
}

fn with<T>(body: impl FnOnce(&mut Fabric) -> T) -> T {
    body(
        FABRIC
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
            .expect("installed fabric"),
    )
}

impl Fabric {
    fn linked(&self) -> bool {
        self.spaces[&PORT][LINK_CONTROL] & LINK_DISABLE == 0
    }

    fn read(&mut self, function: (u8, u8, u8), offset: usize, bytes: usize) -> u32 {
        let below = function.0 == 1;
        if below && !self.linked() {
            return u32::MAX >> (32 - bytes * 8);
        }
        if below && offset == 0 && self.retry_reads != 0 {
            self.retry_reads -= 1;
            // The Vendor ID a function still initializing answers with.
            return 0xffff_0001 & (u32::MAX >> (32 - bytes * 8));
        }
        let Some(space) = self.spaces.get(&function) else {
            return u32::MAX >> (32 - bytes * 8);
        };
        let mut word = [0; 4];
        word[..bytes].copy_from_slice(&space[offset..offset + bytes]);
        let mut value = u32::from_le_bytes(word);
        if function == PORT && (offset..offset + bytes).contains(&(LINK_STATUS + 1)) {
            let active = self.linked() && self.link_down_reads == 0;
            if self.linked() && self.link_down_reads != 0 {
                self.link_down_reads -= 1;
            }
            let bit = 1u32 << (13 + 8 * (LINK_STATUS - offset) as u32);
            value = if active { value | bit } else { value & !bit };
        }
        value
    }

    fn write(&mut self, function: (u8, u8, u8), offset: usize, bytes: usize, value: u32) -> bool {
        if self.refuse_writes {
            return false;
        }
        self.writes.push((function, offset, bytes as u32, value));
        if let Some(space) = self.spaces.get_mut(&function) {
            space[offset..offset + bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
        }
        true
    }
}

/// One function's configuration in the fabric.
struct Config(Address);

impl ConfigSpace for Config {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        Ok(with(|fabric| fabric.read(key(self.0), offset.into(), 1)) as u8)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        Ok(with(|fabric| fabric.read(key(self.0), offset.into(), 2)) as u16)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        Ok(with(|fabric| fabric.read(key(self.0), offset.into(), 4)))
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        with(|fabric| fabric.write(key(self.0), offset.into(), 1, value.into()));
        Ok(())
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        with(|fabric| fabric.write(key(self.0), offset.into(), 2, value.into()));
        Ok(())
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        with(|fabric| fabric.write(key(self.0), offset.into(), 4, value));
        Ok(())
    }
}

fn key(address: Address) -> (u8, u8, u8) {
    (address.bus, address.device, address.function)
}

fn read(address: Address, offset: u16) -> Option<u32> {
    (offset < 256 && address.segment == 0)
        .then(|| with(|fabric| fabric.read(key(address), offset.into(), 4)))
}

#[test]
fn the_scan_finds_every_bridge_and_the_empty_secondary_buses() {
    let _serial = crate::platform::acpi::test_support::TEST_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install();
    // A bridge on bus 2 below 00:1d.0, leading to bus 5 and a function
    // there; a bridge whose secondary bus is not above its own forwards
    // nothing the scan follows.
    with(|fabric| {
        fabric.spaces.insert((2, 0, 0), port(0x1234, 5, false));
        fabric
            .spaces
            .insert((5, 0, 0), function(0x1111_8086, 0x0108_0200, 0));
        fabric.spaces.insert((0, 2, 0), port(0x2345, 0, false));
    });
    let topology = Topology::scan(&[(0, 0)], read);
    let found: Vec<_> = topology.found.iter().map(|&(address, _)| address).collect();
    assert_eq!(
        found,
        [
            at(0, 0, 0),
            at(0, 2, 0),
            at(0, 0x1c, 0),
            at(0, 0x1d, 0),
            at(0, 0x1e, 0),
            at(0, 0x1f, 0),
            at(2, 0, 0),
            at(5, 0, 0),
        ],
        "each bus whole, then below its bridges in order, as Linux scans"
    );
    assert_eq!(topology.found[7].1, [1, 8, 2], "class bytes, base first");
    let empty: Vec<_> = topology.empty_ports().collect();
    assert_eq!(empty, [at(0, 0x1c, 0), at(0, 0x1e, 0), at(0, 0x1f, 0)]);
    assert!(topology.answers_below(at(0, 0x1d, 0)));
    assert!(!topology.answers_below(at(0, 0x1c, 0)));
    assert_eq!(topology.secondary(at(0, 0x1c, 0)), Some(1));
    assert_eq!(topology.secondary(at(0, 2, 0)), None);
}

/// ACPI reports a device's power off by `_PSC`, else by an off `_PR0`
/// resource.
#[test]
fn power_is_off_as_linux_infers_it() {
    assert!(power_off(Some(3), &[]));
    assert!(!power_off(Some(0), &[Some(0)]), "_PSC decides");
    assert!(power_off(None, &[Some(1), Some(0)]));
    assert!(!power_off(None, &[Some(1), None]));
    assert!(!power_off(None, &[]));
}

#[test]
fn only_a_hot_plug_slot_reporting_no_presence_is_empty() {
    let _serial = crate::platform::acpi::test_support::TEST_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install();
    let port = Config(at(0, 0x1d, 0));
    assert_eq!(slot_empty(&port), Ok(false), "no slot");
    let set = |flags: u16, capabilities: u32, status: u16| {
        with(|fabric| {
            let space = fabric.spaces.get_mut(&(0, 0x1d, 0)).unwrap();
            space[EXPRESS + 2..EXPRESS + 4].copy_from_slice(&(0x42 | flags).to_le_bytes());
            space[EXPRESS + 0x14..EXPRESS + 0x18].copy_from_slice(&capabilities.to_le_bytes());
            space[EXPRESS + 0x1a..EXPRESS + 0x1c].copy_from_slice(&status.to_le_bytes());
        })
    };
    set(1 << 8, 0, 0);
    assert_eq!(slot_empty(&port), Ok(false), "a slot that is not hot-plug");
    set(1 << 8, 1 << 6, 1 << 6);
    assert_eq!(slot_empty(&port), Ok(false), "something is present");
    set(1 << 8, 1 << 6, 0);
    assert_eq!(slot_empty(&port), Ok(true));
}

mod acpi;

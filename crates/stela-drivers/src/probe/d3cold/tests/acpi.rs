//! The real ACPICA over a DSDT whose root port's power resource `_ON`
//! writes the port's Link Control through a PCI_Config field, with the
//! simulated fabric serving ACPICA's PCI configuration callbacks.
use super::*;
use crate::bus::pci::bus_reset::{SecondaryBus, wait_for_secondary_bus};
use crate::platform::acpi::{
    Mode, PciId, Session, Status, Value,
    test_support::{TEST_SERIAL, dsdt_fixture},
};
use alloc::string::ToString;
use core::ffi::c_void;

/// AML encoding (ACPI 6.5 section 20), as much as the DSDT below needs.
mod aml {
    use alloc::{vec, vec::Vec};

    /// A package length that counts its own bytes.
    fn length(body: usize) -> Vec<u8> {
        if body + 1 < 0x40 {
            return vec![(body + 1) as u8];
        }
        let total = body + 2;
        assert!(total < 1 << 12);
        vec![0x40 | (total & 0xf) as u8, (total >> 4) as u8]
    }
    fn package(op: &[u8], body: Vec<u8>) -> Vec<u8> {
        let mut out = op.to_vec();
        out.extend(length(body.len()));
        out.extend(body);
        out
    }
    fn segment(name: &str) -> [u8; 4] {
        let mut segment = *b"____";
        segment[..name.len()].copy_from_slice(name.as_bytes());
        segment
    }
    pub fn name(path: &str) -> Vec<u8> {
        let (mut out, path) = match path.strip_prefix('\\') {
            Some(path) => (vec![b'\\'], path),
            None => (Vec::new(), path),
        };
        let segments: Vec<_> = path.split('.').map(segment).collect();
        match segments.len() {
            1 => {}
            2 => out.push(0x2e),
            count => out.extend([0x2f, count as u8]),
        }
        out.extend(segments.concat());
        out
    }
    pub fn int(value: u64) -> Vec<u8> {
        match value {
            0 => vec![0],
            1 => vec![1],
            2..=0xff => vec![0x0a, value as u8],
            0x100..=0xffff => [&[0x0b][..], &(value as u16).to_le_bytes()].concat(),
            _ => [&[0x0c][..], &(value as u32).to_le_bytes()].concat(),
        }
    }
    pub fn string(text: &str) -> Vec<u8> {
        [&[0x0d][..], text.as_bytes(), &[0]].concat()
    }
    pub fn scope(path: &str, body: Vec<Vec<u8>>) -> Vec<u8> {
        package(&[0x10], [name(path), body.concat()].concat())
    }
    pub fn device(path: &str, body: Vec<Vec<u8>>) -> Vec<u8> {
        package(&[0x5b, 0x82], [name(path), body.concat()].concat())
    }
    pub fn power_resource(path: &str, body: Vec<Vec<u8>>) -> Vec<u8> {
        // System level S0, resource order 0.
        package(
            &[0x5b, 0x84],
            [name(path), vec![0, 0, 0], body.concat()].concat(),
        )
    }
    pub fn method(path: &str, arguments: u8, body: Vec<Vec<u8>>) -> Vec<u8> {
        package(
            &[0x14],
            [name(path), vec![arguments], body.concat()].concat(),
        )
    }
    pub fn named(path: &str, value: Vec<u8>) -> Vec<u8> {
        [vec![0x08], name(path), value].concat()
    }
    pub fn references(paths: &[&str]) -> Vec<u8> {
        let elements: Vec<u8> = paths.iter().flat_map(|path| name(path)).collect();
        package(&[0x12], [vec![paths.len() as u8], elements].concat())
    }
    /// `OperationRegion (path, PCI_Config, offset, bytes)`.
    pub fn pci_region(path: &str, offset: u64, bytes: u64) -> Vec<u8> {
        [
            vec![0x5b, 0x80],
            name(path),
            vec![2],
            int(offset),
            int(bytes),
        ]
        .concat()
    }
    /// `Field (region, WordAcc, NoLock, Preserve) { Offset (at), field, bits }`.
    pub fn word_field(region: &str, at: usize, field: &str, bits: u8) -> Vec<u8> {
        let skip = at * 8;
        let body = [
            name(region),
            vec![2, 0, 0x40 | (skip & 0xf) as u8, (skip >> 4) as u8],
            segment(field).to_vec(),
            vec![bits],
        ]
        .concat();
        package(&[0x5b, 0x81], body)
    }
    pub fn store(value: Vec<u8>, target: &str) -> Vec<u8> {
        [vec![0x70], value, name(target)].concat()
    }
    pub fn ret(value: Vec<u8>) -> Vec<u8> {
        [vec![0xa4], value].concat()
    }
    pub fn increment(target: &str) -> Vec<u8> {
        [vec![0x75], name(target)].concat()
    }
    /// `If (LAnd (LEqual (Arg0, a), LEqual (Arg1, b))) { body }`.
    pub fn if_arguments(a: u64, b: u64, body: Vec<u8>) -> Vec<u8> {
        let predicate = [vec![0x90, 0x93, 0x68], int(a), vec![0x93, 0x69], int(b)].concat();
        package(&[0xa0], [predicate, body].concat())
    }
}

/// The DSDT: power resources PG00 (off; its `_ON` clears the port's Link
/// Disable), PG01 (on) and PG02 (off); root ports RP01 at 00:1c.0 on PG00
/// with `_PS0` and `_REG` counters, RP02 at 00:1d.0 on PG01, RP03 at
/// 00:1e.0 on PG02 with `_EJ0`, RP04 at 00:1f.0 whose `_PR0` is not a
/// package; the GPU's companion PEGP below RP01 with `_PSC` 3 until its
/// `_PS0`.
fn dsdt() -> Vec<u8> {
    use aml::*;
    let off_resource = |path: &str, on: Vec<Vec<u8>>| {
        power_resource(
            path,
            vec![
                named("STAT", int(0)),
                method("_STA", 0, vec![ret(name("STAT"))]),
                method("_ON", 0, [on, vec![store(int(1), "STAT")]].concat()),
                method("_OFF", 0, vec![store(int(0), "STAT")]),
            ],
        )
    };
    let child = |path: &str| device(path, vec![named("_ADR", int(0))]);
    let port = |path: &str, address: u64, mut body: Vec<Vec<u8>>, below: Vec<u8>| {
        let mut all = vec![named("_ADR", int(address))];
        all.append(&mut body);
        all.push(below);
        device(path, all)
    };
    scope(
        "\\_SB",
        vec![
            off_resource("PG00", vec![store(int(0), "\\_SB.PCI0.RP01.LCTL")]),
            power_resource(
                "PG01",
                vec![
                    method("_STA", 0, vec![ret(int(1))]),
                    method("_ON", 0, vec![]),
                    method("_OFF", 0, vec![]),
                ],
            ),
            off_resource("PG02", vec![]),
            device(
                "PCI0",
                vec![
                    named("_HID", string("PNP0A08")),
                    port(
                        "RP01",
                        0x001c_0000,
                        vec![
                            pci_region("PXCS", 0, 0x100),
                            word_field("PXCS", LINK_CONTROL, "LCTL", 16),
                            named("_PR0", references(&["\\_SB.PG00"])),
                            named("PS0C", int(0)),
                            method("_PS0", 0, vec![increment("PS0C")]),
                            named("REGC", int(0)),
                            method("_REG", 2, vec![if_arguments(2, 1, increment("REGC"))]),
                        ],
                        device(
                            "PEGP",
                            vec![
                                named("_ADR", int(0)),
                                named("PSCV", int(3)),
                                method("_PSC", 0, vec![ret(name("PSCV"))]),
                                method("_PS0", 0, vec![store(int(0), "PSCV")]),
                            ],
                        ),
                    ),
                    port(
                        "RP02",
                        0x001d_0000,
                        vec![named("_PR0", references(&["\\_SB.PG01"]))],
                        child("PXSX"),
                    ),
                    port(
                        "RP03",
                        0x001e_0000,
                        vec![
                            named("_PR0", references(&["\\_SB.PG02"])),
                            method("_EJ0", 1, vec![]),
                        ],
                        child("PXSX"),
                    ),
                    port(
                        "RP04",
                        0x001f_0000,
                        vec![named("_PR0", int(5)), method("_PS0", 0, vec![])],
                        child("PXSX"),
                    ),
                ],
            ),
        ],
    )
}

unsafe extern "C" fn read_pci(
    _: *mut c_void,
    id: *mut PciId,
    register: u32,
    value: *mut u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes a live identity and a writable output.
    let id = unsafe { &*id };
    let function = (id.bus as u8, id.device as u8, id.function as u8);
    let read = with(|fabric| fabric.read(function, register as usize, width as usize / 8));
    // SAFETY: as above.
    unsafe { value.write(u64::from(read)) };
    0
}

unsafe extern "C" fn write_pci(
    _: *mut c_void,
    id: *mut PciId,
    register: u32,
    value: u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes a live identity.
    let id = unsafe { &*id };
    let function = (id.bus as u8, id.device as u8, id.function as u8);
    match with(|fabric| {
        fabric.write(
            function,
            register as usize,
            width as usize / 8,
            value as u32,
        )
    }) {
        true => 0,
        // AE_SUPPORT, as Stela's provider refuses a write.
        false => 0x000f,
    }
}

fn session() -> Session {
    let mut services = dsdt_fixture(&dsdt());
    services.read_pci = read_pci;
    services.write_pci = write_pci;
    // SAFETY: the serialized fixture hands its whole provider to the one
    // ACPICA session, which outlives every handle below.
    unsafe { Session::start(services, Mode::InterpreterOnly) }.unwrap()
}

fn counter(session: &Session, path: &str) -> u64 {
    match session.handle(path).unwrap().evaluate(None, &[]).unwrap() {
        Some(Value::Integer(value)) => value,
        other => panic!("{path} is {other:?}"),
    }
}

/// The whole power-on: only RP01 is a port to power on; its `_ON` writes
/// the port's configuration through AML, `_PS0` and `_REG` follow, the
/// wait sees the link come up and the GPU answer after its retries, and a
/// scan below the port then finds the GPU and its audio function. The
/// GPU's companion reports D3 until its own `_PS0`.
#[test]
fn a_powered_off_port_comes_up_through_its_power_resource() {
    let _serial = TEST_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install();
    let session = session();
    let mut topology = Topology::scan(&roots(&session), read);
    assert_eq!(roots(&session), [(0, 0)]);
    assert_eq!(
        topology.empty_ports().collect::<Vec<_>>(),
        [
            at(0, 0x1c, 0),
            at(0, 0x1d, 0),
            at(0, 0x1e, 0),
            at(0, 0x1f, 0)
        ]
    );
    // RP02's resource is on, RP03 has _EJ0, RP04's _PR0 is no package.
    assert_eq!(powered_off(&session, &topology), [at(0, 0x1c, 0)]);
    assert_eq!(power_on(&session, &topology, at(0, 0x1d, 0)), Ok(None));
    assert_eq!(power_on(&session, &topology, at(0, 0x1e, 0)), Ok(None));
    // ACPICA wraps the integer in a package and refuses its element, or
    // refuses the object: either way the refusal names RP04's _PR0.
    let refused = power_on(&session, &topology, at(0, 0x1f, 0)).unwrap_err();
    assert!(refused.to_string().contains("RP04._PR0"), "{refused}");
    let registered = counter(&session, "\\_SB.PCI0.RP01.REGC");
    let port = at(0, 0x1c, 0);
    assert_eq!(
        power_on(&session, &topology, port),
        Ok(Some(PoweredOn {
            resources: 1,
            ps0: true,
            reg: true,
        }))
    );
    assert_eq!(counter(&session, "\\_SB.PCI0.RP01.PS0C"), 1);
    // ACPICA runs the region's own connect `_REG` when the `_ON` first
    // reaches its PCI_Config field; the power-on's runs after it.
    assert_eq!(counter(&session, "\\_SB.PCI0.RP01.REGC"), registered + 2);
    assert_eq!(
        with(|fabric| fabric.writes.clone()),
        [(PORT, LINK_CONTROL, 2, 0)],
        "only the AML's own write"
    );
    // Now on: a second power-on changes nothing.
    assert_eq!(power_on(&session, &topology, port), Ok(None));
    let mut waited = 0;
    let wait = wait_for_secondary_bus(&Config(port), &Config(at(1, 0, 0)), |microseconds| {
        waited += microseconds;
        Ok(())
    });
    assert_eq!(wait, Ok(SecondaryBus::Ready));
    assert_eq!(waited, 20_000 + 3 * 1_000 + 100_000 + (1 + 2 + 4) * 1_000);
    assert!(!slot_empty(&Config(port)).unwrap());
    assert_eq!(topology.scan_below(port, read), [at(1, 0, 0), at(1, 0, 1)]);
    assert!(topology.answers_below(port));
    assert_eq!(topology.empty_ports().count(), 3);
    assert_eq!(
        power_on(&session, &topology, at(1, 0, 0)),
        Ok(Some(PoweredOn {
            resources: 0,
            ps0: true,
            reg: false,
        }))
    );
    assert_eq!(
        power_on(&session, &topology, at(1, 0, 1)),
        Ok(None),
        "no companion"
    );
    drop(session);
}

/// When the provider refuses the AML's configuration write, `_ON` aborts:
/// the failure names the method, the resource stays off and nothing
/// answers below the port.
#[test]
fn a_refused_configuration_write_fails_the_power_on() {
    let _serial = TEST_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install();
    with(|fabric| fabric.refuse_writes = true);
    let session = session();
    let topology = Topology::scan(&roots(&session), read);
    let port = at(0, 0x1c, 0);
    match power_on(&session, &topology, port) {
        Err(PowerOnError::Method { path, status }) => {
            assert!(path.ends_with("PG00._ON"), "{path}");
            assert_ne!(status, 0);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        counter(&session, "\\_SB.PCI0.RP01.PS0C"),
        0,
        "no _PS0 after it"
    );
    assert_eq!(counter(&session, "\\_SB.PG00.STAT"), 0);
    assert_eq!(powered_off(&session, &topology), [port]);
    let wait = wait_for_secondary_bus(&Config(port), &Config(at(1, 0, 0)), |_| Ok(()));
    assert_eq!(wait, Ok(SecondaryBus::NoLink));
    drop(session);
}

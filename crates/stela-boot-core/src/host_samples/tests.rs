use super::*;
use alloc::{vec, vec::Vec};
use stela_engine::machine::engine::step_timing::block_regions;

const ARENA: u64 = 0xffff_9000_0000_0000;
const NAMES: [&str; EXIT_SLOTS] = ["e"; EXIT_SLOTS];

/// An arena with one block at its start (inline, cold, a link slot and its
/// exit, a dynamic exit), a stamped tail, a probe and a PAC thunk, as the
/// engine describes them.
fn arena() -> Tags {
    let tags = Tags::new(ARENA, 4096).unwrap();
    use CodeRegion::{Cold, Exit, Link, Pointer, Probe, Stamped};
    let mut spans = [
        (160, 320, Cold),
        (400, 448, Link),
        (448, 472, Exit),
        (480, 496, Exit),
    ];
    let regions = block_regions(512, &mut spans);
    assert!(tags.describe(ARENA, 512, &regions));
    assert!(tags.describe(ARENA + 512, 96, &[(0, Stamped)]));
    assert!(tags.describe(ARENA + 1024, 256, &[(0, Probe)]));
    assert!(tags.describe(ARENA + 2048, 128, &[(0, Pointer)]));
    // Code outside the tags is not described.
    assert!(!tags.describe(ARENA + 4000, 200, &[(0, Probe)]));
    assert!(!tags.describe(ARENA - 16, 16, &[(0, Probe)]));
    tags
}

#[test]
fn arena_addresses_classify_by_their_region() {
    let tags = arena();
    let region = |address: u64| tags.contains(address).then(|| tags.region(address));
    let class = |rip: u64| {
        NativeSample {
            rip,
            rsp: 0,
            top: 0,
            filling: false,
            helper: false,
            region,
            word: |_| 0,
            code: |_, _| None,
            service_calls: &[],
        }
        .class()
    };
    use CodeRegion::*;
    for (offset, expected) in [
        (0, Inline),
        (159, Inline),
        (160, Cold),
        (319, Cold),
        (320, Inline),
        (400, Link),
        (447, Link),
        (448, Exit),
        (463, Exit),
        // A granule takes its middle byte's region: 464..480 is inline.
        (470, Inline),
        (480, Exit),
        (500, Inline),
        (512, Stamped),
        (607, Stamped),
        (608, Untagged),
        (1024, Probe),
        (1279, Probe),
        (2048, Pointer),
        (4095, Untagged),
    ] {
        assert_eq!(class(ARENA + offset), expected as usize, "offset {offset}");
    }
    // Retagging replaces a granule's region, its neighbour keeps its own.
    tags.tag(ARENA + 16, ARENA + 32, Lookup);
    assert_eq!(class(ARENA + 16), Lookup as usize);
    assert_eq!(class(ARENA), Inline as usize);
    assert_eq!(class(ARENA + 32), Inline as usize);
}

#[test]
fn routines_native_code_calls_classify_by_their_call() {
    let tags = arena();
    // A PAC thunk's call of the service at ARENA + 2048 + 32 and a block's
    // call of another routine at ARENA + 200.
    let service: &[u8] = &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xd0];
    let other: &[u8] = &[0xff, 0x57, 0x08];
    let mut code = vec![0u8; 4096];
    let thunk_return = 2048 + 32;
    code[thunk_return - service.len()..thunk_return].copy_from_slice(service);
    let block_return = 200;
    code[block_return - other.len()..block_return].copy_from_slice(other);
    // A stack of 64 words at STACK: host words, then the return address.
    const STACK: u64 = 0x7000_0000;
    let mut stack: Vec<u64> = (0..64).map(|word| 0x1000 + word).collect();
    let region = |address: u64| tags.contains(address).then(|| tags.region(address));
    let sample = |stack: &[u64], rip: u64, filling: bool, helper: bool| {
        let stack = stack.to_vec();
        let code = &code;
        NativeSample {
            rip,
            rsp: STACK + 8,
            top: STACK + 8 * stack.len() as u64,
            filling,
            helper,
            region,
            word: move |address: u64| stack[((address - STACK) / 8) as usize],
            code: move |address: u64, bytes: usize| {
                let at = (address - ARENA) as usize;
                code.get(at..at + bytes)
            },
            service_calls: &[&[0xff, 0x57, 0x40], service],
        }
        .class()
    };
    const HOST_RIP: u64 = 0xffff_8000_0010_0000;
    // No return address on the stack.
    assert_eq!(sample(&stack, HOST_RIP, false, false), NATIVE_OTHER);
    stack[20] = ARENA + thunk_return as u64;
    assert_eq!(sample(&stack, HOST_RIP, false, false), PAC_CALL);
    stack[10] = ARENA + block_return as u64;
    assert_eq!(sample(&stack, HOST_RIP, false, false), CALL);
    // A word below the interrupted stack pointer is not looked at.
    stack[10] = 0;
    stack[0] = ARENA + block_return as u64;
    assert_eq!(sample(&stack, HOST_RIP, false, false), PAC_CALL);
    // Fills and the helper come first; code in the arena is its region.
    assert_eq!(sample(&stack, HOST_RIP, true, false), FILL);
    assert_eq!(sample(&stack, HOST_RIP, false, true), HELPER);
    assert_eq!(
        sample(&stack, ARENA + 160, false, true),
        CodeRegion::Cold as usize
    );
    assert_eq!(sample(&stack, ARENA + 160, true, false), FILL);
}

#[test]
fn samples_outside_native_code_go_to_their_phase() {
    assert_eq!(charged(PAC_CALL, Some(Phase::Exit), Some(3)), PAC_CALL);
    assert_eq!(charged(OUTSIDE, Some(Phase::Native), None), GLUE);
    assert_eq!(charged(OUTSIDE, Some(Phase::Schedule), None), SCHEDULE);
    assert_eq!(charged(OUTSIDE, Some(Phase::Devices), None), DEVICES);
    assert_eq!(charged(OUTSIDE, Some(Phase::Fetch), None), FETCH);
    assert_eq!(charged(OUTSIDE, Some(Phase::Exit), Some(6)), EXITS + 6);
    assert_eq!(charged(OUTSIDE, Some(Phase::Exit), None), EXIT_OTHER);
    assert_eq!(
        charged(OUTSIDE, Some(Phase::Exit), Some(EXIT_SLOTS)),
        EXIT_OTHER
    );
    assert_eq!(charged(OUTSIDE, None, None), HOST);
    assert!(native(NATIVE_OTHER) && !native(GLUE) && !native(HOST));
    // Every class has its own name.
    let mut names: Vec<String> = (0..CLASSES)
        .map(|class| class_name(class, &NAMES))
        .collect();
    let exits: Vec<String> = (0..EXIT_SLOTS).map(|slot| format!("x:{slot}")).collect();
    for (slot, name) in exits.iter().enumerate() {
        names[EXITS + slot] = name.clone();
    }
    names.sort();
    names.dedup();
    assert_eq!(names.len(), CLASSES);
}

#[test]
fn lines_show_shares_of_instructions_then_cycles() {
    let mut counts: Counts = [[0; SAMPLED]; CLASSES];
    // Cycles, instructions.
    counts[CodeRegion::Inline as usize] = [600, 750];
    counts[PAC_CALL] = [300, 200];
    counts[EXITS + 2] = [100, 49];
    counts[FETCH] = [0, 1];
    let line = shares(&counts, &NAMES);
    assert_eq!(
        line,
        " ins=0M cyc=0M nat_ins=0M nat_cyc=0M native=95.0/90.0 inline=75.0/60.0 \
         pac-call=20.0/30.0 fetch=0.1/0.0 x:e=4.9/10.0"
    );
    assert_eq!(
        shares(&[[0; SAMPLED]; CLASSES], &NAMES),
        " ins=0M cyc=0M nat_ins=0M nat_cyc=0M native=0.0/0.0"
    );
    let mut counts: Counts = [[0; SAMPLED]; CLASSES];
    counts[CodeRegion::Inline as usize] = [3_000_000, 5_000_000];
    counts[HOST] = [1_000_000, 1_000_000];
    assert!(shares(&counts, &NAMES).starts_with(" ins=6M cyc=4M nat_ins=5M nat_cyc=3M"));
}

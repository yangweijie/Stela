//! Which host instructions real blocks execute, run by hand: each block of
//! the sample `DENSITY_IN` names (lines of hex PC, weight and hex bytes) is
//! compiled as a system-mode block and run once in a child process under
//! the x86 trap flag, which records every host instruction it executes.
//! Guest registers point into a scratch arena whose words point back into
//! it, so loads and pointer chasing stay mapped; the anchors point at zeroed
//! areas with an unbounded chain budget, and the pointer-authentication
//! routine returns its input. `DENSITY_OUT` gets, per block, a `B` line
//! (PC, weight, exit, host instructions executed inline, out of line and
//! outside the block) and per guest instruction an `S` line (its word, how
//! often its code was entered, host instructions inline, and those out of
//! line that it branched to). Inline is the block's code up to its last
//! instruction's first unconditional jump or return; the rest (side-exit
//! stubs, cold paths, loop copies) is out of line.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    block::{BlockProfile, CompilationPlan, Features},
    x86_64::{MemoryChecks, NativeSystem, RangeCheck, pointer},
};
use alloc::{format, string::String, vec, vec::Vec};
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

const SIGTRAP: i32 = 5;
const SA_SIGINFO: i32 = 4;
const TRAP_FLAG: u64 = 0x100;
/// `uc_mcontext.gregs` in `ucontext_t`, and REG_RIP / REG_EFL in it.
const GREGS: usize = 40;
const RIP: usize = 16;
const EFLAGS: usize = 17;
const STEPS: usize = 1 << 20;
const OUTSIDE: u32 = u32::MAX;

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

unsafe extern "C" {
    fn sigaction(signal: i32, action: *const SigAction, old: *mut SigAction) -> i32;
    fn fork() -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, bytes: *mut c_void, count: usize) -> isize;
    fn write(fd: i32, bytes: *const c_void, count: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn alarm(seconds: u32) -> u32;
    fn _exit(status: i32) -> !;
    fn mmap(
        address: *mut c_void,
        bytes: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
}

static BASE: AtomicUsize = AtomicUsize::new(0);
static LENGTH: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static mut TRACE: [u32; STEPS] = [0; STEPS];

unsafe extern "C" fn step(_: i32, _: *mut c_void, context: *mut c_void) {
    // SAFETY: Linux passes a ucontext_t; gregs holds the interrupted RIP and
    // EFLAGS. The child is single threaded.
    unsafe {
        let gregs = context.cast::<u8>().add(GREGS).cast::<u64>();
        let rip = *gregs.add(RIP) as usize;
        let base = BASE.load(Ordering::Relaxed);
        let count = COUNT.load(Ordering::Relaxed);
        if count >= STEPS {
            *gregs.add(EFLAGS) &= !TRAP_FLAG;
            return;
        }
        let offset = if (base..base + LENGTH.load(Ordering::Relaxed)).contains(&rip) {
            (rip - base) as u32
        } else {
            OUTSIDE
        };
        core::ptr::addr_of_mut!(TRACE)
            .cast::<u32>()
            .add(count)
            .write(offset);
        COUNT.store(count + 1, Ordering::Relaxed);
    }
}

#[repr(C)]
struct Pair(u64, u64);

/// The pointer-authentication routine: success, with its input.
extern "sysv64" fn authenticated(_: *mut u8, _: u32, value: u64, _: u64) -> Pair {
    Pair(1, value)
}

fn options() -> Options {
    let checks = MemoryChecks::system(true, false, true, false)
        .with_range(RangeCheck::four_level(4).one_sided(true));
    let system = NativeSystem {
        exclusive: true,
        pointer: Some(pointer::inline::Cells {
            tags: 0x40,
            strips: 0x80,
            routine: 0x1c0,
        }),
        self_loops: true,
        ..NativeSystem::NONE
    };
    Options::new(
        BlockProfile::new(Features::SYSTEM_MODE),
        TargetCpu::detect(),
    )
    .with_memory_checks(checks)
    .with_native_system(system)
}

fn map(bytes: usize) -> *mut u8 {
    // SAFETY: private anonymous read-write memory.
    let page = unsafe { mmap(core::ptr::null_mut(), bytes, 3, 0x22, -1, 0) };
    assert_ne!(page as usize, usize::MAX);
    page.cast()
}

/// Run `entry` (the pinned entry wrapper and the block) in a child under
/// the trap flag; the parent gets the trace and the exit.
fn traced(entry: &[u8], body_offset: usize) -> Option<(u64, u64, Vec<u32>)> {
    let mut fds = [0i32; 2];
    // SAFETY: plain POSIX calls; the child only runs the block and writes.
    unsafe {
        assert_eq!(pipe(fds.as_mut_ptr()), 0);
        let pid = fork();
        if pid == 0 {
            close(fds[0]);
            alarm(5);
            let code = map(entry.len().next_multiple_of(4096) + 4096);
            core::ptr::copy_nonoverlapping(entry.as_ptr(), code, entry.len());
            code.add(entry.len()).write(0xc3);
            mprotect(code.cast(), entry.len().next_multiple_of(4096) + 4096, 5);
            BASE.store(code as usize + body_offset, Ordering::Relaxed);
            LENGTH.store(entry.len() - body_offset, Ordering::Relaxed);
            let action = SigAction {
                handler: step as unsafe extern "C" fn(i32, *mut c_void, *mut c_void) as usize,
                mask: [0; 16],
                flags: SA_SIGINFO,
                restorer: 0,
            };
            sigaction(SIGTRAP, &action, core::ptr::null_mut());
            let state = alloc::boxed::Box::leak(alloc::boxed::Box::new(GuestState::default()));
            prepare(state);
            let run: unsafe extern "sysv64" fn(*mut GuestState) -> u64 = core::mem::transmute(code);
            core::arch::asm!("pushfq", "or qword ptr [rsp], 0x100", "popfq");
            let exit = run(state);
            core::arch::asm!("pushfq", "and qword ptr [rsp], -257", "popfq");
            let count = COUNT.load(Ordering::Relaxed);
            let trace =
                core::slice::from_raw_parts(core::ptr::addr_of!(TRACE).cast::<u32>(), count);
            write(fds[1], (&raw const exit).cast(), 8);
            // ChainControl's retired count (its second word) and the loop's.
            let control = *(core::ptr::from_mut(state).cast::<u8>())
                .add(core::mem::offset_of!(GuestState, anchors))
                .cast::<*const u64>();
            let retired = *control.add(1) + state.loop_retired;
            write(fds[1], (&raw const retired).cast(), 8);
            write(fds[1], (&raw const count).cast(), 8);
            let mut sent = 0;
            while sent < count * 4 {
                let n = write(
                    fds[1],
                    trace.as_ptr().cast::<u8>().add(sent).cast(),
                    count * 4 - sent,
                );
                if n <= 0 {
                    break;
                }
                sent += n as usize;
            }
            _exit(0);
        }
        close(fds[1]);
        let mut header = [0u64; 2];
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = read(fds[0], buffer.as_mut_ptr().cast(), buffer.len());
            if n <= 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..n as usize]);
        }
        close(fds[0]);
        let mut status = 0;
        waitpid(pid, &mut status, 0);
        if status != 0 || bytes.len() < 24 {
            return None;
        }
        header[0] = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        header[1] = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let trace = bytes[24..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_le_bytes(*chunk))
            .collect();
        Some((header[0], header[1], trace))
    }
}

/// Registers and memory for a run: an 8 MiB arena whose words point into
/// its middle, registers spread over it, IXC set (the usual running
/// state), zeroed anchor areas with an unbounded chain budget.
fn prepare(state: &mut GuestState) {
    const ARENA: usize = 8 << 20;
    let arena = map(ARENA);
    let middle = arena as u64 + (ARENA as u64) / 2;
    // SAFETY: the arena is mapped read-write.
    unsafe {
        let words = arena.cast::<u64>();
        for index in 0..ARENA / 8 {
            *words.add(index) = middle + ((index as u64 * 8) & 0xffff);
        }
    }
    for (index, register) in state.x.iter_mut().enumerate() {
        *register = middle + 0x100 * index as u64;
    }
    state.sp = middle + 0x10_0000;
    state.fpsr = 0x10;
    let anchors = map(8 << 16);
    let fault = map(4096);
    state.unreachable = fault as u64;
    state.lower_limit = crate::Limit(u64::MAX);
    let raw = (state as *mut GuestState).cast::<u8>();
    let anchor_offset = core::mem::offset_of!(GuestState, anchors);
    // SAFETY: the anchors are eight words in the state; each area is mapped.
    unsafe {
        for index in 0..8 {
            let area = anchors.add(index << 16);
            raw.add(anchor_offset + 8 * index)
                .cast::<u64>()
                .write(area as u64);
        }
        // ChainControl's budget, and the pointer routine.
        anchors.cast::<u64>().write(u64::MAX / 2);
        anchors.add(3 << 16).add(0x1c0).cast::<u64>().write(
            (authenticated as extern "sysv64" fn(*mut u8, u32, u64, u64) -> Pair) as usize as u64,
        );
    }
}

#[test]
#[ignore = "manual: opt-in"]
fn executed_paths_of_real_blocks() {
    use std::io::Write;
    let input = std::env::var("DENSITY_IN").expect("DENSITY_IN names the sample");
    let output = std::env::var("DENSITY_OUT").expect("DENSITY_OUT names the output");
    let mut out = std::fs::File::create(output).expect("the output");
    let options = options();
    for line in std::fs::read_to_string(input).expect("the sample").lines() {
        let mut fields = line.split(' ');
        let (Some(pc), Some(weight), Some(hex)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let pc = u64::from_str_radix(pc, 16).unwrap();
        let source: Vec<u8> = (0..hex.len() / 2)
            .map(|at| u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).unwrap())
            .collect();
        let Ok(plan) = CompilationPlan::new(&source, GuestAddress(pc), &options) else {
            continue;
        };
        let Ok(compiled) = plan.compile() else {
            continue;
        };
        let body = &compiled.native.x86_64_code;
        let entry = crate::x86_64::pinned::entered(body);
        let body_offset = entry.len() - body.len();
        let map = &compiled.native.source_map;
        if map.is_empty() {
            continue;
        }
        // Inline: to the last instruction's first unconditional jump or ret.
        let last = map[map.len() - 1].1;
        let inline_end = inline_end(body, last);
        let Some((exit, looped, trace)) = traced(&entry, body_offset) else {
            writeln!(out, "X {pc:x} {weight}").unwrap();
            continue;
        };
        let span_of = |offset: u32| {
            map.iter()
                .rposition(|&(_, start)| start as u32 <= offset)
                .unwrap_or(0)
        };
        let mut entered = vec![0u32; map.len()];
        let mut inline = vec![0u32; map.len()];
        let mut cold = vec![0u32; map.len()];
        let (mut inside, mut outside, mut out_of_line) = (0u32, 0u32, 0u32);
        let mut current = usize::MAX;
        let first = trace
            .iter()
            .position(|&o| o != OUTSIDE)
            .unwrap_or(trace.len());
        let end = trace
            .iter()
            .rposition(|&o| o != OUTSIDE)
            .map_or(first, |at| at + 1);
        for &offset in &trace[first..end] {
            if offset == OUTSIDE {
                outside += 1;
                continue;
            }
            if (offset as usize) < inline_end {
                inside += 1;
                let span = span_of(offset);
                if span != current {
                    entered[span] += 1;
                    current = span;
                }
                inline[span] += 1;
            } else {
                out_of_line += 1;
                if current < map.len() {
                    cold[current] += 1;
                }
            }
        }
        writeln!(
            out,
            "B {pc:x} {weight} {exit:x} {inside} {out_of_line} {outside} {looped}"
        )
        .unwrap();
        for (index, &(guest, _)) in map.iter().enumerate() {
            let at = (guest.0 - pc) as usize;
            let word = u32::from_le_bytes(source[at..at + 4].try_into().unwrap());
            writeln!(
                out,
                "S {word:08x} {} {} {}",
                entered[index], inline[index], cold[index]
            )
            .unwrap();
        }
    }
}

/// The end of a block's inline code: past the first unconditional jump or
/// return at or after `last` (the last instruction's start); the whole code
/// when there is none.
fn inline_end(body: &[u8], last: usize) -> usize {
    // Decoded by objdump: exact for every form the emitter uses.
    let path = std::env::temp_dir().join(format!("stela-inline-{}.bin", std::process::id()));
    std::fs::write(&path, &body[last..]).unwrap();
    let listing = std::process::Command::new("objdump")
        .args([
            "-D",
            "-b",
            "binary",
            "-m",
            "i386:x86-64",
            "--no-show-raw-insn",
        ])
        .arg(&path)
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    let mut lines = listing
        .lines()
        .filter_map(|line| {
            let (offset, rest) = line.trim_start().split_once(":\t")?;
            Some((
                usize::from_str_radix(offset, 16).ok()?,
                String::from(rest.trim()),
            ))
        })
        .peekable();
    while let Some((_, text)) = lines.next() {
        if text.starts_with("jmp") || text.starts_with("ret") {
            return last + lines.peek().map_or(body.len() - last, |(next, _)| *next);
        }
    }
    body.len()
}

/// What the value allocator would save system-mode blocks, run by hand:
/// each block of `DENSITY_IN` compiled as a system-mode block (pinned set,
/// fault table, no regions) into `DENSITY_OUT`, and as a process block
/// (regions and the value allocator over all twelve hosts, no pinned set
/// or fault table) into `DENSITY_OUT.process`, in `density_dump`'s format
/// (`pc weight source-bytes hex-code pc:offset,...`). The process code
/// bounds what an unconstrained allocator (variant C, before recovery
/// rows) can reach on the same instructions.
#[test]
#[ignore = "manual: opt-in"]
fn allocator_bound_census() {
    use std::io::Write;
    let input = std::env::var("DENSITY_IN").expect("DENSITY_IN names the sample");
    let output = std::env::var("DENSITY_OUT").expect("DENSITY_OUT names the output");
    let process = Options::new(
        BlockProfile::new(Features::POINTER_AUTHENTICATION),
        TargetCpu::detect(),
    );
    for (options, path) in [(options(), output.clone()), (process, output + ".process")] {
        let mut out = std::fs::File::create(path).expect("the output");
        for line in std::fs::read_to_string(&input).expect("the sample").lines() {
            let mut fields = line.split(' ');
            let (Some(pc), Some(weight), Some(hex)) = (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let pc = u64::from_str_radix(pc, 16).unwrap();
            let source: Vec<u8> = (0..hex.len() / 2)
                .map(|at| u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).unwrap())
                .collect();
            let compiled = CompilationPlan::new(&source, GuestAddress(pc), &options)
                .ok()
                .and_then(|plan| plan.compile().ok());
            let Some(compiled) = compiled else {
                writeln!(out, "{pc:x} {weight} refused").unwrap();
                continue;
            };
            let code: String = compiled
                .native
                .x86_64_code
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let map: Vec<String> = compiled
                .native
                .source_map
                .iter()
                .map(|(pc, offset)| format!("{:x}:{offset}", pc.0))
                .collect();
            writeln!(
                out,
                "{pc:x} {weight} {} {code} {}",
                compiled.source_bytes,
                map.join(",")
            )
            .unwrap();
        }
    }
}

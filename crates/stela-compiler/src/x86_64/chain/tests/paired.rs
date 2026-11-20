//! Paired frames run natively: a call's frame and its return's compare,
//! with the frame taken, left or refused, and every exit back at the entry
//! however many frames the run left.
use super::super::*;
use crate::GuestState;
use crate::x86_64::asm::{Asm, Code, Patch};
use alloc::{boxed::Box, vec::Vec};
use core::ffi::c_void;
unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        bytes: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, bytes: usize) -> i32;
}

const PAGE: usize = 4096;
/// The guest return address of the calls.
const RETURN: u64 = 0xffff_fe00_0012_3404;
/// Another one, which no frame holds.
const OTHER: u64 = 0xffff_fe00_0045_6704;
/// The RET block's instructions.
const RAN: u32 = 5;
/// What a continuation returns in RAX and EDX.
const CONTINUED: (u64, u64) = (0xc0de, 77);
/// The word of a return's exit, as its dynamic exit returns it.
const RETURNED: u64 = 99;
/// The word of an exit before any return.
const EXITED: u64 = 55;
/// The calling block's word, which a matched return names again without
/// its BTYPE.
const CALLER: u64 = 0x3_0000_0042;
/// The contexts the runs start in.
const CONTEXTS: [u64; 2] = [5 << LOOKUP_SALT_BITS, 9 << LOOKUP_SALT_BITS];
/// The poison a failed authentication leaves in a pointer's top bits
/// (Arm `AuthIA`'s error code, without FEAT_FPAC).
const POISON: u64 = 1 << 53;

struct Pages(*mut u8, usize);
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: our mapping, nothing runs it any more.
        assert_eq!(unsafe { munmap(self.0.cast(), self.1) }, 0);
    }
}
fn pages(code: &[u8]) -> Pages {
    let bytes = code.len().next_multiple_of(PAGE);
    // SAFETY: private anonymous memory, unmapped on drop, written before it runs.
    unsafe {
        let base = mmap(core::ptr::null_mut(), bytes, 7, 0x22, -1, 0);
        assert_ne!(base as usize, usize::MAX);
        core::ptr::copy_nonoverlapping(code.as_ptr(), base.cast(), code.len());
        Pages(base.cast(), bytes)
    }
}

/// The exit of a return that took no frame: RAX as it is, [`RETURNED`].
fn return_exit(asm: &mut Asm) {
    asm.mov_imm32(Rdx, RETURNED as u32);
    exit_return(asm);
}

/// A continuation: [`CONTINUED`] out.
fn continued(asm: &mut Asm) {
    asm.mov_imm32(Rax, CONTINUED.0 as u32);
    asm.mov_imm32(Rdx, CONTINUED.1 as u32);
    exit_return(asm);
}

/// The return to the target in RSI: the paired check, then the exit.
fn returning(asm: &mut Asm) {
    asm.mov(Qword, Rax, Gpr::Rsi);
    paired_return(asm, RAN).unwrap();
    return_exit(asm);
}

/// What runs between the call and the return.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Callee {
    /// Nothing: a RET to the target in RSI.
    Return,
    /// The retire epoch moved: a block retired meanwhile.
    Retired,
    /// An interruption is pending.
    Interrupted,
    /// An exit before any return.
    Exit,
    /// A native SVC or exception entry: the lower half's context changes
    /// (another EL's), and the upper half's.
    Entered,
    /// That entry, then the ERET back: the contexts are the call's again.
    EnteredAndReturned,
    /// A native ERET to another process: the lower half's context alone
    /// changes.
    Switched,
}

/// Change the context of `half` by `by`.
fn move_context(asm: &mut Asm, half: i32, by: i8) {
    asm.place(Rcx, CONTROL);
    asm.alu_imm8(Alu::Add, Qword, Mem::base(Rcx, CONTEXTS_AT + 8 * half), by);
}
const CONTEXTS_AT: i32 = core::mem::offset_of!(ChainControl, contexts) as i32;

/// Code that calls [`RETURN`] with a paired frame, the call's exit linked
/// straight into a callee that runs `callee`, then returns to the target in
/// RSI, and whose continuation returns [`CONTINUED`].
fn call_and_return(callee: Callee) -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let continuation = paired_call(&mut asm, GuestAddress(RETURN));
    // The call's exit, linked: into the callee.
    let to_callee = asm.jmp();
    asm.bind(continuation);
    continued(&mut asm);
    asm.bind(to_callee);
    match callee {
        Callee::Return => {}
        Callee::Retired => {
            asm.place(Rcx, CONTROL);
            asm.mov_load(Qword, R8, Mem::base(Rcx, RETIRE_EPOCH));
            asm.alu_imm8(Alu::Add, Qword, Mem::base(R8, 0), 1);
        }
        Callee::Interrupted => {
            asm.place(Rcx, CONTROL);
            asm.alu_imm8(Alu::Add, Qword, Mem::base(Rcx, INTERRUPT_EPOCH), 1);
        }
        Callee::Exit => {
            asm.mov_imm32(Rdx, EXITED as u32);
            exit_return(&mut asm);
        }
        Callee::Entered => {
            move_context(&mut asm, 0, 1);
            move_context(&mut asm, 1, 1);
        }
        Callee::EnteredAndReturned => {
            move_context(&mut asm, 0, 1);
            move_context(&mut asm, 1, 1);
            move_context(&mut asm, 0, -1);
            move_context(&mut asm, 1, -1);
        }
        Callee::Switched => move_context(&mut asm, 0, 1),
    }
    returning(&mut asm);
    code.into_bytes()
}

struct Run {
    control: Box<ChainControl>,
    epoch: Box<u64>,
}

impl Run {
    fn new(bound: u32) -> Self {
        let mut epoch = Box::new(7);
        let control = Box::new(ChainControl {
            budget: 100,
            block: CALLER,
            contexts: CONTEXTS,
            frame_room: bound * FRAME_BYTES as u32,
            retire_epoch: &raw mut *epoch as u64,
            ..ChainControl::default()
        });
        Self { control, epoch }
    }

    /// Enter `code` at `at` with RSI = `target`: RAX and RDX of its exit.
    /// The host stack pointer is the same after it as before.
    fn enter(&mut self, code: &Pages, at: usize, target: u64) -> (u64, u64) {
        let mut state = Box::new(GuestState::default());
        state.anchors[Anchor::Control] = &raw mut *self.control as u64;
        let entry = (code.0 as usize + at) as *const u8;
        let before = stack_pointer();
        // SAFETY: the code has the block ABI and touches only the state,
        // the control, the epoch and the stack below the entry's return
        // address, which outlive the call.
        let result = unsafe { crate::x86_64::native::enter(entry, &mut *state, target, 0) };
        assert_eq!(stack_pointer(), before);
        (result as u64, (result >> 64) as u64)
    }

    fn pairs(&self) -> [u64; PAIR_COUNTS] {
        self.control.pairs
    }
}

#[inline(always)]
fn stack_pointer() -> u64 {
    let rsp: u64;
    // SAFETY: reads RSP only.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack)) };
    rsp
}

#[test]
fn a_return_to_its_call_takes_the_continuation() {
    let code = pages(&call_and_return(Callee::Return));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, RETURN), CONTINUED);
    assert_eq!(run.pairs(), [1, 0, 0]);
    // The return counted its block and named the caller again, with the
    // BTYPE a continuation enters with.
    assert_eq!(
        (run.control.retired, run.control.block),
        (u64::from(RAN), CALLER & 0xffff_ffff)
    );
    // The continuation's own transfer spends the budget, not the return.
    assert_eq!(run.control.budget, 100);
}

#[test]
fn a_return_elsewhere_takes_the_lookup_and_leaves_the_frame() {
    let code = pages(&call_and_return(Callee::Return));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    // A modified X30: the exit, at the target, its frame still pushed;
    // the exit's return reaches the entry all the same.
    assert_eq!(run.enter(&code, 0, OTHER), (OTHER, RETURNED));
    assert_eq!(run.pairs(), [0, 1, 0]);
    assert_eq!(run.control.retired, 0);
}

#[test]
fn a_failed_authentication_never_matches_a_frame() {
    // RETAA's thunk hands the tail the authenticated target, or the
    // pointer poisoned where it failed: never a frame's address, which a
    // BL or BLR wrote canonical.
    let code = pages(&call_and_return(Callee::Return));
    for poison in [POISON, POISON << 1, 0x7f << 56] {
        let mut run = Run::new(DEFAULT_FRAME_BOUND);
        let forged = RETURN ^ poison;
        assert_eq!(run.enter(&code, 0, forged), (forged, RETURNED));
        assert_eq!(run.pairs(), [0, 1, 0]);
    }
}

#[test]
fn what_runs_between_call_and_return_decides_the_frame() {
    for (callee, taken) in [
        (Callee::Retired, false),
        (Callee::Interrupted, false),
        (Callee::Entered, false),
        (Callee::Switched, false),
        (Callee::EnteredAndReturned, true),
    ] {
        let code = pages(&call_and_return(callee));
        let mut run = Run::new(DEFAULT_FRAME_BOUND);
        let (result, pairs) = match taken {
            true => (CONTINUED, [1, 0, 0]),
            false => ((RETURN, RETURNED), [0, 1, 0]),
        };
        assert_eq!(run.enter(&code, 0, RETURN), result, "{callee:?}");
        assert_eq!(run.pairs(), pairs, "{callee:?}");
    }
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    let code = pages(&call_and_return(Callee::Retired));
    run.enter(&code, 0, RETURN);
    assert_eq!(*run.epoch, 8);
    // Acknowledged: the next run's frame matches.
    let code = pages(&call_and_return(Callee::Interrupted));
    run.enter(&code, 0, RETURN);
    run.control.observed_interrupt_epoch = run.control.interrupt_epoch;
    let code = pages(&call_and_return(Callee::Return));
    assert_eq!(run.enter(&code, 0, RETURN), CONTINUED);
}

#[test]
fn no_budget_left_takes_the_exit() {
    let code = pages(&call_and_return(Callee::Return));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    run.control.budget = 0;
    assert_eq!(run.enter(&code, 0, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [0, 1, 0]);
}

#[test]
fn an_exit_between_call_and_return_discards_the_frame() {
    let code = call_and_return(Callee::Exit);
    let callee = code.len() - return_tail_bytes();
    let code = pages(&code);
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    // The exit leaves with the frame pushed: back at the entry.
    assert_eq!(run.enter(&code, 0, RETURN).1, EXITED);
    // The next run starts with none, and its return, at the entry's own
    // stack where a frame would be, takes the exit.
    assert_eq!(run.enter(&code, callee, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [0; PAIR_COUNTS]);
}

/// Bytes of [`call_and_return`]'s return: RAX from RSI, the paired return
/// and the exit.
fn return_tail_bytes() -> usize {
    let mut code = Code::pinned();
    returning(&mut code.asm());
    code.len()
}

#[test]
fn a_return_at_the_entrys_depth_reads_no_frame() {
    // The stack above the entry's is the host's, whatever it holds.
    let mut code = Code::pinned();
    returning(&mut code.asm());
    let code = pages(&code.into_bytes());
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    for target in [RETURN, OTHER, 0] {
        assert_eq!(run.enter(&code, 0, target), (target, RETURNED));
    }
    assert_eq!(run.pairs(), [0; PAIR_COUNTS]);
}

#[test]
fn code_without_a_control_pushes_and_takes_no_frame() {
    let code = pages(&call_and_return(Callee::Return));
    let mut state = Box::new(GuestState::default());
    // SAFETY: as `Run::enter`, without a control.
    let result = unsafe { crate::x86_64::native::enter(code.0, &mut *state, RETURN, 0) };
    // The call is its plain exit into the callee, whose return exits.
    assert_eq!((result as u64, (result >> 64) as u64), (RETURN, RETURNED));
}

/// Code that recurses `depth` (RSI) times through one call site whose
/// return address is [`RETURN`], each level's continuation a return to
/// it, the deepest level a return too, which first records the host stack
/// pointer at `deepest` (RDX): what frames there are match, then the return
/// with none left exits.
fn recursion() -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let start = asm.len();
    asm.alu_imm8(Alu::Sub, Qword, Gpr::Rsi, 1);
    let base = asm.jcc(Cond::E);
    let continuation = paired_call(&mut asm, GuestAddress(RETURN));
    let again = asm.jmp();
    asm.bind_back(again, start);
    asm.bind(base);
    asm.mov_store(Qword, Mem::base(Rdx, 0), Gpr::Rsp);
    asm.bind(continuation);
    asm.mov_imm64(Rax, RETURN);
    paired_return(&mut asm, RAN).unwrap();
    return_exit(&mut asm);
    code.into_bytes()
}

#[test]
fn recursion_past_the_bound_refuses_the_deeper_frames() {
    let code = pages(&recursion());
    for (bound, depth) in [(4, 10), (16, 16), (64, 200), (0, 3), (64, 65)] {
        let mut run = Run::new(bound);
        let mut deepest = Box::new(0u64);
        let mut state = Box::new(GuestState::default());
        state.anchors[Anchor::Control] = &raw mut *run.control as u64;
        let entered = stack_pointer();
        // SAFETY: as `Run::enter`; RDX names `deepest`.
        let result = unsafe {
            crate::x86_64::native::enter(code.0, &mut *state, depth, &raw mut *deepest as u64)
        };
        assert_eq!(
            (result as u64, (result >> 64) as u64),
            (RETURN, RETURNED),
            "{bound}"
        );
        let pushed = u64::from(bound).min(depth - 1);
        // Every frame matched in turn; the deeper calls took the plain exit.
        assert_eq!(
            run.pairs(),
            [pushed, 0, depth - 1 - pushed],
            "{bound} {depth}"
        );
        assert_eq!(run.control.retired, pushed * u64::from(RAN));
        // The frames are all the stack the recursion took.
        let used = entered - *deepest;
        assert!(
            used <= pushed * FRAME_BYTES as u64 + 64,
            "{bound} {depth}: {used}"
        );
        assert!(
            used >= pushed * FRAME_BYTES as u64,
            "{bound} {depth}: {used}"
        );
    }
}

/// [`recursion`] that exits at its deepest level instead of returning,
/// or takes an interruption there.
fn recursion_ending(interrupt: bool) -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let start = asm.len();
    asm.alu_imm8(Alu::Sub, Qword, Gpr::Rsi, 1);
    let base = asm.jcc(Cond::E);
    let continuation = paired_call(&mut asm, GuestAddress(RETURN));
    let again = asm.jmp();
    asm.bind_back(again, start);
    asm.bind(base);
    if interrupt {
        asm.place(Rcx, CONTROL);
        asm.alu_imm8(Alu::Add, Qword, Mem::base(Rcx, INTERRUPT_EPOCH), 1);
    } else {
        asm.mov_imm32(Rax, 0x5e);
        asm.mov_imm32(Rdx, EXITED as u32);
        exit_return(&mut asm);
    }
    asm.bind(continuation);
    asm.mov_imm64(Rax, RETURN);
    paired_return(&mut asm, RAN).unwrap();
    return_exit(&mut asm);
    code.into_bytes()
}

#[test]
fn exits_and_interruptions_at_every_depth_reach_the_entry() {
    let exits = pages(&recursion_ending(false));
    let interrupts = pages(&recursion_ending(true));
    let bound = 8;
    for depth in 1..=bound as u64 + 3 {
        let pushed = u64::from(bound).min(depth - 1);
        let mut run = Run::new(bound);
        assert_eq!(run.enter(&exits, 0, depth), (0x5e, EXITED), "{depth}");
        assert_eq!(run.pairs(), [0, 0, depth - 1 - pushed]);
        // An interruption pending: the deepest return takes its lookup,
        // which leaves, at any depth.
        let mut run = Run::new(bound);
        assert_eq!(
            run.enter(&interrupts, 0, depth),
            (RETURN, RETURNED),
            "{depth}"
        );
        assert_eq!(run.pairs(), [0, u64::from(pushed > 0), depth - 1 - pushed]);
    }
}

/// Two calls, to [`RETURN`] and then [`OTHER`], whose callee returns to
/// the first, past the second, then to whatever RSI says: an unwinding
/// (longjmp, an exception's) that skips a frame.
fn unwinding() -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let outer = paired_call(&mut asm, GuestAddress(RETURN));
    let to_inner = asm.jmp();
    asm.bind(outer);
    continued(&mut asm);
    asm.bind(to_inner);
    let inner = paired_call(&mut asm, GuestAddress(OTHER));
    let to_callee = asm.jmp();
    // The inner continuation: [`OTHER`]'s, which returns its own marker.
    asm.bind(inner);
    asm.mov_imm32(Rax, 0x0e);
    asm.mov_imm32(Rdx, 78);
    exit_return(&mut asm);
    asm.bind(to_callee);
    // The callee unwinds to RETURN, which the top frame does not hold:
    // the exit, as for the lookup.
    asm.mov_imm64(Rax, RETURN);
    paired_return(&mut asm, RAN).unwrap();
    // The lookup lands in some code that returns to RSI later.
    returning(&mut asm);
    code.into_bytes()
}

#[test]
fn an_unwinding_return_misses_and_a_later_one_takes_the_frame_it_names() {
    let code = pages(&unwinding());
    // The top frame holds OTHER: a return to it is that frame's
    // continuation however the code got there.
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, OTHER), (0x0e, 78));
    assert_eq!(run.pairs(), [1, 1, 0]);
    // A return to the deeper frame's address under the top one exits, with
    // both frames left: the exit's return reaches the entry.
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [0, 2, 0]);
}

#[test]
fn a_matched_return_takes_no_indirect_jump() {
    let mut code = Code::pinned();
    paired_return(&mut code.asm(), RAN).unwrap();
    let bytes = code.into_bytes();
    // The hit path is everything up to `ret 40`: conditional branches, ALU
    // and moves; no FF /2 or FF /4 (indirect call or jump) in it.
    let ret = bytes
        .windows(3)
        .position(|window| window == [0xc2, (FRAME_BYTES - 8) as u8, 0])
        .unwrap();
    assert!(
        !bytes[..ret]
            .windows(2)
            .any(|pair| pair[0] == 0xff && matches!(pair[1] >> 3 & 7, 2 | 4)),
        "{:02x?}",
        &bytes[..ret]
    );
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let continuation: Patch = paired_call(&mut asm, GuestAddress(RETURN));
    asm.bind(continuation);
    let bytes = code.into_bytes();
    // The call is a direct one (E8 rel32).
    assert_eq!(bytes.iter().filter(|&&byte| byte == 0xe8).count(), 1);
}

#[test]
fn a_paired_tail_is_the_frame_check_then_the_lookup_tail() {
    let (at, probe) = (0x10_0000, 0x10_4000);
    let tail = paired_tail(at, ExitKind::Return, RAN, probe).unwrap();
    let mut check = Code::new();
    paired_return(&mut check.asm(), RAN).unwrap();
    let check = check.into_bytes();
    let lookup = lookup_tail(at + check.len() as u64, ExitKind::Return, RAN, probe, 0).unwrap();
    let body = lookup.iter().rposition(|&byte| byte != 0xcc).unwrap() + 1;
    assert_eq!(tail[..check.len()], check[..]);
    assert_eq!(tail[check.len()..][..body], lookup[..body]);
    assert!(tail[check.len() + body..].iter().all(|&byte| byte == 0xcc));
    const { assert!(PAIRED_TAIL_BYTES <= TAIL_ROOM) };
}

/// The call sites of [`call_loop`] and their guest return addresses, all
/// in one page.
const SITES: usize = 8;
const fn site_return(site: usize) -> u64 {
    RETURN + 0x40 * site as u64
}
/// Where [`call_loop`]'s return tail, probes and continuation blocks begin.
const TAIL_AT: usize = 2048;
const PROBES: usize = 4096;
const CONTINUATIONS: usize = 6 * 1024;

/// A loop of RSI calls whose callee returns at once, through `sites` call
/// sites: with one, the same site each time; with more, a site the
/// state's X0 (a linear congruential sequence) picks each time, as a
/// function with several callers returns. The callee's return is the
/// return exit's tail at [`TAIL_AT`]: a paired tail with `paired`, the
/// lookup tail (its jump cache, then the table probe) without, as today.
/// Each site's continuation exit is linked to its return address's block,
/// which goes back to the loop; the table holds those blocks.
fn call_loop(paired: bool, sites: usize, base: u64) -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let start = asm.len();
    asm.alu_imm8(Alu::Sub, Qword, Gpr::Rsi, 1);
    let done = asm.jcc(Cond::E);
    // RCX = the site: X0 = X0 * 6364136223846793005 + 1, its top 3 bits.
    asm.mov_imm64(Rcx, 6_364_136_223_846_793_005);
    asm.mov_load(Qword, Rax, Mem::base(Gpr::Rdi, 0));
    asm.fixed(&[0x48, 0x0f, 0xaf, 0xc1]); // imul rax, rcx
    asm.alu_imm8(Alu::Add, Qword, Rax, 1);
    asm.mov_store(Qword, Mem::base(Gpr::Rdi, 0), Rax);
    asm.shift_imm(ShiftOp::Shr, Qword, Rax, 61);
    let mut to_sites = Vec::new();
    for site in 1..sites {
        asm.alu_imm8(Alu::Cmp, Dword, Rax, site as i8);
        to_sites.push((site, asm.jcc(Cond::E)));
    }
    let mut first = Some(asm.jmp());
    let mut continuations = Vec::new();
    for site in 0..sites {
        match site {
            0 => asm.bind(first.take().unwrap()),
            _ => {
                let (_, branch) = to_sites.remove(0);
                asm.bind(branch);
            }
        }
        // BL: X30 (the state's X1 here) is the return address.
        asm.mov_imm64(R8, site_return(site));
        asm.mov_store(Qword, Mem::base(Gpr::Rdi, 8), R8);
        let continuation = paired.then(|| paired_call(&mut asm, GuestAddress(site_return(site))));
        // The call's exit, linked into the callee.
        let to_callee = asm.jmp();
        if let Some(continuation) = continuation {
            asm.bind(continuation);
            continuations.push((site, asm.jmp()));
        }
        continuations.push((usize::MAX, to_callee));
    }
    // The callee: RET X30, its exit's patch point jumping to the tail.
    let callee = asm.len();
    asm.mov_load(Qword, Rax, Mem::base(Gpr::Rdi, 8));
    asm.mov_imm32(Rdx, ExitWord::from(ExitKind::Return).encoded());
    let to_tail = asm.jmp();
    asm.bind(done);
    asm.mov_imm32(Rax, 1);
    asm.mov_imm32(Rdx, 2);
    exit_return(&mut asm);
    let used = asm.len();
    assert!(used <= TAIL_AT, "{used}");
    for _ in used..TAIL_AT {
        asm.int3();
    }
    let at = base + TAIL_AT as u64;
    let probe = base + (PROBES + PROBE_ENTRY) as u64;
    let word = ExitWord::from(ExitKind::Return);
    match paired {
        true => asm.fixed(&paired_tail(at, word, RAN, probe).unwrap()),
        false => asm.fixed(&lookup_tail(at, word, RAN, probe, 0).unwrap()),
    }
    let tails = asm.len();
    for _ in tails..PROBES {
        asm.int3();
    }
    asm.fixed(&lookup_dispatcher(0).unwrap());
    let probes = asm.len();
    assert!(probes <= CONTINUATIONS);
    for _ in probes..CONTINUATIONS {
        asm.int3();
    }
    // Each return address's block: back to the loop.
    for _ in 0..sites {
        let back = asm.jmp();
        asm.bind_back(back, start);
        let at = asm.len();
        for _ in at..at.next_multiple_of(16) {
            asm.int3();
        }
    }
    for (site, jump) in continuations {
        match site {
            usize::MAX => crate::x86_64::asm::resolve(&mut code, jump, callee),
            site => crate::x86_64::asm::resolve(&mut code, jump, CONTINUATIONS + 16 * site),
        }
    }
    crate::x86_64::asm::resolve(&mut code, to_tail, TAIL_AT);
    code.into_bytes()
}

/// Host cost of a guest call and return pair through one site and through
/// eight in a random order, as today (the return's lookup tail) and
/// paired. Prints nanoseconds per pair; asserts only the counts.
#[test]
#[ignore = "manual: opt-in"]
fn paired_and_looked_up_return_costs() {
    const ITERATIONS: u64 = 1 << 22;
    let key = block_key(0x4000_0000, 1);
    for sites in [1, SITES] {
        let mut results = Vec::new();
        for paired in [false, true] {
            // The code's address first: its tails jump relative to it.
            let region = pages(&[0; CONTINUATIONS + 16 * SITES]);
            let code = call_loop(paired, sites, region.0 as u64);
            // SAFETY: the mapping is RWX and nothing runs it yet.
            unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), region.0, code.len()) };
            let mut table = LookupTable::new();
            let mut itlb = LookupTable::itlb();
            itlb.insert(
                itlb.page_slot(RETURN, CONTEXTS[1]),
                LookupEntry::page(RETURN & !0xfff, CONTEXTS[1], key),
            );
            for site in 0..sites {
                let pc = site_return(site);
                table.insert(
                    table.slot(pc, key),
                    LookupEntry {
                        pc,
                        key,
                        entry: region.0 as u64 + (CONTINUATIONS + 16 * site) as u64,
                        block: 3 + site as u32,
                        targets: 1,
                    },
                );
            }
            let stamps = table.new_stamps();
            let mut run = Run::new(DEFAULT_FRAME_BOUND);
            run.control.budget = u64::MAX / 2;
            run.control.table = table.address();
            run.control.itlb = itlb.address();
            run.control.salts = [itlb.salt(CONTEXTS[0]), itlb.salt(CONTEXTS[1])];
            run.control.masks = [table.mask(), itlb.mask()];
            run.control.stamps = stamps;
            assert_eq!(run.enter(&region, 0, 1 << 12), (1, 2));
            let mut best = f64::MAX;
            for _ in 0..5 {
                let start = std::time::Instant::now();
                assert_eq!(run.enter(&region, 0, ITERATIONS), (1, 2));
                let ns = start.elapsed().as_secs_f64() * 1e9 / (ITERATIONS - 1) as f64;
                best = best.min(ns);
            }
            let pairs = run.pairs();
            if paired {
                assert!(pairs[PairCount::Matched as usize] > ITERATIONS);
                assert_eq!(pairs[PairCount::Missed as usize], 0);
                assert_eq!(pairs[PairCount::Refused as usize], 0);
                assert_eq!(run.control.hits, 0);
            } else {
                assert_eq!(pairs, [0; PAIR_COUNTS]);
                assert!(run.control.hits > 0);
            }
            results.push(best);
        }
        std::println!(
            "call/return pair, {sites} site(s): lookup tail {:.2} ns, paired {:.2} ns",
            results[0],
            results[1]
        );
    }
}

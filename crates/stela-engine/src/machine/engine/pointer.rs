//! The PAC results the engine computes, remembers and lets native code
//! complete (`x86_64::pointer`).
//!
//! A signing or authentication is a pure function of its key, the chip's
//! PAC version, the regime's TCR (Arm `AddPAC`, `Auth`) and its operands,
//! so [`PointerService`] remembers results in a memo tagged with the
//! generation of that key's inputs. It lives at a fixed host address: PAC
//! thunks read its memo and its tag words, and on a memo miss call
//! [`complete`] with it, which computes the result exactly as the engine's
//! exit would ([`PointerService::result`]) without leaving native code.
//! A key's tag word is nonzero only while the service is open and the key
//! was found enabled and untrapped under the current derived state, which
//! is what both paths require, or [`pointer::DISABLED`] while it was found
//! disabled, whose results [`complete`] gives and remembers under that word.
//! Native code reads a memo whatever the tag words: an empty one shared by
//! every service until a service needs its own.
use crate::pauth;
use alloc::{boxed::Box, vec, vec::Vec};
use core::mem::offset_of;
use stela_compiler::{Anchor, Place, block::PointerAuthenticationKey, x86_64::pointer};

pub(super) mod census;

/// The memo native code reads while its service has none: no entry's tag
/// matches a tag word, so every lookup misses ([`pointer::DISABLED`]).
/// Only read, through its address.
static EMPTY_MEMO: [core::sync::atomic::AtomicU64; pointer::MEMO_ENTRIES * 4] =
    [const { core::sync::atomic::AtomicU64::new(0) }; pointer::MEMO_ENTRIES * 4];

/// The distinct keys (each with the version and TCR) whose memo
/// generations are kept: two per process (its IB and DB keys) for over a
/// hundred processes. The lists are kept most recent first, so the keys in
/// use are found in the first few entries.
pub(super) const POINTER_INPUTS_SEEN: usize = 256;

/// What a PAC result depends on besides its operands: the five keys, the
/// chip's PAC version and the regime's TCR (Arm `AddPAC`, `Auth`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PointerInputs {
    pub(super) keys: [Option<[u64; 2]>; 5],
    pub(super) version: pauth::Version,
    pub(super) tcr: u64,
}

/// What the results of one key depend on: its tag word's index, its value,
/// the chip's PAC version and the regime's TCR. Another key's value does
/// not change them, so a key's entries outlive changes of the others (a
/// process's own keys beside the kernel's, which stay).
#[derive(Clone, Copy, PartialEq, Eq)]
struct KeyInputs {
    index: u8,
    key: Option<[u64; 2]>,
    version: pauth::Version,
    tcr: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PointerOperation {
    Sign,
    Authenticate { combined: bool },
}

/// The [`pointer::MemoEntry`] kinds of the results native code does not
/// complete, plus 1 for a combined form: an authentication that failed
/// without a fault, and one that faults with the code in `value`.
const UNAUTHENTICATED: u64 = 3;
const FAULTED: u64 = 5;
/// The tag bits of an entry's kind.
const KIND: u64 = 0xf;

/// A result: the value and whether it authenticated (signings always do),
/// or the PAC failure code of a faulting authentication.
pub(super) type PointerResult = Result<(u64, bool), u8>;

/// The memo kind and value of an operation's result.
fn memo_result(operation: PointerOperation, result: PointerResult) -> (u64, u64) {
    let combined = u64::from(operation == PointerOperation::Authenticate { combined: true });
    match (operation, result) {
        (PointerOperation::Sign, Ok((value, _))) => (pointer::SIGNED, value),
        (_, Ok((value, true))) => (pointer::AUTHENTICATED, value),
        (_, Ok((value, false))) => (UNAUTHENTICATED + combined, value),
        (_, Err(code)) => (FAULTED + combined, u64::from(code)),
    }
}

/// The memo index of a key.
pub(super) fn memo_key(key: stela_contracts::pauth::Key) -> u8 {
    pointer::key_index(match key {
        stela_contracts::pauth::Key::Ia => PointerAuthenticationKey::Ia,
        stela_contracts::pauth::Key::Ib => PointerAuthenticationKey::Ib,
        stela_contracts::pauth::Key::Da => PointerAuthenticationKey::Da,
        stela_contracts::pauth::Key::Db => PointerAuthenticationKey::Db,
    })
}

fn key_of(key: PointerAuthenticationKey) -> stela_contracts::pauth::Key {
    match key {
        PointerAuthenticationKey::Ia => stela_contracts::pauth::Key::Ia,
        PointerAuthenticationKey::Ib => stela_contracts::pauth::Key::Ib,
        PointerAuthenticationKey::Da => stela_contracts::pauth::Key::Da,
        PointerAuthenticationKey::Db => stela_contracts::pauth::Key::Db,
    }
}

/// The engine's PAC context, memo and tag words, which native code reads.
pub(super) struct PointerService {
    /// The keys, version and layout, while open.
    context: Option<pauth::Context>,
    /// The layouts of the most recent regime, kept across key changes.
    layouts: Option<pauth::Layouts>,
    /// Results, each tagged with the generation of its key's inputs when it
    /// was computed; `generations[index]` is that of each key in `inputs`.
    /// Allocated before the first usable native tag and kept at that
    /// address for the owner.
    memo: Option<Box<[pointer::MemoEntry]>>,
    inputs: Option<PointerInputs>,
    pub(super) key_generations: [u64; pointer::TAG_WORDS],
    /// The generation of the whole `inputs`, which native transitions
    /// compare (`transition::check_pointer`): equal exactly when the key
    /// generations, and so the tag words the engine reopens, are equal.
    pub(super) generation: u64,
    /// The whole inputs most recently seen, each with its key generations
    /// and its generation, most recent first.
    seen_inputs: Vec<(PointerInputs, [u64; pointer::TAG_WORDS], u64)>,
    /// The generations of the most recent distinct key inputs, most recent
    /// first, so entries stay valid across a return to an earlier key (EL0
    /// and EL1 keys, guarded levels, PE switches) and across changes of the
    /// other keys.
    seen: Vec<(KeyInputs, u64)>,
    /// The last generation handed out; an evicted one is never reused.
    generations: u64,
    /// Each key's tag word for native code: zero until a PAC exit finds the
    /// key enabled and untrapped under the current memo, and again whenever
    /// derived state may have changed.
    pub(super) tags: [u64; pointer::TAG_WORDS],
    /// Instruction/data XPAC masks, independent of cryptographic key state.
    pub(super) strips: [pointer::strip::Cell; 2],
    /// [`SERVICE`]'s address, which blocks completing PAC instructions
    /// inside themselves call through (`x86_64::pointer::inline`).
    routine: u64,
    /// Results computed since boot (the cipher ran): each is a memo miss,
    /// of a block, a thunk or an engine exit.
    pub(super) fills: u64,
    /// Under `--profile`, what the memo missed and why ([`census`]).
    pub(super) census: Option<Box<census::Census>>,
}

/// The routine a thunk calls on a memo miss.
pub(super) const SERVICE: pointer::ServiceRoutine = complete;

/// Where blocks find the service's tag words, strip cells and routine.
pub(super) const CELLS: pointer::inline::Cells = pointer::inline::Cells {
    tags: offset_of!(PointerService, tags) as u32,
    strips: offset_of!(PointerService, strips) as u32,
    routine: offset_of!(PointerService, routine) as u32,
};

/// Where native code finds the service's tag words.
pub(super) const TAGS: Place = Place::new(Anchor::Pointer, offset_of!(PointerService, tags));

/// Where native code finds the stripping cell of `data`.
pub(super) const fn strip_place(data: bool) -> Place {
    Place::new(
        Anchor::Pointer,
        offset_of!(PointerService, strips) + data as usize * size_of::<pointer::strip::Cell>(),
    )
}

impl PointerService {
    pub(super) fn new() -> Self {
        Self {
            context: None,
            layouts: None,
            memo: None,
            inputs: None,
            key_generations: [0; pointer::TAG_WORDS],
            generation: 0,
            seen_inputs: Vec::new(),
            seen: Vec::new(),
            generations: 0,
            tags: [0; pointer::TAG_WORDS],
            strips: [pointer::strip::Cell::default(); 2],
            routine: SERVICE as usize as u64,
            fills: 0,
            census: None,
        }
    }

    /// Forget the context and close every key, as derived state changed.
    pub(super) fn close(&mut self) {
        self.context = None;
        self.close_native();
    }

    fn close_native(&mut self) -> [bool; 2] {
        self.tags = [0; pointer::TAG_WORDS];
        self.strips
            .each_mut()
            .map(|cell| core::mem::take(&mut cell.enabled) != 0)
    }

    /// Derived state changed, now with `inputs`: every tag word and
    /// stripping cell closes, and the context stays when it was made for
    /// these inputs (else it is made anew, with their memo generation).
    /// Returns which stripping cells were open, for the engine to reopen
    /// with [`Self::reopen`].
    pub(super) fn revalidate(&mut self, inputs: PointerInputs) -> [bool; 2] {
        let stripping = self.close_native();
        if self.context.is_none() || self.inputs != Some(inputs) {
            self.open(inputs);
        }
        stripping
    }

    /// Whether every key is closed to native code.
    pub(super) fn tags_closed(&self) -> bool {
        self.tags.iter().all(|&tag| tag == 0)
    }

    /// Whether native code had anything open: a tag word or a stripping cell.
    pub(super) fn any_open(&self) -> bool {
        self.tags.iter().any(|&tag| tag != 0) || self.strips.iter().any(|cell| cell.enabled != 0)
    }

    /// After [`Self::revalidate`], open `key`'s tag word as a PAC exit
    /// would: [`pointer::DISABLED`] while its SCTLR enable is clear, else,
    /// untrapped and present in the context, the memo's current tag.
    pub(super) fn reopen(
        &mut self,
        key: stela_contracts::pauth::Key,
        enabled: bool,
        trapped: bool,
    ) {
        let index = memo_key(key);
        self.tags[usize::from(index)] = if !enabled {
            pointer::DISABLED
        } else if !trapped
            && self
                .context
                .as_ref()
                .is_some_and(|context| context.has_key(key))
        {
            self.native_tag(index)
        } else {
            0
        };
    }

    /// After [`Self::revalidate`], open the generic key's tag word as a
    /// PACGA exit would: untrapped and present in the context, the memo's
    /// current tag.
    pub(super) fn reopen_generic(&mut self, trapped: bool) {
        let usable = !trapped
            && self
                .context
                .as_ref()
                .is_some_and(pauth::Context::has_generic_key);
        self.tags[usize::from(pointer::GENERIC_KEY)] = if usable {
            self.native_tag(pointer::GENERIC_KEY)
        } else {
            0
        };
    }

    /// After [`Self::revalidate`], reopen the stripping cell of `data`.
    pub(super) fn reopen_stripping(&mut self, data: bool) {
        if let Some(keep) = self
            .context
            .as_ref()
            .map(|context| context.stripping_masks(data))
        {
            self.strips[usize::from(data)] = pointer::strip::Cell {
                enabled: 1,
                keep,
                upper_extension: !keep[1],
            };
        }
    }

    pub(super) fn open_stripping(&mut self, context: &pauth::Context, data: bool) {
        let keep = context.stripping_masks(data);
        self.strips[usize::from(data)] = pointer::strip::Cell {
            enabled: 1,
            keep,
            upper_extension: !keep[1],
        };
    }

    pub(super) fn is_open(&self) -> bool {
        self.context.is_some()
    }

    /// Open the service with the current `inputs`.
    pub(super) fn open(&mut self, inputs: PointerInputs) {
        if self.inputs != Some(inputs) {
            for (index, key) in inputs.keys.into_iter().enumerate() {
                self.key_generations[index] = self.generation_of(KeyInputs {
                    index: index as u8,
                    key,
                    version: inputs.version,
                    tcr: inputs.tcr,
                });
            }
            let keys = self.key_generations;
            self.generation = match self
                .seen_inputs
                .iter()
                .position(|&(known, generations, _)| known == inputs && generations == keys)
            {
                Some(index) => self.seen_inputs.remove(index).2,
                None => {
                    self.generations += 1;
                    self.generations
                }
            };
            self.seen_inputs.insert(0, (inputs, keys, self.generation));
            self.seen_inputs.truncate(POINTER_INPUTS_SEEN);
            self.inputs = Some(inputs);
        }
        let [ia, ib, da, db, generic] = inputs.keys;
        let mut keys = pauth::Keys::from_optional_words([ia, ib, da, db]);
        if let Some(generic) = generic {
            keys = keys.with_generic_words(generic);
        }
        let layouts = match self.layouts {
            Some(layouts) if layouts.tcr() == inputs.tcr => layouts,
            _ => *self.layouts.insert(pauth::Layouts::new(inputs.tcr)),
        };
        self.context = Some(
            pauth::Context::new_with_version(0, keys, inputs.version)
                .with_layouts(layouts)
                .with_implementation_defined_cipher(),
        );
    }

    /// A usable tag permits a thunk to dereference the memo anchor. A
    /// closed or disabled tag is handled before that dereference.
    fn native_tag(&mut self, key: u8) -> u64 {
        if self.memo.is_none() {
            self.allocate_memo();
        }
        pointer::tag(self.key_generations[usize::from(key)], key, 0)
    }

    #[cold]
    fn allocate_memo(&mut self) {
        self.memo =
            Some(vec![pointer::MemoEntry::default(); pointer::MEMO_ENTRIES].into_boxed_slice());
    }

    /// What native code finds through [`Anchor::Pointer`] and
    /// [`Anchor::Memo`] on its next entry: the memo, or the empty one.
    pub(super) fn anchors(&self) -> (u64, u64) {
        (
            self as *const Self as u64,
            self.memo
                .as_ref()
                .map_or(EMPTY_MEMO.as_ptr() as u64, |memo| memo.as_ptr() as u64),
        )
    }

    /// A disabled key's result, `pointer` unchanged (Arm `AddPAC`, `Auth`),
    /// remembered under [`pointer::DISABLED`] for native code, whatever the
    /// key: a signing's for signings, a success for both authentications.
    fn disabled(&mut self, authenticate: bool, pointer: u64, modifier: u64) -> u64 {
        if self.memo.is_none() {
            self.allocate_memo();
        }
        let kind = if authenticate {
            pointer::AUTHENTICATED
        } else {
            pointer::SIGNED
        };
        let memo = self.memo.as_mut().expect("memo allocated");
        pointer::insert(
            memo,
            pointer::MemoEntry {
                pointer,
                modifier,
                tag: pointer::DISABLED | kind,
                value: pointer,
            },
        );
        pointer
    }

    /// One signing or authentication with the open context, remembered
    /// while its inputs stay the same, with `key` known enabled and
    /// untrapped, which opens its tag word. The memo slot comes from the
    /// pointer and modifier alone, so which slot is touched never depends on
    /// a key. A signing whose result strips back to its pointer also
    /// remembers that authenticating the result with the same key and
    /// modifier succeeds with that pointer (Arm `Auth` recomputes the PAC of
    /// the stripped pointer), which answers the epilogue of a signed frame;
    /// a success answers both the combined and the plain authentication.
    /// `None` when the service is closed or the context lacks the key.
    pub(super) fn result(
        &mut self,
        operation: PointerOperation,
        key: stela_contracts::pauth::Key,
        pointer: u64,
        modifier: u64,
    ) -> Option<PointerResult> {
        if !self.context.as_ref()?.has_key(key) {
            return None;
        }
        let index = memo_key(key);
        self.tags[usize::from(index)] = self.native_tag(index);
        if let Some(result) = self.remembered(operation, key, pointer, modifier) {
            return Some(result);
        }
        self.computed(operation, key, pointer, modifier)
    }

    /// [`Self::result`] past its memo lookup, which a thunk's miss has
    /// already made: the cipher's result, remembered. `None` when the
    /// service is closed.
    fn computed(
        &mut self,
        operation: PointerOperation,
        key: stela_contracts::pauth::Key,
        pointer: u64,
        modifier: u64,
    ) -> Option<PointerResult> {
        let index = memo_key(key);
        let context = self.context.as_ref()?;
        let words = context.words(key)?;
        self.fills += 1;
        let result = match operation {
            PointerOperation::Sign => Ok((context.sign_with(key, words, pointer, modifier), true)),
            PointerOperation::Authenticate { combined } => {
                match context.authenticate_with(key, words, pointer, modifier, combined) {
                    Ok(result) => Ok((result.pointer, result.authenticated)),
                    Err(failure) => Err(failure.code),
                }
            }
        };
        let strips_back = match (operation, result) {
            (PointerOperation::Sign, Ok((signed, _))) => {
                (context.strip(key, signed) == pointer).then_some(signed)
            }
            _ => None,
        };
        if let Some(census) = &mut self.census
            && let Some(inputs) = self.inputs
            && let Some(words) = inputs.keys[usize::from(index)]
        {
            let kind = match operation {
                PointerOperation::Sign => census::SIGN,
                PointerOperation::Authenticate { .. } => census::AUTHENTICATE,
            };
            census.fill(
                index,
                words,
                inputs.tcr,
                kind,
                pointer,
                modifier,
                strips_back,
            );
        }
        let tag = pointer::tag(self.key_generations[usize::from(index)], index, 0);
        let memo = self.memo.as_mut()?;
        let (kind, value) = memo_result(operation, result);
        pointer::insert(
            memo,
            pointer::MemoEntry {
                pointer,
                modifier,
                tag: tag | kind,
                value,
            },
        );
        if let Some(signed) = strips_back {
            pointer::insert(
                memo,
                pointer::MemoEntry {
                    pointer: signed,
                    modifier,
                    tag: tag | pointer::AUTHENTICATED,
                    value: pointer,
                },
            );
        }
        Some(result)
    }

    /// PACGA with the open context, remembered as [`Self::result`] does,
    /// the key known untrapped. `None` when the context lacks the key.
    pub(super) fn generic_code(&mut self, data: u64, modifier: u64) -> Option<u64> {
        let key = pointer::GENERIC_KEY;
        let code = self.context.as_ref()?.generic_code(data, modifier).ok()?;
        self.fills += 1;
        if let Some(census) = &mut self.census
            && let Some(inputs) = self.inputs
            && let Some(words) = inputs.keys[usize::from(key)]
        {
            census.fill(
                key,
                words,
                inputs.tcr,
                census::GENERIC,
                data,
                modifier,
                None,
            );
        }
        let tag = self.native_tag(key);
        let memo = self.memo.as_mut().expect("memo for open tag");
        pointer::insert(
            memo,
            pointer::MemoEntry {
                pointer: data,
                modifier,
                tag: tag | pointer::SIGNED,
                value: code,
            },
        );
        self.tags[usize::from(key)] = tag;
        Some(code)
    }

    /// The memo generation of a key's `inputs`: the one they had if they
    /// are among the [`POINTER_INPUTS_SEEN`] most recent distinct key
    /// inputs, else a new one. A result depends only on its key's inputs
    /// and its operands, so an entry of a reused generation is still exact.
    fn generation_of(&mut self, inputs: KeyInputs) -> u64 {
        let generation = match self.seen.iter().position(|&(known, _)| known == inputs) {
            Some(index) => self.seen.remove(index).1,
            None => {
                self.generations += 1;
                if let Some(census) = &mut self.census {
                    census.generations += 1;
                }
                self.generations
            }
        };
        self.seen.insert(0, (inputs, generation));
        self.seen.truncate(POINTER_INPUTS_SEEN);
        generation
    }

    /// The current memo's result of `operation` with `key` on these
    /// operands, if it has one: a success answers both authentication forms.
    pub(super) fn remembered(
        &self,
        operation: PointerOperation,
        key: stela_contracts::pauth::Key,
        pointer: u64,
        modifier: u64,
    ) -> Option<PointerResult> {
        let index = memo_key(key);
        let tag = pointer::tag(self.key_generations[usize::from(index)], index, 0);
        let first = pointer::slot(pointer, modifier);
        let entry = *self.memo.as_ref()?[first..first + pointer::MEMO_WAYS]
            .iter()
            .find(|entry| {
                entry.pointer == pointer && entry.modifier == modifier && entry.tag & !KIND == tag
            })?;
        let kind = entry.tag & KIND;
        let combined = u64::from(operation == PointerOperation::Authenticate { combined: true });
        match operation {
            PointerOperation::Sign => (kind == pointer::SIGNED).then_some(Ok((entry.value, true))),
            PointerOperation::Authenticate { .. } => match kind {
                pointer::AUTHENTICATED => Some(Ok((entry.value, true))),
                kind if kind == UNAUTHENTICATED + combined => Some(Ok((entry.value, false))),
                kind if kind == FAULTED + combined => Some(Err(entry.value as u8)),
                _ => None,
            },
        }
    }
}

translated_callee! {
/// A PAC thunk's memo miss (`x86_64::pointer::ServiceRoutine`): the result
/// of `request` on these operands while the requested key's tag word is
/// open, completed when it is a signing or a successful authentication,
/// and the pointer itself while the key is disabled.
/// A failed authentication is remembered for the exit the thunk then takes.
pub(super) fn complete(
    service: u64,
    request: u32,
    pointer: u64,
    modifier: u64,
) -> pointer::Completion {
    // SAFETY: thunks pass the address of the machine's boxed service, which
    // outlives every installed thunk; the engine does not touch it while
    // native code runs.
    let service = unsafe { &mut *(service as *mut PointerService) };
    let fills = service.fills;
    let completion = complete_with(service, request, pointer, modifier);
    if let Some(census) = &mut service.census {
        census.native += service.fills - fills;
        census.calls += 1;
    }
    completion
}
}

/// [`complete`] of the service.
fn complete_with(
    service: &mut PointerService,
    request: u32,
    pointer: u64,
    modifier: u64,
) -> pointer::Completion {
    if pointer::requests_generic_code(request) {
        if service.tags[usize::from(pointer::GENERIC_KEY)] == 0 {
            return pointer::Completion::default();
        }
        return service.generic_code(pointer, modifier).map_or_else(
            pointer::Completion::default,
            |value| pointer::Completion {
                completed: 1,
                value,
            },
        );
    }
    let (key, authenticate, combined) = pointer::requested(request);
    let key = key_of(key);
    match service.tags[usize::from(memo_key(key))] {
        0 => return pointer::Completion::default(),
        pointer::DISABLED => {
            return pointer::Completion {
                completed: 1,
                value: service.disabled(authenticate, pointer, modifier),
            };
        }
        _ => {}
    }
    let operation = if authenticate {
        PointerOperation::Authenticate { combined }
    } else {
        PointerOperation::Sign
    };
    // The thunk missed the memo, and its open tag word says the context
    // holds the key, so the result is computed at once. A failed
    // authentication the memo held is computed and remembered again.
    match service.computed(operation, key, pointer, modifier) {
        Some(Ok((value, true))) => pointer::Completion {
            completed: 1,
            value,
        },
        _ => pointer::Completion::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memo_is_needed_only_for_a_usable_native_tag() {
        use stela_contracts::pauth::Key;

        let mut owner = Box::new(PointerService::new());
        let (service, memo) = owner.anchors();
        let empty = EMPTY_MEMO.as_ptr() as u64;
        assert_eq!(memo, empty);
        let first = inputs(pauth::Version::Classic, 25 | 25 << 16);
        let mut unavailable = first;
        unavailable.keys = [None; 5];
        owner.open(unavailable);
        owner.reopen(Key::Ia, false, true);
        owner.reopen(Key::Ib, true, false);
        owner.reopen_generic(false);
        owner.reopen_stripping(true);
        assert_eq!(owner.tags, [pointer::DISABLED, 0, 0, 0, 0]);
        assert_eq!(owner.strips[1].enabled, 1);
        assert_eq!(owner.result(PointerOperation::Sign, Key::Ib, 4, 8), None);
        assert_eq!(owner.generic_code(4, 8), None);
        assert_eq!(owner.anchors(), (service, empty));

        owner.revalidate(first);
        owner.reopen(Key::Ia, true, true);
        owner.reopen_generic(true);
        assert_eq!(owner.anchors(), (service, empty));
        owner.reopen(Key::Ia, true, false);
        let memo = owner.anchors().1;
        assert_ne!(memo, empty);
        let tag = owner.tags[0];
        let result = owner.result(PointerOperation::Sign, Key::Ia, 4, 8).unwrap();
        owner.close();
        assert_eq!(owner.anchors(), (service, memo));
        owner.open(unavailable);
        owner.revalidate(first);
        owner.reopen(Key::Ia, true, false);
        assert_eq!(owner.anchors(), (service, memo));
        assert_eq!(owner.tags[0], tag);
        assert_eq!(
            owner.remembered(PointerOperation::Sign, Key::Ia, 4, 8),
            Some(result)
        );

        let mut other = Box::new(PointerService::new());
        other.open(first);
        assert_eq!(other.anchors().1, empty);
        other.reopen_generic(false);
        assert_ne!(other.anchors().1, empty);
        assert_ne!(other.anchors().1, memo);
    }

    /// A disabled key's request completes with its pointer, from no key
    /// and no cipher, and is remembered under the disabled word, which no
    /// open or closed word's lookup takes; a closed key's is refused.
    #[test]
    fn disabled_keys_complete_with_their_pointer_for_native_code() {
        use stela_contracts::pauth::Key;

        let mut service = Box::new(PointerService::new());
        let state = service.anchors().0;
        let (data, modifier) = (0xffff_fe00_1234_5678, 0xffff_fe00_0000_8000);
        let ib = u32::from(memo_key(Key::Ib));
        let authenticate = ib | pointer::REQUEST_AUTHENTICATE | pointer::REQUEST_COMBINED;
        assert_eq!(
            complete(state, ib, data, modifier),
            pointer::Completion::default()
        );
        service.reopen(Key::Ib, false, true);
        assert_eq!(
            service.tags[usize::from(memo_key(Key::Ib))],
            pointer::DISABLED
        );
        for (request, kind) in [
            (ib, pointer::SIGNED),
            (authenticate, pointer::AUTHENTICATED),
        ] {
            assert_eq!(
                complete(state, request, data, modifier),
                pointer::Completion {
                    completed: 1,
                    value: data,
                }
            );
            assert_eq!(
                service.memo.as_ref().unwrap()[pointer::slot(data, modifier)],
                pointer::MemoEntry {
                    pointer: data,
                    modifier,
                    tag: pointer::DISABLED | kind,
                    value: data,
                }
            );
        }
        assert_eq!(service.fills, 0);
        assert_eq!(
            service.anchors().1,
            service.memo.as_ref().unwrap().as_ptr() as u64
        );
    }

    #[test]
    fn fills_count_each_computed_result_once() {
        use stela_contracts::pauth::Key;

        let mut service = Box::new(PointerService::new());
        service.open(inputs(pauth::Version::Classic, 25 | 25 << 16));
        assert_eq!(service.fills, 0);
        let signed = service
            .result(PointerOperation::Sign, Key::Ib, 0x1000, 0x20)
            .unwrap();
        assert_eq!(service.fills, 1);
        // A remembered signing, and the authentication its signing filled.
        service.result(PointerOperation::Sign, Key::Ib, 0x1000, 0x20);
        let (pointer, _) = signed.unwrap();
        let authenticate = PointerOperation::Authenticate { combined: false };
        service.result(authenticate, Key::Ib, pointer, 0x20);
        assert_eq!(service.fills, 1);
        service.result(PointerOperation::Sign, Key::Ib, 0x2000, 0x20);
        service.generic_code(3, 4).unwrap();
        assert_eq!(service.fills, 3);
    }

    #[test]
    fn a_generic_code_opens_its_own_tag_and_completes_for_thunks() {
        let mut service = Box::new(PointerService::new());
        let mut input = inputs(pauth::Version::Classic, 25 | 25 << 16);
        input.keys[4] = Some([7, 9]);
        service.open(input);
        let state = service.anchors().0;
        let form = pointer::Form::of(
            stela_compiler::block::PointerAuthenticationOperation::GenericCode(
                stela_compiler::block::pauth_memory::GenericCode {
                    destination: 1,
                    source: 2,
                    modifier: 3,
                },
            ),
        )
        .unwrap();
        let (data, modifier) = (0x1234, 0x5678);
        // Closed, the service is not asked.
        assert_eq!(
            complete(state, form.request(), data, modifier),
            pointer::Completion::default()
        );
        let code = service.generic_code(data, modifier).unwrap();
        let tag = pointer::tag(
            service.key_generations[usize::from(pointer::GENERIC_KEY)],
            pointer::GENERIC_KEY,
            0,
        );
        assert_eq!(service.tags[usize::from(pointer::GENERIC_KEY)], tag);
        assert_eq!(service.tags[..4], [0; 4]);
        assert_eq!(
            service.memo.as_ref().unwrap()[pointer::slot(data, modifier)],
            pointer::MemoEntry {
                pointer: data,
                modifier,
                tag: tag | pointer::SIGNED,
                value: code,
            }
        );
        // Open, a memo miss completes through it.
        assert_eq!(
            complete(state, form.request(), data, modifier),
            pointer::Completion {
                completed: 1,
                value: code,
            }
        );
        service.reopen_generic(true);
        assert_eq!(service.tags, [0; pointer::TAG_WORDS]);
        service.reopen_generic(false);
        assert_eq!(service.tags[usize::from(pointer::GENERIC_KEY)], tag);
        // Without the key nothing opens.
        input.keys[4] = None;
        service.close();
        service.open(input);
        assert_eq!(service.generic_code(data, modifier), None);
        service.reopen_generic(false);
        assert_eq!(service.tags, [0; pointer::TAG_WORDS]);
    }

    #[test]
    fn absent_keys_never_open_native_tags_or_reuse_a_known_key_generation() {
        let mut service = PointerService::new();
        let mut input = inputs(pauth::Version::Classic, 25 | 25 << 16);
        input.keys = [None; 5];
        service.open(input);
        assert!(
            service
                .result(
                    PointerOperation::Sign,
                    stela_contracts::pauth::Key::Ia,
                    0x4000,
                    0x8000
                )
                .is_none()
        );
        assert_eq!(service.tags, [0; pointer::TAG_WORDS]);
        let unknown_generation = service.generation;
        input.keys[0] = Some([11, 21]);
        service.close();
        service.open(input);
        assert!(
            service
                .result(
                    PointerOperation::Sign,
                    stela_contracts::pauth::Key::Ia,
                    0x4000,
                    0x8000
                )
                .is_some()
        );
        assert_ne!(service.generation, unknown_generation);
        assert_eq!(service.tags[1..], [0; pointer::TAG_WORDS - 1]);
        service.close();
        input.keys[0] = None;
        service.open(input);
        assert_eq!(service.generation, unknown_generation);
        assert!(
            service
                .result(
                    PointerOperation::Sign,
                    stela_contracts::pauth::Key::Ia,
                    0x4000,
                    0x8000
                )
                .is_none()
        );
        assert_eq!(service.tags, [0; pointer::TAG_WORDS]);
    }

    #[test]
    fn stripping_cells_match_the_authoritative_layout_and_close_without_keys() {
        let mut service = PointerService::new();
        for t0 in [0, 16, 17, 25, 39, 63] {
            for t1 in [0, 16, 17, 25, 39, 63] {
                for controls in 0..16u64 {
                    let tcr = t0
                        | t1 << 16
                        | (controls & 1) << 37
                        | (controls & 2) << 37
                        | (controls & 4) << 49
                        | (controls & 8) << 49;
                    let context =
                        pauth::Context::new(0, pauth::Keys::from_optional_words([None; 4]))
                            .with_translation_regime(tcr);
                    for data in [false, true] {
                        service.open_stripping(&context, data);
                        assert!(
                            !service.is_open(),
                            "no cryptographic context or key is needed"
                        );
                        assert_eq!(service.tags, [0; pointer::TAG_WORDS]);
                        let cell = service.strips[usize::from(data)];
                        assert_eq!(cell.enabled, 1);
                        for pointer in [0, u64::MAX, 1 << 55, 1 << 63, 0xdead_1234_5678_abcd] {
                            let upper = pointer & (1 << 55) != 0;
                            let keep = cell.keep[usize::from(upper)];
                            let key = if data {
                                stela_contracts::pauth::Key::Da
                            } else {
                                stela_contracts::pauth::Key::Ia
                            };
                            assert_eq!(
                                (pointer & keep) | if upper { cell.upper_extension } else { 0 },
                                context.strip(key, pointer)
                            );
                        }
                    }
                    service.close();
                    assert!(service.strips.iter().all(|cell| cell.enabled == 0));
                }
            }
        }
    }

    fn inputs(version: pauth::Version, tcr: u64) -> PointerInputs {
        let key = |index: u64| [0x1122_3344_5566_7788 ^ index, 0x99aa_bbcc_ddee_ff00 + index];
        PointerInputs {
            keys: [key(1), key(2), key(3), key(4), key(5)].map(Some),
            version,
            tcr,
        }
    }

    fn request(key: PointerAuthenticationKey, operation: PointerOperation) -> u32 {
        let mut request = u32::from(pointer::key_index(key));
        if let PointerOperation::Authenticate { combined } = operation {
            request |= pointer::REQUEST_AUTHENTICATE;
            if combined {
                request |= pointer::REQUEST_COMBINED;
            }
        }
        request
    }

    /// The native completion answers exactly what the engine's exit
    /// computes, for every key, form and version and for kernel and user
    /// pointers, signed, corrupted and unsigned: it completes signings and
    /// successful authentications, refuses the rest, and refuses everything
    /// for a key whose tag word is closed.
    #[test]
    fn native_completions_equal_the_engine_results() {
        use PointerAuthenticationKey as Key;
        // T0SZ = T1SZ = 25 (39-bit VAs), TBI0 on.
        let tcr = 25 | 25 << 16 | 1 << 37;
        let operations = [
            PointerOperation::Sign,
            PointerOperation::Authenticate { combined: false },
            PointerOperation::Authenticate { combined: true },
        ];
        for version in [
            pauth::Version::Classic,
            pauth::Version::Enhanced,
            pauth::Version::Faulting,
            pauth::Version::FaultingCombined,
        ] {
            let inputs = inputs(version, tcr);
            let mut native = Box::new(PointerService::new());
            let mut engine = PointerService::new();
            native.open(inputs);
            engine.open(inputs);
            let state = native.anchors().0;
            for key in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
                let pauth_key = key_of(key);
                let index = usize::from(pointer::key_index(key));
                for (step, base) in [0xffff_ff80_0012_3450_u64, 0x0000_0001_0000_8000]
                    .into_iter()
                    .enumerate()
                {
                    let modifier = 0xffff_ff80_0040_0000 + step as u64 * 0x10;
                    let signed = engine.result(PointerOperation::Sign, pauth_key, base, modifier);
                    let Some(Ok((signed, true))) = signed else {
                        panic!("signing {base:#x}: {signed:?}");
                    };
                    for operand in [base, signed, signed ^ (1 << 50), signed ^ (1 << 62)] {
                        for operation in operations {
                            native.tags = [0; pointer::TAG_WORDS];
                            let asked = complete(state, request(key, operation), operand, modifier);
                            assert_eq!(asked, pointer::Completion::default(), "a closed key");
                            native.reopen(pauth_key, true, false);
                            assert_ne!(native.tags[index], 0);
                            let expected = engine.result(operation, pauth_key, operand, modifier);
                            let asked = complete(state, request(key, operation), operand, modifier);
                            let completed = match expected {
                                Some(Ok((value, true))) => pointer::Completion {
                                    completed: 1,
                                    value,
                                },
                                _ => pointer::Completion::default(),
                            };
                            assert_eq!(asked, completed, "{version:?} {key:?} {operation:?}");
                            // The native call remembered what the exit then finds.
                            assert_eq!(
                                native.remembered(operation, pauth_key, operand, modifier),
                                expected
                            );
                        }
                    }
                }
            }
        }
    }

    /// Memo misses of a modelled workload, run by hand: processes that each
    /// have their own IB and DB keys (IA, DA and the generic key shared),
    /// each running a call tree whose frames sign their return address
    /// with IB and SP and authenticate it on return, with system calls into
    /// a kernel whose frames use the kernel's IA and IB keys on the
    /// thread's kernel stack while the process's DB key stays loaded; the
    /// PE switches to the next process after each time slice. Prints the
    /// cipher runs per PAC operation for each number of processes.
    #[test]
    #[ignore = "manual: opt-in"]
    fn memo_replay_of_a_process_mix() {
        extern crate std;
        use stela_contracts::pauth::Key;
        let tcr = 25 | 25 << 16;
        let shared = |word: u64| Some([word, word.rotate_left(17)]);
        let user = |process: u64| PointerInputs {
            keys: [
                shared(1),
                shared(0x100 + process),
                shared(3),
                shared(0x200 + process),
                shared(5),
            ],
            version: pauth::Version::Classic,
            tcr,
        };
        let kernel = |process: u64| PointerInputs {
            keys: [
                shared(9),
                shared(10),
                shared(3),
                shared(0x200 + process),
                shared(5),
            ],
            version: pauth::Version::Classic,
            tcr,
        };
        for processes in [2u64, 4, 8, 16, 32] {
            let mut service = PointerService::new();
            let mut operations = 0u64;
            // A frame: sign on entry, authenticate on return.
            let mut frame = |service: &mut PointerService, key: Key, lr: u64, sp: u64| {
                let signed = match service.result(PointerOperation::Sign, key, lr, sp) {
                    Some(Ok((signed, _))) => signed,
                    other => panic!("{other:?}"),
                };
                service.result(
                    PointerOperation::Authenticate { combined: true },
                    key,
                    signed,
                    sp,
                );
                operations += 2;
            };
            for slice in 0..4000u64 {
                let process = slice % processes;
                service.close();
                service.open(user(process));
                let code = 0x1_0000_0000 + process * 0x100_0000;
                let stack = 0x16f_0000_0000 - process * 0x10_0000;
                for call in 0..64u64 {
                    // A call tree: depth from the call number's low bits.
                    let depth = (call % 7) + 1;
                    for level in 0..depth {
                        let site = code + 0x40 * ((call * 7 + level * 13) % 97);
                        frame(&mut service, Key::Ib, site, stack - 0x60 * level);
                    }
                    if call % 16 == 15 {
                        service.close();
                        service.open(kernel(process));
                        let kernel_stack = 0xffff_fe10_0000_0000 + process * 0x4000;
                        for level in 0..5u64 {
                            let site = 0xffff_fe00_0800_0000 + 0x40 * (level * 11 + call % 3);
                            frame(&mut service, Key::Ib, site, kernel_stack - 0x80 * level);
                            frame(
                                &mut service,
                                Key::Ia,
                                site + 0x20,
                                kernel_stack - 0x80 * level,
                            );
                        }
                        service.close();
                        service.open(user(process));
                    }
                }
            }
            std::println!(
                "REPLAY processes={processes} operations={operations} fills={} per_operation={:.4}",
                service.fills,
                service.fills as f64 / operations as f64
            );
        }
    }

    /// What a memo miss costs, run by hand in a release build: a native
    /// signing miss through the service routine, the cipher alone, and a
    /// miss of the authentication form. Prints nanoseconds per call.
    #[test]
    #[ignore = "manual: opt-in"]
    fn miss_path_timing() {
        extern crate std;
        use PointerAuthenticationKey as Key;
        use std::time::Instant;
        const CALLS: u64 = 1 << 20;
        let tcr = 25 | 25 << 16 | 1 << 37;
        let mut service = Box::new(PointerService::new());
        service.open(inputs(pauth::Version::Classic, tcr));
        let state = service.anchors().0;
        service.reopen(stela_contracts::pauth::Key::Ib, true, false);
        // Canonical upper pointers, which strip back from their signings.
        let operand = |call: u64| {
            (
                0xffff_ff80_0800_0000 + call * 4,
                0xffff_fe10_0000_0000 - call * 16,
            )
        };
        let sign = request(Key::Ib, PointerOperation::Sign);
        let started = Instant::now();
        let mut sum = 0u64;
        for call in 0..CALLS {
            let (pointer, modifier) = operand(call);
            sum = sum.wrapping_add(complete(state, sign, pointer, modifier).value);
        }
        let native = started.elapsed().as_nanos() as f64 / CALLS as f64;
        let cipher = {
            let context = service.context.as_ref().unwrap();
            let started = Instant::now();
            for call in 0..CALLS {
                let (pointer, modifier) = operand(call + CALLS);
                let signed = context.sign(stela_contracts::pauth::Key::Ib, pointer, modifier);
                sum = sum.wrapping_add(signed.unwrap_or(0));
            }
            started.elapsed().as_nanos() as f64 / CALLS as f64
        };
        let authenticate = request(Key::Ib, PointerOperation::Authenticate { combined: true });
        let started = Instant::now();
        for call in 0..CALLS {
            let (pointer, modifier) = operand(call + 2 * CALLS);
            sum = sum.wrapping_add(complete(state, authenticate, pointer, modifier).value);
        }
        let failed = started.elapsed().as_nanos() as f64 / CALLS as f64;
        std::println!(
            "MISS sign_through_service={native:.1}ns sign_alone={cipher:.1}ns auth_miss={failed:.1}ns fills={} ({sum:x})",
            service.fills
        );
        // Host instructions of one call, single-stepped under the trap flag.
        #[cfg(target_os = "linux")]
        {
            let (pointer, modifier) = operand(3 * CALLS);
            let miss = steps(|| {
                core::hint::black_box(complete(state, sign, pointer, modifier));
            });
            let context = service.context.as_ref().unwrap();
            let (pointer, modifier) = operand(3 * CALLS + 1);
            let alone = steps(|| {
                let key = stela_contracts::pauth::Key::Ib;
                core::hint::black_box(context.sign(key, pointer, modifier).ok());
            });
            let key = stela_contracts::pauth::Key::Ib;
            let strip = steps(|| {
                core::hint::black_box(context.strip(key, pointer));
            });
            let (pointer, modifier) = operand(3 * CALLS + 2);
            let lookup = steps(|| {
                core::hint::black_box(service.remembered(
                    PointerOperation::Sign,
                    key,
                    pointer,
                    modifier,
                ));
            });
            let memo = service.memo.as_mut().unwrap();
            let insert = steps(|| {
                pointer::insert(
                    memo,
                    pointer::MemoEntry {
                        pointer,
                        modifier,
                        tag: 7,
                        value: 7,
                    },
                );
            });
            let tag = steps(|| {
                core::hint::black_box(service.native_tag(1));
            });
            std::println!(
                "MISS instructions sign_through_service={miss} sign_alone={alone} strip={strip} lookup={lookup} insert={insert} tag={tag}"
            );
        }
    }

    /// The instructions `run` executes, counted under the trap flag.
    #[cfg(target_os = "linux")]
    fn steps(run: impl FnOnce()) -> usize {
        use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        #[repr(C)]
        struct SigAction {
            handler: usize,
            mask: [u64; 16],
            flags: i32,
            restorer: usize,
        }
        unsafe extern "C" {
            fn sigaction(signal: i32, action: *const SigAction, old: *mut SigAction) -> i32;
        }
        static STEPS: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn step(_: i32, _: *mut core::ffi::c_void, _: *mut core::ffi::c_void) {
            STEPS.fetch_add(1, Relaxed);
        }
        STEPS.store(0, Relaxed);
        let action = SigAction {
            handler: step as extern "C" fn(i32, *mut core::ffi::c_void, *mut core::ffi::c_void)
                as usize,
            mask: [0; 16],
            flags: 4,
            restorer: 0,
        };
        // SAFETY: a SIGTRAP handler that only counts; the trap flag is set
        // around `run` alone.
        unsafe {
            sigaction(5, &action, core::ptr::null_mut());
            core::arch::asm!("pushfq", "or qword ptr [rsp], 0x100", "popfq");
        }
        run();
        // SAFETY: as above.
        unsafe { core::arch::asm!("pushfq", "and qword ptr [rsp], -257", "popfq") };
        STEPS.load(Relaxed)
    }

    /// A key's entries outlive changes of the other keys: a process's keys
    /// change on every switch while the kernel's stay, and the kernel's
    /// results must still be found.
    #[test]
    fn a_keys_entries_outlive_changes_of_the_other_keys() {
        use stela_contracts::pauth::Key;
        let mut service = PointerService::new();
        let mut input = inputs(pauth::Version::Classic, 25 | 25 << 16);
        service.open(input);
        let fills = service.fills;
        let signed = service.result(PointerOperation::Sign, Key::Ia, 0x4000, 0x8000);
        assert_eq!(service.fills, fills + 1);
        for process in 0..2 * POINTER_INPUTS_SEEN as u64 {
            input.keys[1] = Some([process, !process]);
            input.keys[2] = Some([process << 1, process]);
            service.close();
            service.open(input);
            assert_eq!(
                service.result(PointerOperation::Sign, Key::Ia, 0x4000, 0x8000),
                signed
            );
        }
        // Every signing was found again: the cipher ran once.
        assert_eq!(service.fills, fills + 1);
        // A key that changed has a new generation; its old entries miss.
        let ib = service.key_generations[1];
        input.keys[1] = Some([7, 7]);
        service.close();
        service.open(input);
        assert_ne!(service.key_generations[1], ib);
    }

    /// A return to earlier inputs finds their generation again; other inputs
    /// get their own, and beyond the inputs kept a generation is new.
    #[test]
    fn generations_follow_the_inputs() {
        let mut service = PointerService::new();
        let tcr = 25 | 25 << 16;
        let (first, other) = (
            inputs(pauth::Version::Faulting, tcr),
            inputs(pauth::Version::Classic, tcr),
        );
        service.open(first);
        let generation = service.generation;
        service.open(other);
        assert_ne!(service.generation, generation);
        service.open(first);
        assert_eq!(service.generation, generation);
        for extra in 1..=POINTER_INPUTS_SEEN as u64 {
            service.open(inputs(pauth::Version::Faulting, tcr + (extra << 32)));
        }
        service.open(first);
        assert!(service.generation > generation);
        service.close();
        assert!(!service.is_open());
        assert_eq!(service.tags, [0; pointer::TAG_WORDS]);
        assert_eq!(
            service.result(
                PointerOperation::Sign,
                stela_contracts::pauth::Key::Ia,
                1,
                2
            ),
            None
        );
    }
}

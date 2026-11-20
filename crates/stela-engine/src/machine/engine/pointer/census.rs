//! Under `--profile`: what the PAC memo missed and why (the `PES PAC`
//! line). Each cipher run counts by key and by operation (signing,
//! authentication, PACGA), and by cause from a table every PE shares: the
//! last PE that computed a result of the same operands, key and
//! operation. `new` when none did (as far as the table remembers), `here`
//! when this PE did and its memo lost it, `other` when another PE did: a
//! memo shared between the PEs would have had it.

use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering::Relaxed};
use stela_compiler::x86_64::pointer::TAG_WORDS;

/// Signing, authentication and PACGA.
pub(crate) const OPERATIONS: usize = 3;
pub(crate) const SIGN: usize = 0;
pub(crate) const AUTHENTICATE: usize = 1;
pub(crate) const GENERIC: usize = 2;
/// Never computed, computed here before, computed on another PE.
pub(crate) const CAUSES: usize = 3;
const NEW: usize = 0;
const HERE: usize = 1;
const OTHER: usize = 2;
/// Words a census reports ([`Census::words`]): fills by key and operation,
/// causes, fills from native code and its calls of the service, new key
/// generations.
pub const WORDS: usize = TAG_WORDS * OPERATIONS + CAUSES + 3;
/// Entries in the shared table: 32 MiB.
const SHADOW_BITS: u32 = 22;

static SHADOW: AtomicPtr<AtomicU64> = AtomicPtr::new(core::ptr::null_mut());

fn shadow() -> &'static [AtomicU64] {
    let mut pointer = SHADOW.load(Relaxed);
    if pointer.is_null() {
        let table: Vec<AtomicU64> = (0..1usize << SHADOW_BITS)
            .map(|_| AtomicU64::new(0))
            .collect();
        let leaked = Box::leak(table.into_boxed_slice()).as_mut_ptr();
        pointer = match SHADOW.compare_exchange(core::ptr::null_mut(), leaked, Relaxed, Relaxed) {
            Ok(_) => leaked,
            Err(held) => {
                // SAFETY: ours, never published.
                drop(unsafe {
                    Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                        leaked,
                        1 << SHADOW_BITS,
                    ))
                });
                held
            }
        };
    }
    // SAFETY: published once, leaked, never freed.
    unsafe { core::slice::from_raw_parts(pointer, 1 << SHADOW_BITS) }
}

fn mix(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^ value >> 33
}

/// One PE's census.
pub(crate) struct Census {
    /// The PE, as the shared table records it.
    pe: u8,
    pub(crate) fills: [[u64; OPERATIONS]; TAG_WORDS],
    pub(crate) causes: [u64; CAUSES],
    pub(crate) native: u64,
    pub(crate) calls: u64,
    pub(crate) generations: u64,
}

impl Census {
    pub(crate) fn new(pe: usize) -> Self {
        Self {
            pe: (pe % 255) as u8 + 1,
            fills: [[0; OPERATIONS]; TAG_WORDS],
            causes: [0; CAUSES],
            native: 0,
            calls: 0,
            generations: 0,
        }
    }

    /// The identity of a result: its operands, operation and key, the key
    /// by its words and the translation regime that lays its PAC out.
    fn identity(
        key: u8,
        words: [u64; 2],
        tcr: u64,
        operation: usize,
        pointer: u64,
        modifier: u64,
    ) -> u64 {
        mix(pointer
            ^ mix(modifier
                ^ mix(words[0]
                    ^ mix(words[1] ^ mix(tcr ^ u64::from(key) << 56 ^ (operation as u64) << 60)))))
    }

    /// Note that this PE computed `operation` with key `key` (words
    /// `words`) on these operands; `inverse` names the authentication a
    /// signing also remembered.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fill(
        &mut self,
        key: u8,
        words: [u64; 2],
        tcr: u64,
        operation: usize,
        pointer: u64,
        modifier: u64,
        inverse: Option<u64>,
    ) {
        self.fills[usize::from(key)][operation] += 1;
        let table = shadow();
        let identity = Self::identity(key, words, tcr, operation, pointer, modifier);
        let slot = &table[(identity >> (64 - SHADOW_BITS)) as usize];
        let held = slot.swap(identity & !0xff | u64::from(self.pe), Relaxed);
        let cause = match held {
            held if held & !0xff != identity & !0xff => NEW,
            held if held & 0xff == u64::from(self.pe) => HERE,
            _ => OTHER,
        };
        self.causes[cause] += 1;
        if let Some(signed) = inverse {
            let identity = Self::identity(key, words, tcr, AUTHENTICATE, signed, modifier);
            table[(identity >> (64 - SHADOW_BITS)) as usize]
                .store(identity & !0xff | u64::from(self.pe), Relaxed);
        }
    }

    /// The census as [`WORDS`] words.
    pub(crate) fn words(&self) -> [u64; WORDS] {
        let mut words = [0; WORDS];
        words[..TAG_WORDS * OPERATIONS].copy_from_slice(self.fills.as_flattened());
        words[TAG_WORDS * OPERATIONS..][..CAUSES].copy_from_slice(&self.causes);
        words[WORDS - 3] = self.native;
        words[WORDS - 2] = self.calls;
        words[WORDS - 1] = self.generations;
        words
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causes_tell_new_results_from_ones_this_or_another_pe_computed() {
        let words = [0x1234, 0x5678];
        let mut first = Census::new(0);
        let mut second = Census::new(1);
        first.fill(1, words, 25, SIGN, 0x1000, 0x2000, Some(0xab00_1000));
        assert_eq!(first.causes, [1, 0, 0]);
        first.fill(1, words, 25, SIGN, 0x1000, 0x2000, None);
        assert_eq!(first.causes, [1, 1, 0]);
        // The other PE authenticates what the first signed.
        second.fill(1, words, 25, AUTHENTICATE, 0xab00_1000, 0x2000, None);
        assert_eq!(second.causes, [0, 0, 1]);
        // Another key's words make another result.
        second.fill(1, [0x1234, 0x5679], 25, SIGN, 0x1000, 0x2000, None);
        assert_eq!(second.causes, [1, 0, 1]);
        assert_eq!(first.fills[1], [2, 0, 0]);
        assert_eq!(second.fills[1], [1, 1, 0]);
        let reported = second.words();
        assert_eq!(reported[OPERATIONS + SIGN], 1);
        assert_eq!(reported[TAG_WORDS * OPERATIONS + OTHER], 1);
    }
}

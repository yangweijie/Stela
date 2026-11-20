//! Who owned the GPU addresses of whole memory allocations, for naming what
//! a GPU MMU fault address held when the device is lost.
//!
//! The host kernel names a faulting address and the mappings either side
//! of it, and when the address was last unbound, but not which Metal object
//! the mapping belonged to. The device knows: every buffer answers its GPU
//! address, and a whole `VkDeviceMemory` (imported guest memory, a heap, a
//! resource's own memory) is bound at one range that freeing it unbinds.
//! The book keeps, for each whole allocation whose address a buffer showed,
//! its range, what owns it and the serials of its life; the newest frees
//! stay after they are gone. The lost-device report lists those frees with
//! the live ranges next to them, so the kernel's fault line can be matched
//! to its owners.
use crate::metal::vulkan::object::Memory;
use alloc::{collections::BTreeMap, collections::VecDeque, format, string::String, vec::Vec};

/// A Metal object whose memory a connection holds, for
/// [`Device::book_holder`](super::Device::book_holder).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryOwner {
    Import(super::MemoryId),
    Buffer(super::BufferId),
    Texture(super::TextureId),
    Heap(super::HeapId),
}

/// Frees kept after their memory is gone.
const FREED_KEPT: usize = 32;
/// Frees the lost-device report shows, newest first.
const FREED_SHOWN: usize = 12;
/// Freed imports kept bound for reuse that the book follows.
const KEPT_FOLLOWED: usize = 64;

/// One whole allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    /// The GPU address of its first byte, once a buffer over it showed one.
    pub va: Option<u64>,
    pub bytes: u64,
    /// What owns it, as the report names it.
    pub what: String,
    /// The first connection that held its owner.
    pub connection: Option<u64>,
    /// The serial submitted last when it was made.
    pub created: u64,
    /// The serial submitted last when its owner was destroyed.
    pub released: Option<u64>,
}

#[derive(Clone, Debug)]
struct Freed {
    entry: Entry,
    /// The serial completed when its memory was freed.
    freed: u64,
    /// The serial completed when the backend unbound it, for a freed import
    /// it kept bound for reuse until then.
    unbound: Option<u64>,
}

#[derive(Default)]
pub(crate) struct MemoryBook {
    live: BTreeMap<Memory, Entry>,
    freed: VecDeque<Freed>,
    /// Freed imports the backend keeps bound, by its name for each: their
    /// GPU addresses still map until it unbinds them, which is when a read
    /// of them faults.
    kept: VecDeque<(u64, Freed)>,
}

impl MemoryBook {
    /// Notes a whole allocation of `bytes` that `what` owns, made while
    /// `serial` was the newest submitted. A noted one keeps its address
    /// and connection, and takes the new owner.
    pub(crate) fn note(&mut self, memory: Memory, bytes: u64, what: String, serial: u64) {
        let entry = self.live.entry(memory).or_insert_with(|| Entry {
            va: None,
            bytes,
            what: String::new(),
            connection: None,
            created: serial,
            released: None,
        });
        entry.what = what;
    }

    /// `memory`'s first byte is at GPU address `va`.
    pub(crate) fn learn_address(&mut self, memory: Memory, va: u64) {
        if let Some(entry) = self.live.get_mut(&memory) {
            entry.va.get_or_insert(va);
        }
    }

    /// Names what owns `memory` now, such as a texture made over its buffer.
    pub(crate) fn describe(&mut self, memory: Memory, what: String) {
        if let Some(entry) = self.live.get_mut(&memory) {
            entry.what = what;
        }
    }

    /// The first connection to hold `memory`'s owner.
    pub(crate) fn hold(&mut self, memory: Memory, connection: u64) {
        if let Some(entry) = self.live.get_mut(&memory) {
            entry.connection.get_or_insert(connection);
        }
    }

    /// `memory`'s owner was destroyed while `serial` was the newest
    /// submitted; the memory goes once that completes.
    pub(crate) fn release(&mut self, memory: Memory, serial: u64) {
        if let Some(entry) = self.live.get_mut(&memory) {
            entry.released.get_or_insert(serial);
        }
    }

    /// Whether `memory` is noted without a known address.
    pub(crate) fn lacks_address(&self, memory: Memory) -> bool {
        self.live
            .get(&memory)
            .is_some_and(|entry| entry.va.is_none())
    }

    /// The noted allocations without a known address.
    pub(crate) fn addressless(&self) -> Vec<Memory> {
        self.live
            .iter()
            .filter(|(_, entry)| entry.va.is_none())
            .map(|(&memory, _)| memory)
            .collect()
    }

    /// `memory` was freed when `serial` completed: with its GPU mapping, or
    /// kept bound by the backend as `kept` until [`Self::unbound`] names it.
    pub(crate) fn free(&mut self, memory: Memory, serial: u64, kept: Option<u64>) {
        let Some(entry) = self.live.remove(&memory) else {
            return;
        };
        let freed = Freed {
            entry,
            freed: serial,
            unbound: None,
        };
        match kept {
            Some(key) => {
                if self.kept.len() == KEPT_FOLLOWED {
                    self.kept.pop_front();
                }
                self.kept.push_back((key, freed));
            }
            None => self.push_freed(freed),
        }
    }

    fn push_freed(&mut self, freed: Freed) {
        if self.freed.len() == FREED_KEPT {
            self.freed.pop_front();
        }
        self.freed.push_back(freed);
    }

    /// The backend unbound the kept allocations `keys` by `serial`.
    pub(crate) fn unbound(&mut self, keys: &[u64], serial: u64) {
        for key in keys {
            if let Some(at) = self.kept.iter().position(|(kept, _)| kept == key) {
                let (_, mut freed) = self.kept.remove(at).expect("found");
                freed.unbound = Some(serial);
                self.push_freed(freed);
            }
        }
    }

    /// The backend gave kept allocation `key` to a new import: no longer
    /// freed.
    pub(crate) fn retaken(&mut self, key: u64) {
        self.kept.retain(|(kept, _)| *kept != key);
    }

    /// The live allocations with known addresses nearest below and above
    /// `start..end`.
    fn neighbours(&self, start: u64, end: u64) -> (Option<&Entry>, Option<&Entry>) {
        let mut below: Option<&Entry> = None;
        let mut above: Option<&Entry> = None;
        for entry in self.live.values() {
            let Some(va) = entry.va else { continue };
            if va + entry.bytes <= start {
                if below.is_none_or(|kept| kept.va < Some(va)) {
                    below = Some(entry);
                }
            } else if va >= end && above.is_none_or(|kept| kept.va > Some(va)) {
                above = Some(entry);
            }
        }
        (below, above)
    }

    /// The newest frees, each with the live ranges either side, for a
    /// device lost while serial `now` was the newest submitted.
    pub(crate) fn report(&self, now: u64) -> Vec<String> {
        let mut lines = Vec::new();
        for freed in self.freed.iter().rev().take(FREED_SHOWN) {
            let entry = &freed.entry;
            let (below, above) = match entry.va {
                Some(start) => self.neighbours(start, start + entry.bytes),
                None => (None, None),
            };
            let unbound = freed.unbound.map_or_else(String::new, |serial| {
                format!(", kept bound for reuse and unbound when serial {serial} completed")
            });
            lines.push(format!(
                "lost device memory: freed {} when serial {} completed{unbound} (device at {}); \
                 live below: {}; live above: {}",
                describe(entry),
                freed.freed,
                now,
                below.map_or_else(|| String::from("none"), describe),
                above.map_or_else(|| String::from("none"), describe),
            ));
        }
        if lines.is_empty() {
            lines.push(String::from(
                "lost device memory: no whole allocation was freed",
            ));
        }
        if !self.kept.is_empty() {
            lines.push(format!(
                "lost device memory: {} freed imports still bound for reuse, newest {}",
                self.kept.len(),
                self.kept
                    .back()
                    .map_or_else(String::new, |(_, freed)| describe(&freed.entry)),
            ));
        }
        lines
    }
}

/// An entry's range, size, owner and serials.
fn describe(entry: &Entry) -> String {
    let range = entry.va.map_or_else(
        || String::from("an unknown address"),
        |start| format!("{start:#x}-{:#x}", start + entry.bytes),
    );
    let connection = entry.connection.map_or_else(
        || String::from("no connection"),
        |c| format!("connection {c}"),
    );
    let released = entry.released.map_or_else(String::new, |serial| {
        format!(", released at serial {serial}")
    });
    format!(
        "{range} ({} bytes) {} of {connection}, made at serial {}{released}",
        entry.bytes, entry.what, entry.created,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_freed_range_names_its_owner_and_its_live_neighbours() {
        let mut book = MemoryBook::default();
        book.note(Memory(1), 0x4b_0000, String::from("imported buffer"), 10);
        book.learn_address(Memory(1), 0x3f_b3d5_0000);
        book.describe(
            Memory(1),
            String::from("imported buffer under texture 1280x960"),
        );
        book.hold(Memory(1), 7);
        book.note(Memory(2), 0x40_0000, String::from("imported heap"), 11);
        book.learn_address(Memory(2), 0x3f_b420_0000);
        book.note(Memory(3), 0x4b_0000, String::from("imported buffer"), 12);
        book.learn_address(Memory(3), 0x3f_b38a_0000);
        // Far below the nearer one.
        book.note(Memory(4), 0x1000, String::from("buffer"), 12);
        book.learn_address(Memory(4), 0x1000_0000);
        book.release(Memory(1), 20);
        book.free(Memory(1), 20, None);
        let lines = book.report(25);
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(line.contains(
            "freed 0x3fb3d50000-0x3fb4200000 (4915200 bytes) imported buffer under texture \
             1280x960 of connection 7, made at serial 10, released at serial 20 when serial 20 \
             completed (device at 25)"
        ));
        assert!(line.contains("live below: 0x3fb38a0000-0x3fb3d50000"));
        assert!(
            line.contains("live above: 0x3fb4200000-0x3fb4600000 (4194304 bytes) imported heap")
        );
    }

    #[test]
    fn frees_without_an_address_are_named_and_old_frees_go() {
        let mut book = MemoryBook::default();
        assert_eq!(
            book.report(1),
            ["lost device memory: no whole allocation was freed"]
        );
        book.note(Memory(1), 4096, String::from("texture"), 1);
        book.free(Memory(1), 1, None);
        assert!(book.report(1)[0].contains(
            "freed an unknown address (4096 bytes) texture of no connection, made at serial 1"
        ));
        for n in 0..(FREED_KEPT as u64 + 5) {
            book.note(Memory(n + 10), 4096, format!("buffer {n}"), n);
            book.learn_address(Memory(n + 10), (n + 1) << 20);
            book.free(Memory(n + 10), n, None);
        }
        let lines = book.report(100);
        assert_eq!(lines.len(), FREED_SHOWN);
        assert!(lines[0].contains(&format!("buffer {}", FREED_KEPT + 4)));
        assert_eq!(book.freed.len(), FREED_KEPT);
    }

    #[test]
    fn an_address_is_kept_once_learned() {
        let mut book = MemoryBook::default();
        book.note(Memory(1), 8192, String::from("heap"), 1);
        book.learn_address(Memory(1), 0x10_0000);
        book.learn_address(Memory(1), 0x20_0000);
        book.note(Memory(1), 8192, String::from("heap again"), 2);
        let entry = &book.live[&Memory(1)];
        assert_eq!(entry.va, Some(0x10_0000));
        assert_eq!(entry.what, "heap again");
        assert_eq!(entry.created, 1);
    }

    #[test]
    fn a_kept_import_is_freed_in_the_report_when_unbound() {
        let mut book = MemoryBook::default();
        book.note(Memory(1), 0x4a_0000, String::from("imported buffer"), 5);
        book.learn_address(Memory(1), 0x3f_9896_0000);
        book.free(Memory(1), 9, Some(77));
        assert!(book.report(10)[0].contains("no whole allocation was freed"));
        assert!(book.report(10)[1].contains("1 freed imports still bound for reuse"));
        book.unbound(&[77], 40);
        let line = &book.report(41)[0];
        assert!(line.contains(
            "freed 0x3f98960000-0x3f98e00000 (4849664 bytes) imported buffer of no connection, \
             made at serial 5 when serial 9 completed, kept bound for reuse and unbound when \
             serial 40 completed (device at 41)"
        ));
        // One the backend gives to a new import again is not freed.
        book.note(Memory(2), 4096, String::from("imported buffer"), 50);
        book.learn_address(Memory(2), 0x1000);
        book.free(Memory(2), 51, Some(78));
        book.retaken(78);
        book.unbound(&[78], 60);
        assert_eq!(book.report(61).len(), 1);
    }
}

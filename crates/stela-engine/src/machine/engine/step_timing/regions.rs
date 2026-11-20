//! What each range of installed code is, for `--profile`'s host samples
//! (`PES WHERE`): the engine describes the code it installs
//! ([`super::super::Host::profile_code`]) and the host tags its arena with
//! it, so that a sample's address names its region by a table lookup.

use alloc::vec::Vec;

/// What a range of installed code is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodeRegion {
    /// Code nothing described: installed before profiling, or by a path
    /// that does not describe its code.
    Untagged,
    /// A block's inline code.
    Inline,
    /// A block's cold code (`CompiledBlock::cold`): slow paths moved out
    /// of line and the paths behind the jumps over them.
    Cold,
    /// A block's exits to the engine: each direct exit, the dynamic exit
    /// ending its terminal and the check failures after its exits.
    Exit,
    /// Chained transfers: a block's link slots and the thunks apart.
    Link,
    /// Stamped tails.
    Stamped,
    /// Lookup and cell tails.
    Lookup,
    /// The lookup dispatchers' probes, which tails call.
    Probe,
    /// PAC thunks, which complete a block's RETA*, BRA* or BLRA* terminal
    /// natively.
    Pointer,
    /// Other code the engine installs: transition and mirrored-read
    /// thunks, device stubs, routines.
    Other,
}

impl CodeRegion {
    pub const COUNT: usize = Self::Other as usize + 1;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Untagged,
        Self::Inline,
        Self::Cold,
        Self::Exit,
        Self::Link,
        Self::Stamped,
        Self::Lookup,
        Self::Probe,
        Self::Pointer,
        Self::Other,
    ];

    /// The name `PES WHERE` prints.
    pub fn name(self) -> &'static str {
        match self {
            Self::Untagged => "untagged",
            Self::Inline => "inline",
            Self::Cold => "cold",
            Self::Exit => "exit",
            Self::Link => "link",
            Self::Stamped => "stamped",
            Self::Lookup => "lookup",
            Self::Probe => "probe",
            Self::Pointer => "pac-thunk",
            Self::Other => "other-code",
        }
    }

    /// The region of value `index` (`self as u8`).
    pub fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }
}

/// The bytes the PAC service's calls end with in native code, up to the
/// return address (`x86_64::pointer::service_call_ends`): a host that
/// samples where native code runs finds them before a return address to
/// tell time in the service, the cipher of memo misses, from other calls.
pub fn pointer_service_calls() -> [Vec<u8>; 2] {
    use super::super::pointer::{CELLS, SERVICE};
    stela_compiler::x86_64::pointer::service_call_ends(CELLS.routine, SERVICE as usize as u64)
}

/// The regions of a block's `bytes` of code, as `(offset, region)` pairs
/// in ascending offsets, each running to the next one's offset and the last
/// to `bytes`: inline code apart from `spans`, each `(start, end, region)`.
/// Spans are clipped to the code and to each other in the order of their
/// starts; adjacent ranges of one region merge.
pub fn block_regions(bytes: u32, spans: &mut [(u32, u32, CodeRegion)]) -> Vec<(u32, CodeRegion)> {
    spans.sort_unstable_by_key(|&(start, ..)| start);
    let mut regions: Vec<(u32, CodeRegion)> = Vec::with_capacity(2 * spans.len() + 1);
    let mut push = |offset: u32, region: CodeRegion| {
        if regions.last().is_none_or(|&(_, last)| last != region) {
            regions.push((offset, region));
        }
    };
    let mut cursor = 0;
    for &(start, end, region) in spans.iter() {
        let (start, end) = (start.max(cursor), end.min(bytes));
        if start >= end {
            continue;
        }
        if start > cursor {
            push(cursor, CodeRegion::Inline);
        }
        push(start, region);
        cursor = end;
    }
    if cursor < bytes || bytes == 0 {
        push(cursor, CodeRegion::Inline);
    }
    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_indices_round_trip() {
        for (index, region) in CodeRegion::ALL.into_iter().enumerate() {
            assert_eq!(region as usize, index);
            assert_eq!(CodeRegion::from_index(index as u8), Some(region));
        }
        assert_eq!(CodeRegion::from_index(CodeRegion::COUNT as u8), None);
        let mut names: Vec<_> = CodeRegion::ALL.iter().map(|region| region.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CodeRegion::COUNT);
    }

    #[test]
    fn a_block_is_inline_apart_from_its_spans() {
        use CodeRegion::{Cold, Exit, Inline, Link};
        // Inline, cold, inline, a link slot and its exit, a failure.
        let mut spans = [
            (90, 110, Exit),
            (40, 60, Cold),
            (110, 120, Exit),
            (70, 90, Link),
            (200, 300, Exit),
        ];
        assert_eq!(
            block_regions(210, &mut spans),
            [
                (0, Inline),
                (40, Cold),
                (60, Inline),
                (70, Link),
                (90, Exit),
                (120, Inline),
                (200, Exit)
            ]
        );
        // No spans, an empty cold span and overlapping ones.
        assert_eq!(block_regions(10, &mut []), [(0, Inline)]);
        assert_eq!(block_regions(10, &mut [(4, 4, Cold)]), [(0, Inline)]);
        assert_eq!(
            block_regions(10, &mut [(0, 6, Exit), (4, 8, Link)]),
            [(0, Exit), (6, Link), (8, Inline)]
        );
    }
}

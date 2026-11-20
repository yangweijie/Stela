use super::*;
use alloc::string::ToString;

/// A report as nouveau leaves it after `rounds` rounds that saw `seen`,
/// the last at `pstate`.
fn sampled(rounds: u32, pstate: u32, seen: u32) -> Report {
    let report = Report::new();
    report.started.store(1, Ordering::Relaxed);
    report.rounds.store(rounds, Ordering::Relaxed);
    report.pstate.store(pstate, Ordering::Relaxed);
    report.pstates.store(seen | pstate, Ordering::Relaxed);
    report
}

const P0: u32 = 1;
const P5: u32 = 1 << 5;
const P8: u32 = 1 << 8;

/// A report whose rounds read the link as `status` and `control` after
/// seeing the speed codes in `speeds`, on a link of capability `cap`.
fn linked(report: Report, status: u16, control: u16, speeds: u32, cap: u16) -> Report {
    report
        .link_status
        .store(u32::from(status), Ordering::Relaxed);
    report
        .link_control
        .store(u32::from(control), Ordering::Relaxed);
    report
        .link_speeds
        .store(speeds | 1 << u32::from(status & 0xf), Ordering::Relaxed);
    report.link_cap.store(u32::from(cap), Ordering::Relaxed);
    report
}

/// Link Status or Capabilities for a speed code and a width.
const fn lane(speed: u16, width: u16) -> u16 {
    width << 4 | speed
}

#[test]
fn the_layout_is_nouveaus() {
    // `struct nvkm_perf_report`: nine 32-bit words.
    assert_eq!(core::mem::size_of::<Report>(), 36);
    assert_eq!(core::mem::offset_of!(Report, pstate_status), 16);
    assert_eq!(core::mem::offset_of!(Report, link_status), 20);
    assert_eq!(core::mem::offset_of!(Report, link_control), 24);
    assert_eq!(core::mem::offset_of!(Report, link_speeds), 28);
    assert_eq!(core::mem::offset_of!(Report, link_cap), 32);
}

#[test]
fn nothing_is_taken_before_gsp_starts_or_without_a_round() {
    let report = Report::new();
    report.rounds.store(3, Ordering::Relaxed);
    assert_eq!(report.take(), None);
    assert_eq!(sampled(0, P8, 0).take(), None);
}

#[test]
fn a_take_clears_the_counts_and_keeps_the_current_pstate() {
    let report = sampled(10, P8, P5);
    let taken = report.take().unwrap();
    assert_eq!(
        taken,
        Taken {
            rounds: 10,
            pstate: P8,
            pstates: P5 | P8,
            status: 0,
            link: Link::default(),
        }
    );
    assert_eq!(
        taken.to_string(),
        "pstate=P8 seen=P5+P8 pcie=unknown rounds=10"
    );
    // The next beat starts empty but for the P-state RM last gave.
    report.rounds.store(1, Ordering::Relaxed);
    assert_eq!(
        report.take().unwrap().to_string(),
        "pstate=P8 seen=- pcie=unknown rounds=1"
    );
}

#[test]
fn a_refused_control_is_named_with_its_errno() {
    let report = sampled(1, 0, 0);
    report.pstate_status.store(-22, Ordering::Relaxed);
    assert_eq!(
        report.take().unwrap().to_string(),
        "pstate=unknown(error -22) pcie=unknown rounds=1"
    );
}

#[test]
fn a_line_comes_first_and_then_only_when_the_state_changes() {
    let reported = Reported::new();
    let idle = sampled(10, P8, 0).take().unwrap();
    assert_eq!(
        reported.line(&idle).as_deref(),
        Some("GPU PERF pstate=P8 seen=P8 pcie=unknown rounds=10")
    );
    // The count of rounds is no change.
    assert_eq!(reported.line(&sampled(9, P8, 0).take().unwrap()), None);
    // Load raises the P-state.
    let busy = sampled(10, P0, P8).take().unwrap();
    assert_eq!(
        reported.line(&busy).as_deref(),
        Some("GPU PERF pstate=P0 seen=P0+P8 pcie=unknown rounds=10")
    );
    assert_eq!(reported.line(&busy), None);
}

#[test]
fn the_link_shows_its_speed_width_speeds_seen_capability_and_aspm() {
    // RM dropped the link to gen1 at P8 and raised it to gen5 x16 at P0.
    let report = linked(sampled(10, P0, P8), lane(5, 16), 2, 1 << 1, lane(5, 16));
    assert_eq!(
        report.take().unwrap().to_string(),
        "pstate=P0 seen=P0+P8 pcie=gen5x16 pcie_seen=gen1+gen5 pcie_max=gen5x16 aspm=L1 rounds=10"
    );
    // The speeds seen start again; the last reading stays.
    report.rounds.store(1, Ordering::Relaxed);
    assert_eq!(
        report.take().unwrap().to_string(),
        "pstate=P0 seen=- pcie=gen5x16 pcie_seen=- pcie_max=gen5x16 aspm=L1 rounds=1"
    );
}

#[test]
fn a_link_change_alone_gives_a_line() {
    let reported = Reported::new();
    let slow = linked(sampled(10, P0, 0), lane(1, 16), 0, 0, lane(5, 16));
    assert_eq!(
        reported.line(&slow.take().unwrap()).as_deref(),
        Some(
            "GPU PERF pstate=P0 seen=P0 pcie=gen1x16 pcie_seen=gen1 pcie_max=gen5x16 aspm=off rounds=10"
        )
    );
    let same = linked(sampled(10, P0, 0), lane(1, 16), 0, 0, lane(5, 16));
    assert_eq!(reported.line(&same.take().unwrap()), None);
    let fast = linked(sampled(10, P0, 0), lane(5, 16), 0, 0, lane(5, 16));
    assert_eq!(
        reported.line(&fast.take().unwrap()).as_deref(),
        Some(
            "GPU PERF pstate=P0 seen=P0 pcie=gen5x16 pcie_seen=gen5 pcie_max=gen5x16 aspm=off rounds=10"
        )
    );
}

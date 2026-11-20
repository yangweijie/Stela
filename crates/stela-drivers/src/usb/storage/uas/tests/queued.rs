// SPDX-License-Identifier: GPL-2.0-only
//! Queued commands on a stream device, through the media owner and the
//! block device interface the block layer drives: tags in flight at once
//! and completed out of order, one tag failing while others run, a stalled
//! pipe and a hung command that reset the device, and a modelled
//! throughput at depth 1 and queued.
use super::*;
use crate::{
    block::{BlockDevice, Command, Finished},
    usb::storage::{Disk, Scsi, media},
};
use alloc::collections::{BTreeMap, VecDeque};

/// xHCI Stall Error.
const STALL: u32 = 6;
const MEDIUM_ERROR: u32 = 0x03_11_00;

#[derive(Clone, Copy)]
struct QTicket {
    pipe: Pipe,
    id: u64,
    tag: u16,
    address: u64,
    length: usize,
}

/// A command the device received under its tag.
struct Received {
    iu: Vec<u8>,
    reply: Reply,
    ready_at: u64,
    data_done: bool,
    status_sent: bool,
    stall: bool,
}
impl Received {
    /// Everything of it went back: its status, and its data unless it failed.
    fn finished(&self) -> bool {
        self.status_sent
            && (self.data_done || self.reply.requested == 0 || self.reply.sense.is_some())
    }
}

/// A UAS device with streams: every tag runs at once inside it, each ready
/// after its own service time, with its data then crossing one shared link.
struct Device {
    range: core::ops::Range<u64>,
    streams: u16,
    now: u64,
    tickets: Vec<QTicket>,
    next: u64,
    commands: BTreeMap<u16, Received>,
    target: Target,
    /// Service times for the next commands, in arrival order; then
    /// `latency`.
    script: VecDeque<u64>,
    latency: u64,
    /// Microseconds the link takes per KiB of data, one command at a time.
    per_kib: u64,
    link_free: u64,
    /// A read of this block fails with this sense, once.
    fail: Option<(u64, u32)>,
    /// Reads of these blocks stall their status stream, each once.
    stalls: Vec<u64>,
    /// A port reset fails.
    refuse_reset: bool,
    reset_attempts: u32,
    /// A read of this block never completes, once.
    hang: Option<u64>,
    /// Tags in the order their status went back.
    completed: Vec<u16>,
    /// Each cancelled pipe, with the transfers other tags still had on it.
    cancels: Vec<(Pipe, usize)>,
    resets: u32,
    /// The most commands the device held at once.
    deepest: usize,
    received: usize,
}
#[derive(Clone)]
struct Queue(Rc<RefCell<Device>>);

impl Device {
    /// Move the clock to the next moment a command becomes ready, or by a
    /// second when none will.
    fn advance(&mut self) {
        let next = self
            .commands
            .values()
            .map(|command| command.ready_at)
            .filter(|at| *at > self.now && *at != u64::MAX)
            .min();
        self.now = next.unwrap_or(self.now + 1_000_000);
    }
    fn status(tag: u16, sense: Option<u32>) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        bytes[0] = STATUS_IU;
        bytes[2..4].copy_from_slice(&tag.to_be_bytes());
        if let Some(sense) = sense {
            bytes[6] = 2;
            bytes[14..16].copy_from_slice(&18u16.to_be_bytes());
            bytes.resize(34, 0);
            bytes[16] = 0x70;
            bytes[18] = (sense >> 16) as u8;
            bytes[23] = 10;
            bytes[28] = (sense >> 8) as u8;
            bytes[29] = sense as u8;
        }
        bytes
    }
}

impl Io for Queue {
    type Ticket = QTicket;
    fn ready(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
    fn streams(&self) -> Option<u16> {
        Some(self.0.borrow().streams)
    }
    fn now(&self) -> u64 {
        self.0.borrow().now
    }
    fn pause(&self) {
        self.0.borrow_mut().advance();
    }
    fn submit(
        &mut self,
        pipe: Pipe,
        tag: u16,
        address: u64,
        length: usize,
    ) -> Result<QTicket, BlockError> {
        let mut d = self.0.borrow_mut();
        assert!((1..=d.streams).contains(&tag));
        assert!(address >= d.range.start && address + length as u64 <= d.range.end);
        // Each stream takes one TD at a time.
        assert!(
            pipe == Pipe::Command || !d.tickets.iter().any(|t| t.pipe == pipe && t.tag == tag),
            "stream {tag} already has a TD on {pipe:?}"
        );
        d.next += 1;
        let ticket = QTicket {
            pipe,
            id: d.next,
            tag,
            address,
            length,
        };
        d.tickets.push(ticket);
        if pipe == Pipe::Command {
            // SAFETY: the engine keeps this IU buffer for the TD's life.
            let iu = unsafe { core::slice::from_raw_parts(address as *const u8, length) }.to_vec();
            assert_eq!(iu[0], COMMAND_IU);
            assert_eq!(u16::from_be_bytes([iu[2], iu[3]]), tag);
            assert!(
                d.commands.insert(tag, placeholder()).is_none(),
                "tag {tag} reused while in flight"
            );
            let mut reply = d.target.prepare(&iu);
            let cdb = &iu[16..];
            let lba = (cdb[0] == 0x28).then(|| Target::range(cdb).0);
            let mut stall = false;
            let mut service = d.script.pop_front().unwrap_or(d.latency);
            if lba.is_some() && lba == d.fail.map(|(at, _)| at) {
                reply.sense = d.fail.take().map(|(_, sense)| sense);
                reply.data.clear();
            }
            if let Some(at) = d.stalls.iter().position(|at| Some(*at) == lba) {
                d.stalls.remove(at);
                stall = true;
            }
            if lba.is_some() && lba == d.hang {
                d.hang = None;
                service = u64::MAX;
            }
            if reply.requested != 0 && reply.sense.is_none() {
                let data = if reply.input {
                    Pipe::Input
                } else {
                    Pipe::Output
                };
                assert!(
                    d.tickets
                        .iter()
                        .any(|t| t.pipe == data && t.tag == tag && t.length == reply.requested),
                    "stream data must precede its command"
                );
            }
            let ready_at = if service == u64::MAX {
                u64::MAX
            } else {
                let transfer = d.per_kib * reply.requested as u64 / 1024;
                if transfer == 0 {
                    d.now + service
                } else {
                    let at = (d.now + service).max(d.link_free) + transfer;
                    d.link_free = at;
                    at
                }
            };
            *d.commands.get_mut(&tag).unwrap() = Received {
                iu,
                reply,
                ready_at,
                data_done: false,
                status_sent: false,
                stall,
            };
            d.received += 1;
            d.deepest = d.deepest.max(d.commands.len());
        }
        Ok(ticket)
    }
    fn completed(&mut self, t: &QTicket) -> Option<Result<usize, BlockError>> {
        let mut d = self.0.borrow_mut();
        assert!(d.tickets.iter().any(|current| current.id == t.id));
        let now = d.now;
        let result = match t.pipe {
            Pipe::Command => Some(Ok(t.length)),
            Pipe::Input | Pipe::Output => {
                let command = d.commands.get(&t.tag)?;
                if command.reply.sense.is_some() || now < command.ready_at {
                    return None;
                }
                // A reply may hold less than was asked for (a short MODE SENSE).
                let count = if t.pipe == Pipe::Input {
                    command.reply.data.len().min(t.length)
                } else {
                    t.length
                };
                if t.pipe == Pipe::Input {
                    let data = command.reply.data[..count].to_vec();
                    // SAFETY: the engine keeps this data buffer for the TD's life.
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_ptr(), t.address as *mut u8, count)
                    };
                } else {
                    // SAFETY: as above.
                    let bytes =
                        unsafe { core::slice::from_raw_parts(t.address as *const u8, count) }
                            .to_vec();
                    let iu = command.iu.clone();
                    d.target.write(&iu, bytes);
                }
                let command = d.commands.get_mut(&t.tag).unwrap();
                command.data_done = true;
                if command.finished() {
                    d.commands.remove(&t.tag);
                }
                Some(Ok(count))
            }
            Pipe::Status => {
                // Status may be looked at before the data that precedes it.
                let command = d.commands.get_mut(&t.tag)?;
                if now < command.ready_at || command.status_sent {
                    return None;
                }
                command.status_sent = true;
                let (stall, sense) = (command.stall, command.reply.sense);
                if stall || command.finished() {
                    d.commands.remove(&t.tag);
                }
                if stall {
                    Some(Err(BlockError::Device { status: STALL }))
                } else {
                    let bytes = Device::status(t.tag, sense);
                    // SAFETY: as above; a Status IU fits its 512-byte buffer.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            t.address as *mut u8,
                            bytes.len(),
                        )
                    };
                    d.completed.push(t.tag);
                    Some(Ok(bytes.len()))
                }
            }
        };
        if result.is_some() {
            d.tickets.retain(|current| current.id != t.id);
        }
        result
    }
    fn cancel(&mut self, pipe: Pipe) -> Result<(), BlockError> {
        let mut d = self.0.borrow_mut();
        let others = d.tickets.iter().filter(|t| t.pipe == pipe).count();
        d.cancels.push((pipe, others));
        // As xHCI cancellation: every TD on the endpoint, all streams.
        d.tickets.retain(|t| t.pipe != pipe);
        Ok(())
    }
}

fn placeholder() -> Received {
    Received {
        iu: Vec::new(),
        reply: Reply {
            requested: 0,
            input: true,
            data: Vec::new(),
            sense: None,
            wrong_tag: false,
        },
        ready_at: 0,
        data_done: false,
        status_sent: false,
        stall: false,
    }
}

/// The UAS transport over the queued model, as [`Host`] is over xHCI.
struct QueuedHost {
    engine: Engine<Queue>,
    flags: quirks::Flags,
}
impl Scsi for QueuedHost {
    type Lun = Lun;
    fn command(&mut self, lun: Lun, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        execute(&mut self.engine, self.flags, lun.bytes(), cdb, data)
    }
    fn delay(&mut self, micros: u64) -> Result<(), BlockError> {
        self.engine.io.0.borrow_mut().now += micros;
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.engine.io.now()
    }
    fn poisoned(&self) -> bool {
        self.engine.poisoned
    }
    fn take_failed_data(&mut self) -> Option<Vec<u8>> {
        self.engine.failed_data.take()
    }
    fn queued(&self) -> bool {
        true
    }
    fn depth(&self) -> usize {
        self.engine.usable()
    }
    fn begin(&mut self, lun: Lun, cdb: &[u8], data: Data<'_>) -> Option<Result<usize, BlockError>> {
        Some(admit(self.flags, cdb, &data).and_then(|()| self.engine.begin(lun.bytes(), cdb, data)))
    }
    fn end(&mut self, handle: usize) -> Option<Result<Vec<u8>, BlockError>> {
        self.engine.poll(handle, None, &mut None)
    }
    fn busy(&mut self) -> bool {
        self.engine.busy()
    }
    fn room(&mut self) -> bool {
        self.engine.room()
    }
    fn report_luns_permitted(&self) -> bool {
        self.flags.report_luns_permitted()
    }
    fn read_before_mode_sense(&mut self, lun: Lun, block_size: usize) -> Result<(), BlockError> {
        read_block_zero(&mut self.engine, self.flags, lun.bytes(), block_size)
    }
    fn max_transfer_bytes(&self) -> usize {
        self.flags.max_transfer_bytes()
    }
    /// A port reset: the device drops what it held, and a fresh transport
    /// takes over every lane's buffers, as [`Host::reset_and_rebind`] does.
    fn reset_device(
        &mut self,
        _dma: &mut dyn DmaAllocator,
    ) -> Option<Result<Self, (alloc::string::String, BlockError)>> {
        self.engine.poisoned = true;
        {
            let mut d = self.engine.io.0.borrow_mut();
            d.reset_attempts += 1;
            if d.refuse_reset {
                return Some(Err((
                    "model port reset".into(),
                    BlockError::Unsupported("model port reset refused"),
                )));
            }
            d.resets += 1;
            d.tickets.clear();
            d.commands.clear();
            d.link_free = d.now;
        }
        let lanes = self.engine.lanes.iter_mut().map(Lane::transfer).collect();
        Some(Ok(Self {
            engine: Engine {
                io: self.engine.io.clone(),
                lanes,
                poisoned: false,
                failed_data: None,
            },
            flags: self.flags,
        }))
    }
}

type QueuedDisk = Disk<media::Owner<QueuedHost>>;
/// The disk, its device and the media owner between them.
type Stack = (
    QueuedDisk,
    Rc<RefCell<Device>>,
    Rc<RefCell<media::Owner<QueuedHost>>>,
);

/// A one-disk stream device with `streams` stream IDs, discovered through
/// the media owner.
fn stack(memory: &mut [u64], streams: u16) -> Stack {
    let start = memory.as_mut_ptr() as u64;
    let range = start..start + core::mem::size_of_val(memory) as u64;
    let device = Rc::new(RefCell::new(Device {
        range: range.clone(),
        streams,
        now: 0,
        tickets: Vec::new(),
        next: 0,
        commands: BTreeMap::new(),
        target: Target::new(vec![Media::disk(Lun::default(), 0x5a)]),
        script: VecDeque::new(),
        latency: 1,
        per_kib: 0,
        link_free: 0,
        fail: None,
        stalls: Vec::new(),
        refuse_reset: false,
        reset_attempts: 0,
        hang: None,
        completed: Vec::new(),
        cancels: Vec::new(),
        resets: 0,
        deepest: 0,
        received: 0,
    }));
    // SAFETY: each test keeps `memory` live and exclusive until the stack drops.
    let mut dma = unsafe { RegionAllocator::new(range) };
    let host = QueuedHost {
        engine: Engine::new(Queue(device.clone()), &mut dma).unwrap(),
        flags: quirks::Flags::default(),
    };
    let owner = Rc::new(RefCell::new(media::Owner::new(
        host,
        "queued".into(),
        "serial".into(),
    )));
    let mut failures = Vec::new();
    let mut disks = media::scan_uas(owner.clone(), &mut failures).unwrap();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(disks.len(), 1);
    {
        let mut d = device.borrow_mut();
        d.completed.clear();
        d.deepest = 0;
        d.received = 0;
    }
    (disks.remove(0), device, owner)
}

/// Collect every result of `tags`, moving the device's clock on whenever
/// none completed.
fn drain(
    disk: &mut QueuedDisk,
    device: &Rc<RefCell<Device>>,
    tags: &[u32],
) -> BTreeMap<u32, Finished> {
    let mut results = BTreeMap::new();
    for _ in 0..100_000 {
        for &tag in tags {
            if !results.contains_key(&tag)
                && let Some(result) = disk.finish(tag)
            {
                results.insert(tag, result);
            }
        }
        if results.len() == tags.len() {
            return results;
        }
        device.borrow_mut().advance();
    }
    panic!("queued commands never completed");
}

fn block(lba: u64) -> Vec<u8> {
    (0..4096).map(|at| (lba as usize * 7 + at) as u8).collect()
}

#[test]
fn a_stream_device_runs_its_tags_at_once_and_completes_them_out_of_order() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut disk, device, _owner) = stack(&mut memory, 32);
    // Linux: qdepth - 2 of the 32 streams, within the lane limit.
    assert_eq!(disk.depth(), QUEUE_LIMIT);
    let lbas: Vec<u64> = (0..8).map(|i| 64 + i * 8).collect();
    device.borrow_mut().script = [400, 100, 300, 50, 250, 10, 350, 200].into();
    let mut tags = Vec::new();
    for &lba in &lbas {
        assert!(disk.room());
        let write = Command::Write {
            lba,
            data: block(lba),
            fua: false,
        };
        tags.push(disk.start(write).unwrap());
    }
    assert_eq!(device.borrow().commands.len(), 8);
    let results = drain(&mut disk, &device, &tags);
    assert!(results.values().all(|result| matches!(result, Ok(None))));
    {
        let d = device.borrow();
        assert_eq!(d.deepest, 8);
        // Lowest free tag first, and completion in service order.
        assert_eq!(d.completed, vec![6, 4, 2, 8, 5, 3, 7, 1]);
        assert!(d.cancels.is_empty() && d.resets == 0);
    }
    device.borrow_mut().script = [30, 20, 10, 5, 40, 1, 2, 3].into();
    let tags: Vec<u32> = lbas
        .iter()
        .map(|&lba| disk.start(Command::Read { lba, bytes: 4096 }).unwrap())
        .collect();
    let results = drain(&mut disk, &device, &tags);
    for (tag, lba) in tags.iter().zip(&lbas) {
        assert_eq!(results[tag], Ok(Some(block(*lba))), "lba {lba}");
    }
    assert_ne!(device.borrow().completed[8..], [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn a_full_queue_has_no_room_until_a_tag_completes() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut disk, device, _owner) = stack(&mut memory, 6);
    // Six streams leave four tags.
    assert_eq!(disk.depth(), 4);
    device.borrow_mut().latency = 100;
    let tags: Vec<u32> = (0..4)
        .map(|i| {
            disk.start(Command::Read {
                lba: i * 8,
                bytes: 512,
            })
            .unwrap()
        })
        .collect();
    assert!(!disk.room());
    assert!(
        disk.start(Command::Read {
            lba: 99,
            bytes: 512
        })
        .is_err()
    );
    let results = drain(&mut disk, &device, &tags);
    assert_eq!(results.len(), 4);
    assert!(disk.room());
    let d = device.borrow();
    assert!(d.tickets.is_empty() && d.commands.is_empty());
}

#[test]
fn a_device_without_spare_streams_runs_one_command_at_a_time() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut disk, device, _owner) = stack(&mut memory, 2);
    assert_eq!(disk.depth(), 1);
    device.borrow_mut().latency = 100;
    let first = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
    assert!(!disk.room());
    drain(&mut disk, &device, &[first]);
    let second = disk.start(Command::Read { lba: 8, bytes: 512 }).unwrap();
    drain(&mut disk, &device, &[second]);
    assert_eq!(device.borrow().deepest, 1);
}

#[test]
fn a_failing_tag_ends_alone_once_the_others_leave_its_pipe() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut disk, device, owner) = stack(&mut memory, 32);
    let lbas: Vec<u64> = (0..6).map(|i| 128 + i * 8).collect();
    {
        let mut d = device.borrow_mut();
        // The third read fails first, while the others still run.
        d.script = [500, 600, 10, 700, 800, 900].into();
        d.fail = Some((lbas[2], MEDIUM_ERROR));
    }
    let tags: Vec<u32> = lbas
        .iter()
        .map(|&lba| disk.start(Command::Read { lba, bytes: 4096 }).unwrap())
        .collect();
    device.borrow_mut().now = 20;
    // Its Sense IU arrived, but its data TD shares the data-in pipe with
    // the others: it waits, and no new command joins them meanwhile.
    assert_eq!(disk.finish(tags[2]), None);
    assert!(!disk.room());
    assert!(device.borrow().cancels.is_empty());
    let results = drain(&mut disk, &device, &tags);
    assert_eq!(
        results[&tags[2]],
        Err(BlockError::Sense(Sense {
            key: 3,
            asc: 0x11,
            ascq: 0
        }))
    );
    for (index, tag) in tags.iter().enumerate() {
        if index != 2 {
            assert_eq!(results[tag], Ok(Some(vec![0x5a; 4096])));
        }
    }
    let d = device.borrow();
    // One cancellation, of data-in alone, when only its own TD was there.
    assert_eq!(d.cancels, vec![(Pipe::Input, 1)]);
    assert_eq!(d.resets, 0);
    assert!(d.tickets.is_empty());
    drop(d);
    assert!(!owner.borrow().transport.engine.poisoned);
    assert!(disk.room());
    let tag = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
    assert_eq!(
        drain(&mut disk, &device, &[tag])[&tag],
        Ok(Some(vec![0x5a; 512]))
    );
}

#[test]
fn a_stalled_or_hung_tag_resets_the_device_and_each_running_command_runs_again() {
    for hang in [false, true] {
        let mut memory = vec![0u64; 512 * 1024];
        let (mut disk, device, owner) = stack(&mut memory, 32);
        let lbas: Vec<u64> = (0..5).map(|i| 256 + i * 8).collect();
        for &lba in &lbas {
            disk.write(lba, &block(lba)).unwrap();
        }
        {
            let mut d = device.borrow_mut();
            d.script = [300, 400, 50, 500, 600].into();
            if hang {
                d.hang = Some(lbas[2]);
            } else {
                d.stalls.push(lbas[2]);
            }
            d.received = 0;
        }
        let tags: Vec<u32> = lbas
            .iter()
            .map(|&lba| disk.start(Command::Read { lba, bytes: 4096 }).unwrap())
            .collect();
        let results = drain(&mut disk, &device, &tags);
        for (tag, lba) in tags.iter().zip(&lbas) {
            assert_eq!(results[tag], Ok(Some(block(*lba))), "hang {hang} lba {lba}");
        }
        let d = device.borrow();
        assert_eq!(d.resets, 1, "hang {hang}");
        // Every command that had not completed ran again on the rebound
        // transport, after the reset's probes.
        assert!(d.received > tags.len(), "hang {hang}");
        assert!(d.tickets.is_empty() && d.commands.is_empty());
        drop(d);
        assert!(!owner.borrow().transport.engine.poisoned);
    }
}

#[test]
fn a_command_a_second_reset_ends_after_its_one_more_run_fails() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut disk, device, _owner) = stack(&mut memory, 32);
    let lbas: Vec<u64> = (0..3).map(|i| 512 + i * 8).collect();
    {
        let mut d = device.borrow_mut();
        d.script = [300, 50, 500].into();
        // The stalled read stalls again when it runs once more.
        d.stalls = vec![lbas[1], lbas[1]];
    }
    let tags: Vec<u32> = lbas
        .iter()
        .map(|&lba| disk.start(Command::Read { lba, bytes: 4096 }).unwrap())
        .collect();
    let results = drain(&mut disk, &device, &tags);
    assert_eq!(results[&tags[0]], Ok(Some(vec![0x5a; 4096])));
    assert_eq!(results[&tags[1]], Err(BlockError::Device { status: STALL }));
    // The second reset found the third read running again, its one more
    // run spent: it ends, as Linux fails a command past its retries.
    assert_eq!(results[&tags[2]], Err(media::RESET_ENDED));
    assert_eq!(device.borrow().resets, 2);
}

#[test]
fn a_failed_reset_is_not_tried_again_for_the_commands_it_leaves() {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut disk, device, owner) = stack(&mut memory, 32);
    let lbas: Vec<u64> = (0..4).map(|i| 600 + i * 8).collect();
    {
        let mut d = device.borrow_mut();
        d.script = [300, 50, 400, 500].into();
        d.stalls = vec![lbas[1]];
        d.refuse_reset = true;
    }
    let tags: Vec<u32> = lbas
        .iter()
        .map(|&lba| disk.start(Command::Read { lba, bytes: 4096 }).unwrap())
        .collect();
    let results = drain(&mut disk, &device, &tags);
    assert!(results.values().all(Result::is_err));
    assert_eq!(device.borrow().reset_attempts, 1);
    assert!(owner.borrow().transport.engine.poisoned);
    // The unit is given up until a rescan rebinds it.
    assert!(disk.start(Command::Read { lba: 0, bytes: 512 }).is_err());
}

/// Modelled reads per second of `count` random 16 KiB reads kept `depth`
/// deep on a device with `latency` µs service and a link of `per_kib` µs
/// per KiB.
fn modelled_rate(depth: usize, count: usize, latency: u64, per_kib: u64) -> (f64, usize) {
    let mut memory = vec![0u64; 512 * 1024];
    let (mut disk, device, _owner) = stack(&mut memory, 32);
    {
        let mut d = device.borrow_mut();
        d.latency = latency;
        d.per_kib = per_kib;
        d.now = 0;
        d.link_free = 0;
    }
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut running: Vec<u32> = Vec::new();
    let (mut started, mut done) = (0, 0);
    while done < count {
        while started < count && running.len() < depth && disk.room() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let lba = (seed % 127) * 32;
            running.push(disk.start(Command::Read { lba, bytes: 16384 }).unwrap());
            started += 1;
        }
        let before = running.len();
        running.retain(|&tag| match disk.finish(tag) {
            Some(result) => {
                assert!(result.is_ok());
                false
            }
            None => true,
        });
        done += before - running.len();
        if before == running.len() {
            device.borrow_mut().advance();
        }
    }
    let d = device.borrow();
    (count as f64 * 1e6 / d.now as f64, d.deepest)
}

/// Host benchmark: a USB 3 SSD bridge modelled with 100 µs per command,
/// served in parallel inside the device, and a link of 2 µs per KiB
/// (about 500 MB/s), random 16 KiB reads. The modelled time counts the
/// device alone; host overhead is not modelled.
#[test]
fn queued_reads_outrun_one_at_a_time_on_a_modelled_usb_ssd() {
    extern crate std;
    let count = 2000;
    let (one, deepest_one) = modelled_rate(1, count, 100, 2);
    let (four, _) = modelled_rate(4, count, 100, 2);
    let (queued, deepest) = modelled_rate(QUEUE_LIMIT, count, 100, 2);
    std::println!(
        "UAS modelled 16 KiB random reads: depth 1 {one:.0}/s, depth 4 {four:.0}/s, depth {QUEUE_LIMIT} {queued:.0}/s ({:.1}x)",
        queued / one
    );
    assert_eq!(deepest_one, 1);
    assert!(deepest > 4);
    assert!(queued > 3.0 * one, "{queued} vs {one}");
}

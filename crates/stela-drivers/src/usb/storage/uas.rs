//! Native USB Attached SCSI command/data/status transport.
//!
//! USB2 uses READ/WRITE_READY handshakes, one command at a time; SuperSpeed
//! uses the xHCI primary stream service and opaque transfer tickets, with up
//! to [`QUEUE_LIMIT`] commands in flight, each under its own tag and stream
//! as Linux `uas` queues them. Every command keeps its contributors until
//! completion or acknowledged drain.
// SPDX-License-Identifier: GPL-2.0-only
// Linux uas.c reference: Hans de Goede/Red Hat 2013-2016;
// Matthew Wilcox/Intel Corp 2010; Sarah Sharp/Intel Corp 2010.
use super::{Data, Device, DmaAllocator, Endpoint, MAX_TD, Shared, copy_read};
use crate::{
    block::{BlockError, Sense},
    bus::dma::DmaBuffer,
};
use alloc::vec::Vec;

mod abort;
mod binding;
mod quirks;
pub use abort::{AbortCommandResult, AbortTaskOutcome};
pub use binding::Binding;

/// The most commands a SuperSpeed UAS device runs at once. Linux queues
/// `min(streams, MAX_CMNDS) - 2`, about 30 on most bridges; each command
/// here holds a 64 KiB data buffer of its own (a stream TD is one
/// contiguous TRB), so 16 keep a device's buffers at the 1 MiB the NVMe
/// and AHCI drivers give a disk in the 16 MiB boot DMA region.
pub const QUEUE_LIMIT: usize = 16;

/// The streams requested of the host: one per queued command, plus the two
/// tags Linux leaves unused (`uas_probe`: one for untagged commands, one
/// for bridge firmware off by one).
pub const REQUESTED_STREAMS: u16 = QUEUE_LIMIT as u16 + 2;

/// The commands a transport with `streams` allocated stream IDs runs at
/// once: Linux's `can_queue = qdepth - 2`, within [`QUEUE_LIMIT`]; one
/// without streams, or with too few to leave the two spare, runs one.
fn queue_depth(streams: Option<u16>) -> usize {
    match streams {
        Some(streams) if streams > 2 => (usize::from(streams) - 2).min(QUEUE_LIMIT),
        _ => 1,
    }
}

const COMMAND_IU: u8 = 1;
const STATUS_IU: u8 = 3;
const RESPONSE_IU: u8 = 4;
const READ_READY_IU: u8 = 6;
const WRITE_READY_IU: u8 = 7;
const TIMEOUT_US: u64 = 30_000_000;
const IU_BUFFER_BYTES: usize = 512;
const MAX_CDB: usize = 260;
const PROTOCOL_ERROR: BlockError = BlockError::Protocol("malformed UAS information unit");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pipe {
    Command,
    Status,
    Input,
    Output,
}
impl Pipe {
    fn index(self) -> usize {
        self as usize
    }
}

/// Opaque eight-byte SCSI logical-unit address, kept exactly as reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lun([u8; 8]);
impl Lun {
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
    pub(super) fn sequential(number: u16) -> Self {
        let mut bytes = [0; 8];
        bytes[0..2].copy_from_slice(&number.to_be_bytes());
        Self(bytes)
    }
    pub fn bytes(self) -> [u8; 8] {
        self.0
    }
}
impl core::fmt::Display for Lun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The class owner keeps buffers allocated for the entire boot, including
/// uncertain DMA. A failed command quarantines this complete interface; host
/// TD cancellation alone cannot establish that the device retired its UAS tag.
pub struct Host {
    engine: Engine<Native>,
    flags: quirks::Flags,
    device: Device,
    binding: Binding,
    minimum_error: Option<BlockError>,
}
impl Host {
    /// Whether the host controller sends the handoff's completion signal.
    pub fn signals(&self) -> bool {
        self.engine.io.signals()
    }

    /// Whether a running transfer may have completed; a look at memory.
    pub fn posted(&self) -> bool {
        self.engine.io.posted()
    }

    /// # Safety
    /// `device`, binding and controller must name the same physical attachment
    /// and configuration/reset epoch. The caller owns the interface exclusively
    /// and has not configured or submitted to any of these endpoint contexts.
    /// This constructor owns SET_INTERFACE and endpoint/stream setup.
    /// No firmware/other class owner may drive the interface.
    pub unsafe fn new(
        controller: Shared,
        device: &Device,
        binding: Binding,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let io = Self::configure_native(controller, device, &binding, dma)?;
        let engine = Engine::new(io, dma)?;
        Ok(Self {
            engine,
            flags: binding.flags,
            device: device.clone(),
            binding,
            minimum_error: None,
        })
    }
    /// Establish the alternate and endpoint/stream contexts before
    /// acquiring or transferring any transport DMA owner.
    fn configure_native(
        controller: Shared,
        device: &Device,
        binding: &Binding,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Native, BlockError> {
        use super::super::xhci::{FULL_SPEED, HIGH_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS};
        if !matches!(
            device.speed,
            FULL_SPEED | HIGH_SPEED | SUPER_SPEED | SUPER_SPEED_PLUS
        ) {
            return Err(BlockError::Unsupported("UAS device speed"));
        }
        if controller
            .borrow_mut()
            .device(device.id)?
            .current_configuration()?
            != Some(binding.configuration_value())
        {
            return Err(BlockError::Unsupported(
                "UAS configuration is not acknowledged",
            ));
        }
        if binding.alternate() != 0 {
            controller.borrow_mut().device(device.id)?.control(
                super::setup(
                    0x01,
                    super::super::descriptor::SET_INTERFACE,
                    u16::from(binding.alternate()),
                    u16::from(binding.interface()),
                    0,
                ),
                &[],
            )?;
        }
        let endpoints = binding.endpoints();
        let streams = if matches!(device.speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
            // This is the real allocation/configuration ACK, not a capability
            // advertisement or a caller-supplied claim that streams exist.
            Some(
                controller
                    .borrow_mut()
                    .device(device.id)?
                    .configure_streams(
                        &endpoints,
                        &binding.stream_endpoints(),
                        REQUESTED_STREAMS,
                        dma,
                    )?,
            )
        } else {
            controller
                .borrow_mut()
                .device(device.id)?
                .configure(&endpoints, None, dma)?;
            None
        };
        Ok(Native {
            controller,
            id: device.id,
            endpoints,
            streams,
        })
    }
    /// Permanently retire this owner and construct a new owner after a
    /// whole-device USB reset. Existing Rc disk aliases never become usable.
    /// Keep the three transport allocations; root-leaf reset also reuses
    /// retired controller resources. Downstream reset keeps its existing
    /// controller-allocation behavior until subtree reuse is supported.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub(super) fn reset_and_rebind(
        &mut self,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, (alloc::string::String, BlockError)> {
        let controller = self.engine.io.controller.clone();
        let port = controller.borrow().root_port_of(self.device.id);
        self.reset_and_rebind_once(dma)
            .map_err(|(operation, error)| {
                // The port as the failed step left it.
                match port.map(|port| controller.borrow_mut().root_port_status(port)) {
                    Some(status) => (alloc::format!("{operation} ({status})"), error),
                    None => (operation, error),
                }
            })
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn reset_and_rebind_once(
        &mut self,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, (alloc::string::String, BlockError)> {
        self.engine.poisoned = true;
        let fail = |why| {
            (
                alloc::string::String::from("UAS reset/rebind"),
                BlockError::Unsupported(why),
            )
        };
        if !self.engine.buffers_present() {
            return Err(fail("UAS transport DMA owners already transferred"));
        }
        let interfaces = super::super::descriptor::interfaces(&self.device.configuration);
        if self.device.configuration.get(4) != Some(&1)
            || interfaces.is_empty()
            || interfaces
                .iter()
                .any(|interface| interface.number != self.binding.interface())
        {
            return Err(fail(
                "UAS reset requires exclusive ownership of a single-interface device",
            ));
        }
        let controller = self.engine.io.controller.clone();
        // SAFETY: this sole interface owns exactly all configured class DCIs,
        // and its shared owner was permanently poisoned before retirement.
        let mut fresh = unsafe {
            controller.borrow_mut().reset_and_reuse_root(
                &self.device,
                &self.binding.endpoints(),
                dma,
            )?
        };
        let id = fresh.id;
        let result = (|| {
            if fresh.descriptor != self.device.descriptor
                || fresh.configurations != self.device.configurations
                || fresh.serial != self.device.serial
                || fresh.speed != self.device.speed
            {
                return Err(fail("USB device identity/descriptors changed across reset"));
            }
            fresh.configuration = fresh
                .configurations
                .iter()
                .find(|bytes| bytes.get(5) == Some(&self.binding.configuration_value()))
                .cloned()
                .ok_or_else(|| fail("USB reset lost the selected configuration"))?;
            let interface = super::super::descriptor::interfaces(&fresh.configuration)
                .into_iter()
                .find(|interface| {
                    interface.number == self.binding.interface()
                        && interface.alternate == self.binding.alternate()
                })
                .ok_or_else(|| fail("USB reset lost the selected UAS alternate"))?;
            let binding = Binding::new(&fresh, &interface).map_err(fail)?;
            controller
                .borrow_mut()
                .device(id)
                .and_then(|mut device| device.set_configuration(fresh.configuration_value()))
                .map_err(|error| {
                    (
                        alloc::string::String::from("UAS reset restore configuration"),
                        error,
                    )
                })?;
            let mut io = Self::configure_native(controller.clone(), &fresh, &binding, dma)
                .map_err(|error| {
                    (
                        alloc::string::String::from("UAS reset reconstruct endpoints"),
                        error,
                    )
                })?;
            if io.streams() == Some(0) {
                return Err(fail("UAS has no usable stream IDs"));
            }
            io.ready().map_err(|error| {
                (
                    alloc::string::String::from("UAS reset final transport readiness"),
                    error,
                )
            })?;
            // Whole-device retirement and every fallible reconstruction
            // step precede transferring any of the unique allocations.
            // Old aliases keep their permanently poisoned, empty engine.
            let lanes = self.engine.lanes.iter_mut().map(Lane::transfer).collect();
            Ok(Self {
                engine: Engine {
                    io,
                    lanes,
                    poisoned: false,
                    failed_data: None,
                },
                flags: binding.flags,
                device: fresh,
                binding,
                minimum_error: None,
            })
        })();
        if result.is_err()
            && let Ok(mut device) = controller.borrow_mut().device(id)
        {
            device.quarantine();
        }
        result
    }
    pub(super) fn device(&self) -> &Device {
        &self.device
    }
    /// Whether the device is on `controller`.
    pub(super) fn on(&self, controller: &super::Shared) -> bool {
        alloc::rc::Rc::ptr_eq(&self.engine.io.controller, controller)
    }
    pub(super) fn interface(&self) -> u8 {
        self.binding.interface()
    }
    pub(super) fn quarantine(&mut self) {
        self.engine.poisoned = true;
        let mut controller = self.engine.io.controller.borrow_mut();
        if let Ok(mut device) = controller.device(self.engine.io.id) {
            device.quarantine();
        }
    }

    /// Execute a CDB against an eight-byte SCSI LUN address. A check
    /// condition uses the returned Sense IU, not an invented REQUEST SENSE.
    pub fn command(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<Vec<u8>, BlockError> {
        if let Some(error) = &self.minimum_error {
            return Err(error.clone());
        }
        execute(&mut self.engine, self.flags, lun, cdb, data)
    }

    pub(super) fn read_into(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        output: &mut [u8],
    ) -> Result<(), BlockError> {
        let data = Data::In(output.len());
        admit(self.flags, cdb, &data)?;
        self.engine.read_into(lun, cdb, output)
    }

    /// Begin a CDB as [`Self::command`] runs it, without waiting for any
    /// of its transfers; [`Self::end`] gives its result by the returned
    /// handle.
    pub(super) fn begin(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<usize, BlockError> {
        if let Some(error) = &self.minimum_error {
            return Err(error.clone());
        }
        admit(self.flags, cdb, &data)?;
        self.engine.begin(lun, cdb, data)
    }
    /// Begun command `handle`'s result once it ended; never waits.
    pub(super) fn end(&mut self, handle: usize) -> Option<Result<Vec<u8>, BlockError>> {
        if let Some(error) = &self.minimum_error {
            let lane = self.engine.lanes.get(handle)?;
            return lane.active.as_ref().map(|_| Err(error.clone()));
        }
        self.engine.poll(handle, None, &mut None)
    }
    /// The commands this transport runs at once.
    pub(super) fn depth(&self) -> usize {
        self.engine.usable()
    }
    /// Whether [`Self::begin`] takes a command now: a free tag, and no
    /// failed command waiting for the others to leave its pipes; or an
    /// interface that refuses every command at once.
    pub(super) fn room(&self) -> bool {
        self.minimum_error.is_some() || self.engine.room()
    }
    /// Whether a begun command has not ended.
    pub(super) fn busy(&self) -> bool {
        self.engine.busy()
    }

    pub(super) fn delay(&mut self, micros: u64) -> Result<(), BlockError> {
        if let Some(error) = &self.minimum_error {
            return Err(error.clone());
        }
        let result = (|| {
            let mut controller = self.engine.io.controller.borrow_mut();
            controller.device(self.device.id)?.connected()?;
            controller.minimum_wait(micros)
        })();
        if let Err(error) = &result {
            self.minimum_error = Some(error.clone());
            // Do not cancel/reuse tags or take pending contributors after a
            // failed physical source. Native owner/DMA custody remains held.
            self.engine.poisoned = true;
        }
        result
    }
    pub(super) fn now_us(&self) -> u64 {
        self.engine.io.now()
    }
    /// Linux `uas_sdev_configure`: an ALWAYS_SYNC enclosure skips both mode
    /// pages and is assumed writable with its write cache on.
    pub(super) fn write_protect_page(&self) -> Option<u8> {
        (!self.flags.always_sync()).then_some(super::scsi::ALL_PAGES)
    }
    /// Linux `uas_sdev_configure` sets `broken_fua` for a BROKEN_FUA
    /// enclosure, which then takes no FUA write.
    pub(super) fn fua_permitted(&self) -> bool {
        self.flags.permits(&super::scsi::write_10_fua())
    }
    pub(super) fn caching(&self) -> super::Caching {
        match self.flags.always_sync() {
            true => super::Caching::WriteBack,
            false => super::Caching::Query,
        }
    }
    /// `uas_sdev_configure` sets `read_before_ms` for every UAS unit. Some
    /// bridges otherwise return generic write-protect/cache mode information.
    /// This metadata read is never a retry of a caller's failed block command.
    pub(super) fn read_before_mode_sense(
        &mut self,
        lun: [u8; 8],
        block_size: usize,
    ) -> Result<(), BlockError> {
        read_block_zero(&mut self.engine, self.flags, lun, block_size)
    }
    pub(super) fn max_transfer_bytes(&self) -> usize {
        self.flags.max_transfer_bytes()
    }
    pub(super) fn report_luns_permitted(&self) -> bool {
        self.flags.report_luns_permitted()
    }
    pub fn requires_rebind(&self) -> bool {
        self.engine.poisoned
    }
    /// Whether [`Self::reset_and_rebind`] needs fresh rings from its
    /// allocator, as a device behind a hub does.
    pub(super) fn reset_needs_allocation(&self) -> bool {
        self.engine
            .io
            .controller
            .try_borrow()
            .is_ok_and(|controller| controller.reset_needs_allocation(self.device.id))
    }
    /// What the last command's data phase moved in before it failed.
    pub(super) fn take_failed_data(&mut self) -> Option<Vec<u8>> {
        self.engine.failed_data.take()
    }
}

fn execute<I: Io>(
    engine: &mut Engine<I>,
    flags: quirks::Flags,
    lun: [u8; 8],
    cdb: &[u8],
    data: Data<'_>,
) -> Result<Vec<u8>, BlockError> {
    admit(flags, cdb, &data)?;
    engine.command(lun, cdb, data)
}

/// The enclosure's quirks take `cdb` and its transfer.
fn admit(flags: quirks::Flags, cdb: &[u8], data: &Data<'_>) -> Result<(), BlockError> {
    if !flags.permits(cdb) {
        return Err(BlockError::Unsupported(
            "CDB requires an unsupported enclosure operation",
        ));
    }
    let length = match data {
        Data::None => 0,
        Data::In(bytes) => *bytes,
        Data::Out(bytes) => bytes.len(),
    };
    if length > flags.max_transfer_bytes() {
        return Err(BlockError::Unsupported("UAS enclosure transfer limit"));
    }
    Ok(())
}

/// Linux `sd_read_block_zero` uses READ(10) when the ordinary block path uses
/// ten-byte CDBs. Stela propagates failure rather than querying mode pages after
/// uncertain transport/media change. No retry, write, or data publication occurs.
fn read_block_zero<I: Io>(
    engine: &mut Engine<I>,
    flags: quirks::Flags,
    lun: [u8; 8],
    block_size: usize,
) -> Result<(), BlockError> {
    if block_size < 512 || !block_size.is_power_of_two() || block_size > MAX_TD {
        return Err(BlockError::Unsupported("UAS block-zero probe geometry"));
    }
    let mut cdb = [0; 10];
    cdb[0] = super::scsi::READ_10;
    cdb[8] = 1;
    let bytes = execute(engine, flags, lun, &cdb, Data::In(block_size))?;
    if bytes.len() != block_size {
        return Err(BlockError::Protocol("short UAS block-zero probe"));
    }
    Ok(())
}

trait Io {
    type Ticket;
    fn ready(&mut self) -> Result<(), BlockError>;
    /// Whether the host controller sends the handoff's completion signal.
    fn signals(&self) -> bool {
        false
    }
    /// Whether a submitted transfer may have completed; a look at memory.
    fn posted(&self) -> bool {
        false
    }
    fn streams(&self) -> Option<u16> {
        None
    }
    fn submit(
        &mut self,
        pipe: Pipe,
        tag: u16,
        address: u64,
        length: usize,
    ) -> Result<Self::Ticket, BlockError>;
    fn completed(&mut self, ticket: &Self::Ticket) -> Option<Result<usize, BlockError>>;
    fn cancel(&mut self, pipe: Pipe) -> Result<(), BlockError>;
    fn now(&self) -> u64;
    fn pause(&self);
}
struct Native {
    controller: Shared,
    id: super::super::xhci::SlotId,
    endpoints: [Endpoint; 4],
    streams: Option<u16>,
}
enum NativeTicket {
    Ordinary { pipe: Pipe, trb: u64, length: usize },
    Stream(super::super::xhci::StreamTransfer),
}
impl Io for Native {
    type Ticket = NativeTicket;
    fn signals(&self) -> bool {
        self.controller
            .try_borrow()
            .is_ok_and(|controller| controller.signals())
    }
    fn posted(&self) -> bool {
        self.controller
            .try_borrow()
            .is_ok_and(|controller| controller.posted_for(self.id))
    }
    fn ready(&mut self) -> Result<(), BlockError> {
        let [command, status, input, output] = self.endpoints;
        self.controller
            .borrow_mut()
            .device(self.id)?
            .endpoints_ready(&[1, command.dci(), status.dci(), input.dci(), output.dci()])
    }
    fn streams(&self) -> Option<u16> {
        self.streams
    }
    fn submit(
        &mut self,
        pipe: Pipe,
        tag: u16,
        address: u64,
        length: usize,
    ) -> Result<NativeTicket, BlockError> {
        let dci = self.endpoints[pipe.index()].dci();
        let mut controller = self.controller.borrow_mut();
        let mut device = controller.device(self.id)?;
        if self.streams.is_some() && pipe != Pipe::Command {
            device
                .submit_stream(dci, tag, address, length)
                .map(NativeTicket::Stream)
        } else {
            device
                .submit(dci, address, length)
                .map(|trb| NativeTicket::Ordinary { pipe, trb, length })
        }
    }
    fn completed(&mut self, ticket: &NativeTicket) -> Option<Result<usize, BlockError>> {
        let mut controller = self.controller.borrow_mut();
        let mut device = match controller.device(self.id) {
            Ok(device) => device,
            Err(error) => return Some(Err(error)),
        };
        match ticket {
            NativeTicket::Stream(ticket) => device.completed_stream(ticket),
            NativeTicket::Ordinary { pipe, trb, length } => {
                device.completed(self.endpoints[pipe.index()].dci(), *trb, *length)
            }
        }
    }
    fn cancel(&mut self, pipe: Pipe) -> Result<(), BlockError> {
        self.controller
            .borrow_mut()
            .device(self.id)?
            .cancel(self.endpoints[pipe.index()].dci())
    }
    fn now(&self) -> u64 {
        self.controller.borrow().clock.now_us()
    }
    fn pause(&self) {
        let clock = self.controller.borrow().clock;
        clock.delay(1);
    }
}

/// A unique allocation can move only after acknowledged device retirement.
/// Empty slots belong to permanently poisoned old engines, never dummy buffers.
struct TransportBuffer(Option<DmaBuffer>);
impl TransportBuffer {
    fn new(buffer: DmaBuffer) -> Self {
        Self(Some(buffer))
    }
    fn present(&self) -> bool {
        self.0.is_some()
    }
    fn transfer(&mut self) -> Self {
        Self(Some(self.0.take().expect("retained UAS DMA owner")))
    }
}
impl core::ops::Deref for TransportBuffer {
    type Target = DmaBuffer;
    fn deref(&self) -> &DmaBuffer {
        self.0.as_ref().expect("retained UAS DMA owner")
    }
}
impl core::ops::DerefMut for TransportBuffer {
    fn deref_mut(&mut self) -> &mut DmaBuffer {
        self.0.as_mut().expect("retained UAS DMA owner")
    }
}

/// One command's tag and buffers: its Command and Status IUs and its data.
/// A lane takes a new command only once each of its transfers completed or
/// was cancelled with acknowledgment.
struct Lane<T> {
    command: TransportBuffer,
    status: TransportBuffer,
    data: TransportBuffer,
    pending: [Option<T>; 4],
    touched: [bool; 4],
    tag: u16,
    /// The begun command, until [`Engine::poll`] returns its result.
    active: Option<Active>,
}
impl<T> Lane<T> {
    fn new(dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Ok(Self {
            command: TransportBuffer::new(dma.allocate(IU_BUFFER_BYTES, IU_BUFFER_BYTES)?),
            status: TransportBuffer::new(dma.allocate(IU_BUFFER_BYTES, IU_BUFFER_BYTES)?),
            data: TransportBuffer::new(dma.allocate(MAX_TD, MAX_TD)?),
            pending: core::array::from_fn(|_| None),
            touched: [false; 4],
            tag: 0,
            active: None,
        })
    }
    fn present(&self) -> bool {
        self.command.present() && self.status.present() && self.data.present()
    }
    /// Move this lane's buffers, cleared, to a fresh engine.
    fn transfer<U>(&mut self) -> Lane<U> {
        let mut lane = Lane {
            command: self.command.transfer(),
            status: self.status.transfer(),
            data: self.data.transfer(),
            pending: core::array::from_fn(|_| None),
            touched: [false; 4],
            tag: 0,
            active: None,
        };
        lane.command.bytes_mut().fill(0);
        lane.status.bytes_mut().fill(0);
        lane.data.bytes_mut().fill(0);
        lane
    }
    fn idle(&self) -> bool {
        self.active.is_none() && self.pending.iter().all(Option::is_none)
    }
    /// The command ended with a failing status, and some transfer of it
    /// still waits for its cancellation.
    fn draining(&self) -> bool {
        self.active.as_ref().is_some_and(Active::failed) && self.pending.iter().any(Option::is_some)
    }
}

struct Engine<I: Io> {
    io: I,
    lanes: Vec<Lane<I::Ticket>>,
    poisoned: bool,
    /// Input data that completed before the Sense IU failed its command,
    /// until the next command: sd keeps it when the sense is RECOVERED
    /// ERROR.
    failed_data: Option<Vec<u8>>,
}
impl<I: Io> Engine<I> {
    fn new(mut io: I, dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        if io.streams() == Some(0) {
            return Err(BlockError::Unsupported("UAS has no usable stream IDs"));
        }
        io.ready()?;
        let depth = queue_depth(io.streams());
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(depth)
            .map_err(|_| BlockError::NoDmaMemory)?;
        for _ in 0..depth {
            lanes.push(Lane::new(dma)?);
        }
        Ok(Self {
            io,
            lanes,
            poisoned: false,
            failed_data: None,
        })
    }
    fn buffers_present(&self) -> bool {
        self.lanes.iter().all(Lane::present)
    }
    /// The lanes this attachment's stream IDs give tags to.
    fn usable(&self) -> usize {
        self.lanes.len().min(queue_depth(self.io.streams()))
    }
    fn draining(&self) -> bool {
        self.lanes.iter().any(Lane::draining)
    }
    fn busy(&self) -> bool {
        self.lanes.iter().any(|lane| lane.active.is_some())
    }
    /// A lane for the next command. None while a failed command waits for
    /// the others to leave the pipes it must cancel, so that new commands
    /// cannot keep it waiting.
    fn free_lane(&self) -> Option<usize> {
        if self.draining() {
            return None;
        }
        self.lanes[..self.usable()].iter().position(Lane::idle)
    }
    fn room(&self) -> bool {
        self.poisoned || !self.buffers_present() || self.free_lane().is_some()
    }
    fn post(
        &mut self,
        lane: usize,
        pipe: Pipe,
        address: u64,
        length: usize,
    ) -> Result<(), BlockError> {
        let index = pipe.index();
        if self.lanes[lane].pending[index].is_some() {
            return Err(BlockError::Unsupported(
                "UAS pipe already has a pending transfer",
            ));
        }
        // A failed submit may have published a TD before losing its receipt.
        // Include it in terminal cancellation even without a returned ticket.
        self.lanes[lane].touched[index] = true;
        let tag = self.lanes[lane].tag;
        let ticket = self.io.submit(pipe, tag, address, length)?;
        self.lanes[lane].pending[index] = Some(ticket);
        Ok(())
    }
    /// A transport failure ends every command: each pipe any lane used is
    /// cancelled, which retires every lane's transfers on it, and nothing
    /// is submitted again until the device is reset and rebound, as Linux's
    /// SCSI error handling ends a uas host's commands with a device reset.
    fn failure<T>(&mut self, error: BlockError) -> Result<T, BlockError> {
        self.poisoned = true;
        for pipe in [Pipe::Command, Pipe::Status, Pipe::Input, Pipe::Output] {
            if self.lanes.iter().any(|lane| lane.touched[pipe.index()]) {
                // Keep the owner and all allocations even on cancellation
                // failure. There is no successful-looking tag reuse afterward.
                let _ = self.io.cancel(pipe);
            }
        }
        Err(error)
    }
    fn command(&mut self, lun: [u8; 8], cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        self.command_inner(lun, cdb, data, None, &mut None)
    }
    fn command_inner(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        data: Data<'_>,
        abort_timeout: Option<u64>,
        abort: &mut Option<AbortTaskOutcome>,
    ) -> Result<Vec<u8>, BlockError> {
        let (lane, received) = self.wait(lun, cdb, data, abort_timeout, abort)?;
        Ok(self.received_data(lane, received).to_vec())
    }
    fn read_into(&mut self, lun: [u8; 8], cdb: &[u8], output: &mut [u8]) -> Result<(), BlockError> {
        // The caller's slice stays on the stack. Only a retired command
        // with successful status can give the CPU its received data.
        let (lane, received) = self.wait(lun, cdb, Data::In(output.len()), None, &mut None)?;
        copy_read(output, self.received_data(lane, received))
    }
    fn received_data(&self, lane: usize, received: Option<usize>) -> &[u8] {
        received.map_or(&[], |bytes| &self.lanes[lane].data.bytes()[..bytes])
    }
    fn wait(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        data: Data<'_>,
        abort_timeout: Option<u64>,
        abort: &mut Option<AbortTaskOutcome>,
    ) -> Result<(usize, Option<usize>), BlockError> {
        let lane = self.begin(lun, cdb, data)?;
        loop {
            if let Some(result) = self.poll_completion(lane, abort_timeout, abort) {
                return result.map(|received| (lane, received));
            }
            self.io.pause();
        }
    }
    /// Post `cdb`'s status, data and command requests in a free lane
    /// without waiting for any of them; [`Self::poll`] moves the command on
    /// by the returned lane.
    fn begin(&mut self, lun: [u8; 8], cdb: &[u8], data: Data<'_>) -> Result<usize, BlockError> {
        if self.poisoned || !self.buffers_present() {
            return Err(BlockError::Unsupported("UAS interface requires rebind"));
        }
        let Some(lane) = self.free_lane() else {
            return Err(BlockError::Protocol("every UAS command tag is in use"));
        };
        let (length, input) = match &data {
            Data::None => (0, false),
            Data::In(n) => (*n, true),
            Data::Out(b) => (b.len(), false),
        };
        if cdb.is_empty() || cdb.len() > MAX_CDB || length > MAX_TD {
            return Err(BlockError::Unsupported("UAS CDB or transfer length"));
        }
        // Readiness can fail because topology retirement, a controller fault,
        // or an earlier endpoint error invalidated this attachment. Fence the
        // entire class owner before media code observes the failure. No DMA
        // buffer may be rewritten and no later command may reuse this epoch.
        self.lanes[lane].touched = [false; 4];
        if let Err(error) = self.io.ready() {
            return self.failure(error);
        }
        let streams = self.io.streams();
        let tag = if self.usable() == 1 {
            // One command at a time takes each tag in turn.
            let maximum = streams.unwrap_or(u16::MAX);
            let last = self.lanes[lane].tag;
            if last >= maximum { 1 } else { last + 1 }
        } else {
            // Linux `uas_queuecommand_lck`: the uas tag is the stream ID,
            // the lane's own; a command takes the lowest free one.
            lane as u16 + 1
        };
        let command = command_iu(tag, lun, cdb);
        let slot = &mut self.lanes[lane];
        slot.tag = tag;
        slot.command.bytes_mut()[..command.len()].copy_from_slice(&command);
        slot.status.bytes_mut().fill(0);
        if let Data::Out(bytes) = data {
            slot.data.bytes_mut()[..length].copy_from_slice(bytes);
        }
        slot.touched = [false; 4];
        let (status, data) = (slot.status.physical(), slot.data.physical());
        let command_address = slot.command.physical();
        if let Err(error) = self.post(lane, Pipe::Status, status, IU_BUFFER_BYTES) {
            return self.failure(error);
        }
        // USB3 has no READY handshake. Queue the stream-owned status
        // and data requests before publishing the ordinary command IU.
        if streams.is_some()
            && length != 0
            && let Err(error) = self.post(
                lane,
                if input { Pipe::Input } else { Pipe::Output },
                data,
                length,
            )
        {
            return self.failure(error);
        }
        if let Err(error) = self.post(lane, Pipe::Command, command_address, command.len()) {
            return self.failure(error);
        }
        self.lanes[lane].active = Some(Active {
            lun,
            command: command.len(),
            length,
            input,
            streams,
            started: self.io.now(),
            ready: false,
            moved: if length == 0 { Some(0) } else { None },
            terminal: None,
        });
        Ok(lane)
    }
    /// Lane `lane`'s command result once it ended, failed or timed out;
    /// never waits. `abort_timeout` replaces the command timeout with one
    /// that aborts the task, as error handling's ABORT TASK does.
    fn poll(
        &mut self,
        lane: usize,
        abort_timeout: Option<u64>,
        abort: &mut Option<AbortTaskOutcome>,
    ) -> Option<Result<Vec<u8>, BlockError>> {
        self.poll_completion(lane, abort_timeout, abort)
            .map(|result| result.map(|received| self.received_data(lane, received).to_vec()))
    }
    /// The byte count of a retired successful input command. Writes and
    /// no-data commands have no input to expose.
    fn poll_completion(
        &mut self,
        lane: usize,
        abort_timeout: Option<u64>,
        abort: &mut Option<AbortTaskOutcome>,
    ) -> Option<Result<Option<usize>, BlockError>> {
        let slot = self.lanes.get_mut(lane)?;
        let mut active = slot.active.take()?;
        // Another lane's transport failure cancelled this one's transfers
        // too: only a command that had already completed keeps its result.
        let complete = active
            .terminal
            .as_ref()
            .is_some_and(|status| status.code == 0)
            && slot.pending.iter().all(Option::is_none);
        if self.poisoned && !complete {
            return Some(Err(BlockError::Unsupported(
                "UAS interface requires rebind",
            )));
        }
        let result = self.advance(lane, &mut active, abort_timeout, abort);
        if result.is_none() {
            self.lanes[lane].active = Some(active);
        }
        result
    }
    /// Whether every lane with a transfer still on `pipe`, `lane` among
    /// them, has failed with status: its cancellation then retires none
    /// that may still complete.
    fn only_failed_on(&self, pipe: Pipe, lane: usize) -> bool {
        self.lanes.iter().enumerate().all(|(index, other)| {
            index == lane
                || other.pending[pipe.index()].is_none()
                || other.active.as_ref().is_some_and(Active::failed)
        })
    }
    fn advance(
        &mut self,
        lane: usize,
        active: &mut Active,
        abort_timeout: Option<u64>,
        abort: &mut Option<AbortTaskOutcome>,
    ) -> Option<Result<Option<usize>, BlockError>> {
        let (length, input, streams) = (active.length, active.input, active.streams);
        for pipe in [Pipe::Command, Pipe::Status, Pipe::Input, Pipe::Output] {
            let index = pipe.index();
            let completion = self.lanes[lane].pending[index]
                .as_ref()
                .and_then(|ticket| self.io.completed(ticket));
            let Some(completion) = completion else {
                continue;
            };
            self.lanes[lane].pending[index] = None;
            let count = match completion {
                Ok(count) => count,
                Err(error) => return Some(self.failure(error)),
            };
            match pipe {
                Pipe::Command if count != active.command => {
                    return Some(self.failure(PROTOCOL_ERROR));
                }
                Pipe::Command => {}
                Pipe::Input | Pipe::Output if count <= length => active.moved = Some(count),
                Pipe::Input | Pipe::Output => {
                    return Some(self.failure(PROTOCOL_ERROR));
                }
                Pipe::Status => {
                    let slot = &self.lanes[lane];
                    let frame = match slot
                        .status
                        .bytes()
                        .get(..count)
                        .and_then(|bytes| status_iu(bytes, slot.tag))
                    {
                        Some(frame) => frame,
                        None => {
                            return Some(self.failure(PROTOCOL_ERROR));
                        }
                    };
                    match frame {
                        Frame::Ready(direction)
                            if streams.is_none()
                                && !active.ready
                                && length != 0
                                && direction == input =>
                        {
                            active.ready = true;
                            let (status, data) = (slot.status.physical(), slot.data.physical());
                            // Repost the status request before data; a fast
                            // device may finish its CDB as soon as data ends.
                            if let Err(error) =
                                self.post(lane, Pipe::Status, status, IU_BUFFER_BYTES)
                            {
                                return Some(self.failure(error));
                            }
                            if let Err(error) = self.post(
                                lane,
                                if input { Pipe::Input } else { Pipe::Output },
                                data,
                                length,
                            ) {
                                return Some(self.failure(error));
                            }
                        }
                        Frame::Ready(_) => {
                            return Some(self.failure(PROTOCOL_ERROR));
                        }
                        Frame::Done(status) => active.terminal = Some(status),
                    }
                }
            }
        }
        if let Some(status) = &active.terminal {
            if status.code != 0 {
                let slot = &self.lanes[lane];
                if input && slot.pending[Pipe::Input.index()].is_none() {
                    self.failed_data = active
                        .moved
                        .map(|moved| slot.data.bytes()[..moved].to_vec());
                }
                // Device-terminal error may precede host data completion.
                // Drain each outstanding contributor before any CPU buffer
                // access or later command is permitted. A pipe's cancellation
                // retires every lane's transfer on it, so it waits until the
                // others there have completed (Linux unlinks the one URB).
                for pipe in [Pipe::Command, Pipe::Input, Pipe::Output] {
                    if self.lanes[lane].pending[pipe.index()].is_some()
                        && self.only_failed_on(pipe, lane)
                    {
                        if let Err(error) = self.io.cancel(pipe) {
                            return Some(self.failure(error));
                        }
                        for (index, other) in self.lanes.iter_mut().enumerate() {
                            if index == lane || other.active.as_ref().is_some_and(Active::failed) {
                                other.pending[pipe.index()] = None;
                            }
                        }
                    }
                }
                if self.lanes[lane].pending.iter().all(Option::is_none) {
                    return Some(Err(match status.response {
                        Some(_) => BlockError::Protocol("UAS Response IU refused the command"),
                        None => Sense::parse(&status.sense)
                            .map_or(BlockError::CheckCondition, BlockError::Sense),
                    }));
                }
            } else if self.lanes[lane].pending.iter().all(Option::is_none) {
                let Some(moved) = active.moved else {
                    return Some(self.failure(PROTOCOL_ERROR));
                };
                if !input && moved != length {
                    return Some(Err(BlockError::Protocol("short UAS write")));
                }
                return Some(Ok(input.then_some(moved)));
            }
        }
        if self.io.now().wrapping_sub(active.started) >= abort_timeout.unwrap_or(TIMEOUT_US) {
            if abort_timeout.is_some() {
                // This task and both IU buffers remain owned throughout
                // recovery. No later command may reuse this attachment.
                self.poisoned = true;
                *abort = Some(if active.terminal.is_some() {
                    AbortTaskOutcome::NotAcknowledged(BlockError::Unsupported(
                        "UAS task already returned terminal status",
                    ))
                } else {
                    self.abort_task(lane, active.lun)
                });
                return Some(Err(BlockError::Timeout));
            }
            return Some(self.failure(BlockError::Timeout));
        }
        None
    }
}

/// A begun command: what [`Engine::poll`] has seen of it so far.
struct Active {
    lun: [u8; 8],
    /// The Command IU's bytes.
    command: usize,
    length: usize,
    input: bool,
    streams: Option<u16>,
    started: u64,
    /// The READ or WRITE READY handshake arrived.
    ready: bool,
    moved: Option<usize>,
    terminal: Option<Status>,
}
impl Active {
    /// The command ended with a failing status.
    fn failed(&self) -> bool {
        self.terminal
            .as_ref()
            .is_some_and(|status| status.code != 0)
    }
}

fn command_iu(tag: u16, lun: [u8; 8], cdb: &[u8]) -> Vec<u8> {
    let extra = cdb.len().saturating_sub(16).next_multiple_of(4);
    let mut bytes = vec![0; 32 + extra];
    bytes[0] = COMMAND_IU;
    bytes[2..4].copy_from_slice(&tag.to_be_bytes());
    bytes[6] = extra as u8;
    bytes[8..16].copy_from_slice(&lun);
    bytes[16..16 + cdb.len()].copy_from_slice(cdb);
    bytes
}
struct Status {
    code: u8,
    sense: Vec<u8>,
    response: Option<u8>,
}
enum Frame {
    Ready(bool),
    Done(Status),
}
fn status_iu(bytes: &[u8], tag: u16) -> Option<Frame> {
    if bytes.len() < 4 || u16::from_be_bytes(bytes[2..4].try_into().ok()?) != tag {
        return None;
    }
    match bytes[0] {
        READ_READY_IU if bytes.len() == 4 => Some(Frame::Ready(true)),
        WRITE_READY_IU if bytes.len() == 4 => Some(Frame::Ready(false)),
        STATUS_IU if bytes.len() >= 16 => {
            // Like Linux uas_sense, a sense length that disagrees with the
            // transfer is clamped to the bytes that arrived.
            let length = usize::from(u16::from_be_bytes(bytes[14..16].try_into().ok()?));
            let end = bytes.len().min(16 + length);
            Some(Frame::Done(Status {
                code: bytes[6],
                sense: bytes[16..end].to_vec(),
                response: None,
            }))
        }
        RESPONSE_IU if bytes.len() == 8 => Some(Frame::Done(Status {
            code: if bytes[7] == 8 { 0 } else { 0xff },
            sense: Vec::new(),
            response: Some(bytes[7]),
        })),
        _ => None,
    }
}

#[cfg(test)]
mod tests;

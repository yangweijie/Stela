//! Opens the Metal service for one GPU through its [`GpuStack`]: admits its
//! Vulkan device, derives the platform facts Vulkan does not report, and
//! serves a [`Device`] over the backend and compiler. [`open`] composes the
//! native stack: the stack's Vulkan driver through [`NativeBackend`], which
//! builds its pipelines from the AIR compiler service's internal kernels, and
//! an [`AirCompiler`] for the device the driver reports.
#[cfg(feature = "metal-vulkan")]
use crate::metal::{
    compiler::{self, AirCompiler},
    native::{InternalKernels, Loader, MemoryExporter, NativeBackend, vk},
};
use crate::{
    metal::{
        capabilities::Platform,
        device::Device,
        error::Error,
        nvidia,
        service::{Service, identity::DeviceEpoch},
        shader::Compiler,
        vulkan::{
            backend::Backend,
            physical::{Identity, PciBusInfo},
        },
    },
    stack::GpuStack,
};
#[cfg(feature = "metal-vulkan")]
use alloc::boxed::Box;

/// The negotiated PCI Express link, from the Link Status register
/// (`PCI_EXP_LNKSTA`) of the GPU's PCIe capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcieLink {
    /// Current Link Speed: 1 for 2.5 GT/s through 6 for 64 GT/s.
    pub speed: u8,
    /// Negotiated Link Width in lanes.
    pub width: u8,
}

impl PcieLink {
    pub const fn from_link_status(status: u16) -> Self {
        Self {
            speed: (status & 0xf) as u8,
            width: ((status >> 4) & 0x3f) as u8,
        }
    }

    /// Data bandwidth in bytes per second after line encoding, as Linux's
    /// `PCIE_SPEED2MBS_ENC`: 8b/10b through 5 GT/s, 128b/130b from 8 GT/s,
    /// and FLIT mode at 64 GT/s. Unknown speeds report zero.
    pub const fn bytes_per_second(self) -> u64 {
        let megabits_per_lane: u64 = match self.speed {
            1 => 2500 * 8 / 10,
            2 => 5000 * 8 / 10,
            3 => 8000 * 128 / 130,
            4 => 16000 * 128 / 130,
            5 => 32000 * 128 / 130,
            6 => 64000,
            _ => 0,
        };
        megabits_per_lane * self.width as u64 * 1_000_000 / 8
    }
}

/// Where the GPU is attached, as the platform's PCI and ACPI owners report it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attachment {
    pub link: PcieLink,
    /// Behind a hot-pluggable Thunderbolt or USB4 tunnel.
    pub external: bool,
    /// The slot or enclosure index Metal reports as `locationNumber`.
    pub location_number: u64,
}

/// A stack's admission of its Vulkan device as a Metal device.
pub struct Admission {
    /// Admits the Vulkan device `identity` whose kernel driver reports the
    /// chip ([`crate::stack::Kernel::chip`]), and answers the facts Vulkan
    /// does not report for it.
    pub admit: fn(&Identity, u32, Attachment) -> Result<Platform, Refusal>,
}

/// Why a stack did not admit a Vulkan device, in its vendor's terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Nvidia(nvidia::Refusal),
}

/// The GPU the platform hands the Metal device.
#[derive(Clone, Copy)]
pub struct Gpu {
    pub stack: &'static GpuStack,
    pub pci: PciBusInfo,
    /// The kernel driver's identifier of the chip.
    pub chip: u32,
    pub attachment: Attachment,
}

/// Why the Metal service did not open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    /// The device is not one its stack drives.
    Refused(Refusal),
    /// The device lacks a requirement or could not be created.
    Device(Error),
}

impl From<Error> for OpenError {
    fn from(error: Error) -> Self {
        Self::Device(error)
    }
}

/// Serves the Metal device over `backend`, which drives `gpu`, and
/// `compiler`, in the gate's `epoch` for it.
pub fn serve<B: Backend, C: Compiler>(
    backend: B,
    compiler: C,
    gpu: &Gpu,
    epoch: DeviceEpoch,
) -> Result<Service<B, C>, OpenError> {
    Ok(Service::new(device(backend, compiler, gpu)?, epoch))
}

/// The Metal device over `backend`, once it is admitted as `gpu`.
fn device<B: Backend, C: Compiler>(
    backend: B,
    compiler: C,
    gpu: &Gpu,
) -> Result<Device<B, C>, OpenError> {
    let identity = &backend.physical_device().identity;
    if identity.pci_bus != Some(gpu.pci) {
        return Err(Error::Invalid("the backend drives another GPU").into());
    }
    let platform =
        (gpu.stack.metal.admit)(identity, gpu.chip, gpu.attachment).map_err(OpenError::Refused)?;
    Ok(Device::new(backend, compiler, &platform)?)
}

/// The Metal service over a linked Vulkan driver and the AIR compiler.
#[cfg(feature = "metal-vulkan")]
pub type NativeService = Service<NativeBackend, AirCompiler>;

/// A Vulkan driver's backend for `target`, with the AIR compiler over the
/// service `compiler` answers for its device.
///
/// # Safety
///
/// `loader` is the driver's entry point and `compiler` answers the AIR compiler
/// service with the driver's NIR options for the device it is given, both
/// outliving what this returns.
#[cfg(feature = "metal-vulkan")]
pub unsafe fn stack(
    loader: Loader,
    pci: PciBusInfo,
    exporter: Box<dyn MemoryExporter>,
    compiler: impl FnOnce(vk::PhysicalDevice) -> compiler::Service,
) -> Result<(NativeBackend, AirCompiler), Error> {
    let mut built = None;
    let kernels = |physical| {
        let service = compiler(physical);
        // SAFETY: the caller guarantees the service and its options.
        let kernels = unsafe { service.internal_kernels() }?;
        let [
            accumulate,
            select,
            resolve_draws,
            resolve_dispatches,
            store_texels,
            load_texels,
            average_samples,
            decode_etc,
            decode_pvrtc,
            reorder_blocks,
            decode_astc,
        ] = kernels.code();
        // The kernels last until the pipelines hold their own copies.
        built = Some((service, kernels));
        Ok(InternalKernels {
            accumulate,
            select,
            resolve_draws,
            resolve_dispatches,
            store_texels,
            load_texels,
            average_samples,
            decode_etc,
            decode_pvrtc,
            reorder_blocks,
            decode_astc,
        })
    };
    // SAFETY: the caller guarantees the entry point, and the kernels are the
    // service's NIR for the driver.
    let backend = unsafe { NativeBackend::new(loader, pci, exporter, kernels) }?;
    let Some((service, kernels)) = built else {
        return Err(Error::Invalid("the backend asked for no kernels"));
    };
    drop(kernels);
    // SAFETY: the caller guarantees the service and its options outlive it.
    let compiler = unsafe { AirCompiler::new(service, backend.physical_device()) };
    Ok((backend, compiler))
}

/// Opens the Vulkan driver's device for `gpu` and serves it with the AIR
/// compiler service `compiler` answers for that device.
///
/// # Safety
///
/// `loader` is the entry point of `gpu`'s stack's driver and `compiler`
/// answers the AIR compiler service with that driver's NIR options for the
/// device it is given, both outliving the service.
#[cfg(feature = "metal-vulkan")]
pub unsafe fn open(
    loader: Loader,
    exporter: Box<dyn MemoryExporter>,
    compiler: impl FnOnce(vk::PhysicalDevice) -> compiler::Service,
    gpu: &Gpu,
    epoch: DeviceEpoch,
) -> Result<NativeService, OpenError> {
    // SAFETY: the caller's guarantees.
    let (backend, compiler) = unsafe { stack(loader, gpu.pci, exporter, compiler) }?;
    serve(backend, compiler, gpu, epoch)
}

/// Opens the driver's device for `gpu` as [`open`] does, for a service whose device
/// was lost ([`Service::with_reopen`]).
///
/// # Safety
///
/// As for [`open`].
#[cfg(feature = "metal-vulkan")]
pub unsafe fn reopen(
    loader: Loader,
    exporter: Box<dyn MemoryExporter>,
    compiler: impl FnOnce(vk::PhysicalDevice) -> compiler::Service,
    gpu: &Gpu,
) -> Result<Device<NativeBackend, AirCompiler>, Error> {
    // SAFETY: the caller's guarantees.
    let (backend, compiler) = unsafe { stack(loader, gpu.pci, exporter, compiler) }?;
    device(backend, compiler, gpu).map_err(|error| match error {
        OpenError::Device(error) => error,
        OpenError::Refused(_) => Error::Invalid("the GPU was refused as it reopened"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::{
        device::fixture::{MockBackend, MockCompiler},
        nvidia::CHIPS,
        vulkan::DriverId,
    };
    use crate::stack::NVIDIA;
    use core::num::NonZeroU64;

    fn gpu(chipset: u16) -> Gpu {
        Gpu {
            stack: &NVIDIA,
            pci: PciBusInfo {
                domain: 0,
                bus: 1,
                device: 0,
                function: 0,
            },
            chip: chipset.into(),
            attachment: Attachment {
                link: PcieLink {
                    speed: 4,
                    width: 16,
                },
                external: true,
                location_number: 2,
            },
        }
    }

    fn serve_on(
        backend: MockBackend,
        gpu: &Gpu,
    ) -> Result<Service<MockBackend, MockCompiler>, OpenError> {
        let epoch = DeviceEpoch::from_registered(NonZeroU64::MIN);
        serve(backend, MockCompiler::default(), gpu, epoch)
    }

    #[test]
    fn an_admitted_gpu_is_served_with_its_platform() {
        let mut service = serve_on(MockBackend::new(), &gpu(CHIPS[0].chipset)).unwrap();
        let capabilities = service.device().capabilities();
        assert_eq!(capabilities.architecture, CHIPS[0].name);
        assert!(capabilities.removable);
        assert_eq!(capabilities.location_number, 2);
    }

    #[test]
    fn other_gpus_and_drivers_are_refused() {
        let mut other = gpu(CHIPS[0].chipset);
        other.pci.bus = 2;
        assert_eq!(
            serve_on(MockBackend::new(), &other).err(),
            Some(OpenError::Device(Error::Invalid(
                "the backend drives another GPU"
            )))
        );
        assert_eq!(
            serve_on(MockBackend::new(), &gpu(0x140)).err(),
            Some(OpenError::Refused(Refusal::Nvidia(
                nvidia::Refusal::PreTuring { chipset: 0x140 }
            )))
        );
        let mut backend = MockBackend::new();
        let physical = backend.physical.as_mut().unwrap();
        physical.identity.driver_id = DriverId::MesaRadv;
        assert_eq!(
            serve_on(backend, &gpu(CHIPS[0].chipset)).err(),
            Some(OpenError::Refused(Refusal::Nvidia(
                nvidia::Refusal::NotNvk(DriverId::MesaRadv)
            )))
        );
    }
}

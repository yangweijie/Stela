#[cfg(any(feature = "nouveau-port", feature = "xe-port"))]
#[path = "build/kbuild.rs"]
mod kbuild;
#[cfg(feature = "linux-kernel")]
#[path = "build/native.rs"]
mod native;
#[cfg(feature = "nouveau-port")]
#[path = "build/nouveau.rs"]
mod nouveau;
#[path = "build/nouveau_firmware.rs"]
mod nouveau_firmware;
#[cfg(feature = "xe-port")]
#[path = "build/xe.rs"]
mod xe;

fn main() {
    nouveau_firmware::validate();
    // Active ports declare their native source inputs below. Without this
    // baseline Cargo watches every vendored file even when no C port is used.
    println!("cargo:rerun-if-changed=build.rs");
    // Clippy reads Rust and links nothing, so it needs no C objects.
    println!("cargo:rerun-if-env-changed=CLIPPY_ARGS");
    #[cfg(feature = "linux-kernel")]
    if std::env::var_os("CLIPPY_ARGS").is_some() {
        let tests = stela_c_build::linux_build::Tests::default();
        tests.write();
        return;
    }
    #[cfg(feature = "linux-kernel")]
    let mut linux = native::Linux::new();
    #[cfg(feature = "linux-kernel")]
    let mut tests = stela_c_build::linux_build::Tests::default();
    #[cfg(feature = "linux-kernel")]
    linux.tests(&mut tests);
    #[cfg(feature = "nouveau-port")]
    nouveau::port(&mut linux);
    #[cfg(feature = "xe-port")]
    xe::port(&mut linux);
    #[cfg(feature = "linux-kernel")]
    tests.write();
}

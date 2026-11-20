//! GuC firmware backing reference.
//!
//! Reference only; no firmware binaries live here. The Stela xe driver
//! obtains GuC/HuC/DMC firmware from the USB `stela` firmware area, named
//! as `drivers/gpu/drm/xe/xe_uc_fw.c` looks them up. See the NOTICE entry
//! for this directory: Linux `cc9de5d4b5ab6459f5774946aa3195ad51236fa8`,
//! MIT, `drivers/gpu/drm/xe/xe_bo.c, drivers/gpu/drm/xe/xe_uc_fw.c`.

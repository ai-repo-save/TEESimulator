// C ABI for the native interceptor.
//
// The handle returned by `teesim_km_init` is an opaque pointer to a boxed `Ta`.
// Every entry point is wrapped in `catch_unwind` so a fault in the TA can never
// unwind across the FFI boundary into keystore2.

use crate::{Ta, TaConfig};
use kmr_wire::types::AttestationIdInfo;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

extern "C" {
    /// The one emitter every line in the module goes through, C++ and Rust alike
    /// (common/log_context.cpp). It stamps the subsystem and the request context and rate-limits a
    /// D/V flood — so the reference TA's own `trace!` cannot drown logd. There is no level floor:
    /// routing the Rust side through it is what makes one line shape rather than two, and what
    /// means the vendored TA's own tracing is never a second, ungated backend.
    fn teesim_log(prio: c_int, sub: *const c_char, fmt: *const c_char, ...);
}

// ANDROID_LOG_* priorities, as in <android/log.h>.
const PRIO_VERBOSE: c_int = 2;
const PRIO_DEBUG: c_int = 3;
const PRIO_INFO: c_int = 4;
const PRIO_WARN: c_int = 5;
const PRIO_ERROR: c_int = 6;
const PRIO_FATAL: c_int = 7;

/// Hand one already-formatted line to the shared emitter.
///
/// The message goes in as a `%s` argument rather than as the format string, so a certificate subject
/// or a package name can never be read as a conversion specifier.
fn emit(prio: c_int, sub: &str, msg: &str) {
    // A NUL inside either would truncate the C string silently; neither can legitimately contain one.
    let sub = sub.replace('\0', "?");
    let msg = msg.replace('\0', "?");
    let (Ok(sub), Ok(msg)) = (CString::new(sub), CString::new(msg)) else {
        return;
    };
    // SAFETY: both pointers are NUL-terminated and live for the duration of the call, and the format
    // string has exactly the one conversion the single argument supplies.
    unsafe { teesim_log(prio, sub.as_ptr(), b"%s\0".as_ptr().cast::<c_char>(), msg.as_ptr()) };
}

/// The subsystem token for a record, derived from its module path.
///
/// `teesim_km::resign` becomes `ta/resign` and the vendored `kmr_ta::…` becomes `ta/kmr_ta`, so the
/// reference TA's own lines are filterable apart from ours while both stay under the `ta` prefix.
fn subsystem(module_path: &str) -> String {
    let mut parts = module_path.split("::");
    match (parts.next(), parts.next()) {
        (Some("teesim_km"), Some(module)) => format!("ta/{module}"),
        (Some("teesim_km"), None) => "ta/km".to_string(),
        (Some(krate), _) if !krate.is_empty() => format!("ta/{krate}"),
        _ => "ta".to_string(),
    }
}

struct TeesimLogger;

impl log::Log for TeesimLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let prio = match record.level() {
            log::Level::Error => PRIO_ERROR,
            log::Level::Warn => PRIO_WARN,
            log::Level::Info => PRIO_INFO,
            log::Level::Debug => PRIO_DEBUG,
            log::Level::Trace => PRIO_VERBOSE,
        };
        let module = record.module_path().unwrap_or_default();
        let msg = record.args().to_string();
        // The reference TA prints the boot and HAL info it is handed at INFO, as Debug-formatted
        // byte arrays. "TA ready" states the same values once, in hex, so these drop to DEBUG.
        let prio = if prio == PRIO_INFO
            && module.starts_with("kmr_ta")
            && (msg.starts_with("Setting boot_info") || msg.starts_with("Setting hal_info"))
        {
            PRIO_DEBUG
        } else {
            prio
        };
        emit(prio, &subsystem(module), &msg);
    }

    fn flush(&self) {}
}

static LOGGER: TeesimLogger = TeesimLogger;

/// Install the logger and the panic hook. Idempotent; called by every entry point that can be the
/// first one reached.
fn init_logging() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = log::set_logger(&LOGGER);
        // No dial: every record this crate or the vendored reference TA produces reaches the
        // shared emitter, which is the only place volume gets reduced (its rate limiter), never
        // filtered by category. Set once, forever, at the most permissive level `log` has.
        log::set_max_level(log::LevelFilter::Trace);
        std::panic::set_hook(Box::new(|info| {
            // `log` has no Fatal, so a panic — the one thing here that really is fatal, unwinding
            // inside keystore2 — could only ever be logged as an error. Emit it at FATAL directly,
            // where `grep -E " [WEF] TEESimulator"` and the collector's crash handling both find it.
            emit(PRIO_FATAL, "ta", &format!("panic: {info}"));
        }));
    });
}

/// Copy `len` bytes at `ptr` into an owned buffer; empty for a null/zero span.
///
/// # Safety
/// If non-null, `ptr` must point to `len` readable bytes.
unsafe fn take_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(ptr, len).to_vec()
    }
}

/// Device-ID values passed to `teesim_km_init_ex`. Mirrors `TsDeviceIds` in
/// teesim_km.h field-for-field; each field is a `(ptr, len)` byte span.
#[repr(C)]
pub struct TsDeviceIds {
    pub brand: *const u8,
    pub brand_len: usize,
    pub device: *const u8,
    pub device_len: usize,
    pub product: *const u8,
    pub product_len: usize,
    pub serial: *const u8,
    pub serial_len: usize,
    pub imei: *const u8,
    pub imei_len: usize,
    pub imei2: *const u8,
    pub imei2_len: usize,
    pub meid: *const u8,
    pub meid_len: usize,
    pub manufacturer: *const u8,
    pub manufacturer_len: usize,
    pub model: *const u8,
    pub model_len: usize,
}

/// Create a TA from a keybox.xml byte buffer (UTF-8). Returns an opaque handle,
/// or null on failure.
///
/// # Safety
/// `keybox_ptr` must point to `keybox_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_init(keybox_ptr: *const u8, keybox_len: usize) -> *mut Ta {
    init_logging();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if keybox_ptr.is_null() {
            return None;
        }
        let bytes = slice::from_raw_parts(keybox_ptr, keybox_len);
        let xml = std::str::from_utf8(bytes).ok()?;
        match Ta::new(xml) {
            Ok(ta) => Some(Box::into_raw(Box::new(ta))),
            Err(e) => {
                log::error!("teesim_km_init: {e}");
                None
            }
        }
    }));
    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

/// Create a TA from a fully resolved profile configuration. See teesim_km.h for
/// the integer encodings. Returns an opaque handle, or null on failure.
///
/// # Safety
/// `keybox_ptr` must point to `keybox_len` readable bytes; `vb_key`/`vb_hash`
/// must each point to their stated length (or be null); if non-null, `ids` must
/// point to a valid `TsDeviceIds` whose spans are readable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn teesim_km_init_ex(
    keybox_ptr: *const u8,
    keybox_len: usize,
    security_level: i32,
    os_version: u32,
    os_patchlevel: u32,
    vendor_patchlevel: u32,
    boot_patchlevel: u32,
    vb_key: *const u8,
    vb_key_len: usize,
    vb_hash: *const u8,
    vb_hash_len: usize,
    device_locked: bool,
    verified_boot_state: i32,
    attest_version_tee: i32,
    attest_version_strongbox: i32,
    ids: *const TsDeviceIds,
) -> *mut Ta {
    init_logging();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if keybox_ptr.is_null() {
            return None;
        }
        let xml = std::str::from_utf8(slice::from_raw_parts(keybox_ptr, keybox_len)).ok()?;

        let attestation_ids = if ids.is_null() {
            None
        } else {
            let d = &*ids;
            let info = AttestationIdInfo {
                brand: take_bytes(d.brand, d.brand_len),
                device: take_bytes(d.device, d.device_len),
                product: take_bytes(d.product, d.product_len),
                serial: take_bytes(d.serial, d.serial_len),
                imei: take_bytes(d.imei, d.imei_len),
                imei2: take_bytes(d.imei2, d.imei2_len),
                meid: take_bytes(d.meid, d.meid_len),
                manufacturer: take_bytes(d.manufacturer, d.manufacturer_len),
                model: take_bytes(d.model, d.model_len),
            };
            // Only offer ID attestation when at least one value is present.
            let any = [
                &info.brand,
                &info.device,
                &info.product,
                &info.serial,
                &info.imei,
                &info.imei2,
                &info.meid,
                &info.manufacturer,
                &info.model,
            ]
            .iter()
            .any(|v| !v.is_empty());
            if any {
                Some(info)
            } else {
                None
            }
        };

        let cfg = TaConfig {
            keybox_xml: xml,
            security_level,
            os_version,
            os_patchlevel,
            vendor_patchlevel,
            boot_patchlevel,
            verified_boot_key: take_bytes(vb_key, vb_key_len),
            verified_boot_hash: take_bytes(vb_hash, vb_hash_len),
            device_boot_locked: device_locked,
            verified_boot_state,
            attest_version_tee,
            attest_version_strongbox,
            attestation_ids,
        };
        match Ta::new_ex(cfg) {
            Ok(ta) => Some(Box::into_raw(Box::new(ta))),
            Err(e) => {
                log::error!("teesim_km_init_ex: {e}");
                None
            }
        }
    }));
    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

/// Process one serialized kmr_wire request. On success writes a freshly allocated
/// buffer to `*out_ptr` / `*out_len` (free it with `teesim_km_free_buf`) and
/// returns 0; returns -1 on failure.
///
/// # Safety
/// `handle` must come from `teesim_km_init`; `req_ptr` must point to `req_len`
/// readable bytes; `out_ptr` and `out_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_process(
    handle: *mut Ta,
    req_ptr: *const u8,
    req_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || req_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let _lk = crate::lock_ta();
        let ta = &mut *handle;
        let req = slice::from_raw_parts(req_ptr, req_len);
        let rsp = ta.process(req);

        // into_boxed_slice gives capacity == len, so the matching free can
        // reconstruct the allocation exactly.
        let boxed = rsp.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        *out_ptr = ptr;
        *out_len = len;
        0
    }));
    result.unwrap_or(-1)
}

/// Free a buffer returned by `teesim_km_process`.
///
/// # Safety
/// `ptr`/`len` must be a buffer returned by `teesim_km_process` and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_free_buf(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Vec::from_raw_parts(ptr, len, len));
    }));
}

/// Destroy a TA handle.
///
/// # Safety
/// `handle` must come from `teesim_km_init` and not have been destroyed already.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_destroy(handle: *mut Ta) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // Serialize against any in-flight operation on this handle before freeing it.
        let _lk = crate::lock_ta();
        drop(Box::from_raw(handle));
    }));
}

/// True if `blob` was produced by this TA (has our routing marker).
///
/// # Safety
/// `blob_ptr` must point to `blob_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn teesim_km_is_marked(blob_ptr: *const u8, blob_len: usize) -> bool {
    if blob_ptr.is_null() {
        return false;
    }
    let blob = slice::from_raw_parts(blob_ptr, blob_len);
    crate::is_marked(blob)
}

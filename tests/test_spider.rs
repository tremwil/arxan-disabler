use std::{error::Error, time::Instant};

use arxan_disabler::spider;

#[cfg(feature = "ffi")]
#[test]
fn test_spider_ffi() -> Result<(), Box<dyn Error>> {
    use arxan_disabler::ffi;
    use std::{
        ffi::c_void,
        sync::atomic::{AtomicUsize, Ordering},
    };

    let program_bytes = std::fs::read("tests/bin/dsr_1.3.1_dump.bin")?;
    let now = Instant::now();

    static NUM_CHECKS: AtomicUsize = AtomicUsize::new(0);
    static NUM_FAILED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callback(_: *mut c_void, info: *const ffi::ArxanStubPatchInfo) {
        NUM_CHECKS.fetch_add(1, Ordering::Relaxed);

        let info = &*info;
        if !info.success {
            NUM_FAILED.fetch_add(1, Ordering::Relaxed);
            log::error!("Hook generation failed for {:016x}", info.hook_address);
            return;
        }
        let hook_code = std::slice::from_raw_parts(info.hook_code, info.hook_code_size);
        log::debug!("{hook_code:02x?}");
    }

    unsafe {
        ffi::find_arxan_stubs(program_bytes.as_ptr(), callback, std::ptr::null_mut());
    }

    log::info!("Analysis time (excluding disk ops): {:?}", now.elapsed());

    let (num_failed, num_checks) = (
        NUM_FAILED.load(Ordering::Relaxed),
        NUM_CHECKS.load(Ordering::Relaxed),
    );
    log::info!("{}/{} failed", num_failed, num_checks);

    (num_failed == 0)
        .then_some(())
        .ok_or("Failed to compute patch for all stubs".into())
}

#[test]
fn test_spider_rust() -> Result<(), Box<dyn Error>> {
    let program_bytes = std::fs::read("tests/bin/dsr_1.3.1_dump.bin")?;
    let now = Instant::now();

    let pe = pelite::pe64::PeView::from_bytes(&program_bytes)?;

    let mut num_checks = 0;
    let mut num_failed = 0;
    spider::find_arxan_stubs(pe, |hook_addr, patch| {
        num_checks += 1;
        if let Some(patch) = patch {
            // log::info!("{:016x} -> {:016x}", hook_addr, patch.exit_stub_addr);
            // log::info!("{:02x?}", &patch.stack_state);
            let _ = patch.assemble().inspect_err(|e| {
                num_failed += 1;
                log::error!("{}", e)
            });
        } else {
            num_failed += 1;
            log::error!("Hook generation failed for {:016x}", hook_addr);
        }
    });

    log::info!("Analysis time (excluding disk ops): {:?}", now.elapsed());
    log::info!("{}/{} failed", num_failed, num_checks);

    (num_failed == 0)
        .then_some(())
        .ok_or("Failed to compute patch for all stubs".into())
}

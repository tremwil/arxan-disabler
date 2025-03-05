use std::{error::Error, ffi::c_void, time::Instant};

use dsr_arxan_disabler::{find_arxan_stubs, ArxanStubPatchInfo};
use simplelog::*;

#[test]
fn test_all() -> Result<(), Box<dyn Error>> {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let program_bytes = std::fs::read("dsr_dump.bin")?;
    let now = Instant::now();

    unsafe extern "C" fn callback(_: *mut c_void, info: *const ArxanStubPatchInfo) {
        let info = &*info;

        if !info.success {
            log::error!("Hook generation failed for {:016x}", info.hook_address);
            return;
        }

        let hook_code = std::slice::from_raw_parts(info.hook_code, info.hook_code_size);
        log::debug!("{hook_code:02x?}");
    }

    unsafe {
        find_arxan_stubs(
            program_bytes.as_ptr(),
            program_bytes.len(),
            callback,
            std::ptr::null_mut(),
        );
    }

    log::info!("Analysis time (excluding disk ops): {:?}", now.elapsed());

    Ok(())
}

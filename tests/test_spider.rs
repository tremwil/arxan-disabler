use std::{env, error::Error, time::Instant};

use dotenv::dotenv;

use dsr_arxan_disabler::spider;
use simplelog::*;

#[cfg(feature = "ffi")]
#[test]
fn test_ffi() -> Result<(), Box<dyn Error>> {
    use dsr_arxan_disabler::ffi;
    use std::ffi::c_void;

    dotenv()?;

    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let program_bytes = std::fs::read(env::var("DUMP_PATH")?)?;
    let now = Instant::now();

    unsafe extern "C" fn callback(_: *mut c_void, info: *const ffi::ArxanStubPatchInfo) {
        let info = &*info;
        if !info.success {
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

    Ok(())
}

#[test]
fn test_rust() -> Result<(), Box<dyn Error>> {
    dotenv()?;

    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let program_bytes = std::fs::read(env::var("DUMP_PATH")?)?;
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

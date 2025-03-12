extern crate arxan_disabler;
extern crate windows;

use std::{ffi::OsString, fs::File, os::windows::ffi::OsStringExt, path::PathBuf};

use arxan_disabler::disabler::{
    game_specific::{DS3ArxanDisabler, DSRArxanDisabler},
    ArxanDisabler,
};
use windows::Win32::{
    Foundation::HMODULE,
    System::{
        Console::{AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS},
        LibraryLoader::{DisableThreadLibraryCalls, GetModuleFileNameW},
        SystemServices::DLL_PROCESS_ATTACH,
    },
};

unsafe fn disable_dsr() {
    log::info!("DSR detected");
    DSRArxanDisabler::disable(|| {
        log::info!("Patching hardcoded SteamAppId (pirate emoji)");
        std::env::set_var("SteamAppId", "480");
        let harcoded_appid_imm = 0x140137df8 as *mut u32;
        harcoded_appid_imm.write_unaligned(480);
    });
}

unsafe fn disable_ds3() {
    log::info!("DS3 detected");
    DS3ArxanDisabler::disable(|| log::info!("RIP Arxan"));
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    h_inst_dll: HMODULE,
    fdw_reason: u32,
    _lpv_reserved: *const (),
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(h_inst_dll.into()).ok();

        AttachConsole(ATTACH_PARENT_PROCESS)
            .or_else(|_| AllocConsole())
            .unwrap();

        simplelog::CombinedLogger::init(vec![
            simplelog::TermLogger::new(
                simplelog::LevelFilter::Debug,
                simplelog::Config::default(),
                simplelog::TerminalMode::Stdout,
                simplelog::ColorChoice::Auto,
            ),
            simplelog::WriteLogger::new(
                simplelog::LevelFilter::Trace,
                simplelog::Config::default(),
                File::options()
                    .write(true)
                    .truncate(true)
                    .open("arxan-disabler-dll.log")
                    .unwrap(),
            ),
        ])
        .unwrap();

        let mut name_buf = [0u16; 2048];
        let len = GetModuleFileNameW(None, &mut name_buf) as usize;
        assert!(len < name_buf.len(), "game file path too long");
        let game_path: PathBuf = OsString::from_wide(&name_buf[..len]).into();
        match game_path.file_stem().unwrap().to_string_lossy().as_ref() {
            "DarkSoulsRemastered" => disable_dsr(),
            "DarkSoulsIII" => disable_ds3(),
            other => panic!("{other} is not supported"),
        }
    }
    1
}

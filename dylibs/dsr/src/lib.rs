extern crate arxan_disabler;
extern crate windows;

use arxan_disabler::disabler::{dsr::DSRArxanDisabler, ArxanDisabler};
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{
        Console::{AttachConsole, ATTACH_PARENT_PROCESS},
        LibraryLoader::DisableThreadLibraryCalls,
        SystemServices::DLL_PROCESS_ATTACH,
    },
};

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    h_inst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *const (),
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(h_inst_dll.into()).ok();
        AttachConsole(ATTACH_PARENT_PROCESS).unwrap();
        simplelog::TermLogger::init(
            simplelog::LevelFilter::Debug,
            simplelog::Config::default(),
            simplelog::TerminalMode::Stdout,
            simplelog::ColorChoice::Auto,
        )
        .unwrap();

        std::env::set_var("SteamAppId", "480");
        DSRArxanDisabler::disable(|| {
            log::info!("Arxan disabled");

            log::info!("Patching hardcoded SteamAppId (pirate emoji)");
            let harcoded_appid_imm = 0x140137df8 as *mut u32;
            harcoded_appid_imm.write_unaligned(480);
        });
    }
    1
}

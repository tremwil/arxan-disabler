use std::{
    env::current_dir,
    error::Error,
    ffi::CString,
    os::windows::io::{FromRawHandle, OwnedHandle},
    path::PathBuf,
    ptr::null_mut,
    time::Duration,
};

use dll_syringe::{
    process::{OwnedProcess, Process},
    Syringe,
};
use windows::{
    core::PCSTR,
    Win32::{
        Security::SECURITY_ATTRIBUTES,
        System::{
            Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
            Threading::{
                CreateProcessA, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
                DETACHED_PROCESS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA,
            },
        },
    },
};

fn main() -> Result<(), Box<dyn Error>> {
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Debug,
        simplelog::Config::default(),
        simplelog::TerminalMode::Stdout,
        simplelog::ColorChoice::Auto,
    )
    .unwrap();

    std::process::Command::new("cargo")
        .args(["build", "--release", "-p", "arxan-disabler-dsr"])
        .output()?;

    let game_path = PathBuf::from(dotenvy_macro::dotenv!("LAUNCHER_GAME_PATH"));
    let game_path_cstr = CString::new(game_path.as_os_str().to_str().unwrap())?;

    let game_dir = game_path.parent().unwrap();
    let game_dir_cstr = CString::new(game_dir.as_os_str().to_str().unwrap())?;

    let dll_path = current_dir()?
        .join("target")
        .join("release")
        .join("arxan_disabler_dsr.dll");

    log::info!("Game path: {}", game_path.to_string_lossy());
    log::info!("DLL path: {}", dll_path.to_string_lossy());

    let mut startup = STARTUPINFOA::default();
    startup.cb = size_of::<STARTUPINFOA>().try_into()?;

    let mut proc_info = PROCESS_INFORMATION::default();

    let proc = unsafe {
        CreateProcessA(
            PCSTR(game_path_cstr.as_ptr() as *const _),
            None,
            None,
            None,
            true,
            CREATE_SUSPENDED,
            None,
            PCSTR(game_dir_cstr.as_ptr() as *const _),
            &startup,
            &mut proc_info,
        )?;

        let handle = OwnedHandle::from_raw_handle(proc_info.hProcess.0);
        OwnedProcess::from_handle_unchecked(handle).kill_on_drop()
    };

    log::info!("Created game process. PID = {}", proc_info.dwProcessId);
    log::info!("Injecting DLL");

    let syringe = Syringe::for_process(proc.try_clone()?);
    let _ = syringe.inject(dll_path)?;

    log::info!("DLL injected, resuming process. Output will appear below");

    unsafe {
        ResumeThread(proc_info.hThread);
        WaitForSingleObject(proc_info.hProcess, 100000000);
    }

    Ok(())
}

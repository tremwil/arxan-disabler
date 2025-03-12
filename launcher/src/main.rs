use std::{
    env::current_dir,
    error::Error,
    ffi::{CString, OsStr},
    os::windows::io::{FromRawHandle, OwnedHandle},
};

use clap::Parser;
use dll_syringe::{
    process::{OwnedProcess, Process},
    Syringe,
};
use walkdir::WalkDir;
use windows::{
    core::PCSTR,
    Win32::System::Threading::{
        CreateProcessA, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED, INFINITE,
        PROCESS_INFORMATION, STARTUPINFOA,
    },
};

const GAME_ALIASES: &[(&str, u32)] = &[
    ("dsr", 570940),
    ("ds3", 374320),
    ("sdt", 814380),
    ("er", 1245620),
    ("ac6", 1888160),
];

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[arg(
        value_name = "GAME | APPID",
        help = "Game to start and inject the arxan disabler into."
    )]
    game: String,

    /// Sets a custom config file
    #[arg(
        long,
        value_name = "APPID",
        help = "Optionally override the appid given to the game on launch."
    )]
    env_app_id: Option<u32>,
}

fn main() -> Result<(), Box<dyn Error>> {
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Debug,
        simplelog::Config::default(),
        simplelog::TerminalMode::Stdout,
        simplelog::ColorChoice::Auto,
    )?;

    let args = CliArgs::parse();
    let lowercase_game_name = args.game.to_lowercase();
    let game_app_id = GAME_ALIASES
        .iter()
        .find(|(str, _)| str == &lowercase_game_name)
        .map(|(_, id)| *id)
        .or_else(|| {
            log::info!("Shorthand name '{lowercase_game_name}' not recognized, assuming app id");
            u32::from_str_radix(&lowercase_game_name, 10).ok()
        })
        .ok_or(format!(
            "'{lowercase_game_name}' is not a valid shorthand name or app id",
        ))?;

    let (game_app, game_lib) = steamlocate::SteamDir::locate()?
        .find_app(game_app_id)?
        .ok_or(format!(
            "Game '{lowercase_game_name}' (app ID {game_app_id}) not found in local Steam libraries"
        ))?;

    // Don't match the EAC launcher
    let start_protected_game = Some(OsStr::new("start_protected_game"));
    let game_path = WalkDir::new(game_lib.resolve_app_dir(&game_app))
        .max_depth(2)
        .into_iter()
        .filter_map(|f| f.ok())
        .find(|f| {
            f.path().extension() == Some(OsStr::new("exe"))
                && f.path().file_stem() != start_protected_game
        })
        .ok_or("Failed to find game launcher")?
        .path()
        .to_owned();

    let game_dir = game_path.parent().unwrap();

    let game_path_cstr = CString::new(game_path.as_os_str().to_str().unwrap())?;
    let game_dir_cstr = CString::new(game_dir.as_os_str().to_str().unwrap())?;

    std::process::Command::new("cargo")
        .args(["build", "--release", "-p", "arxan-disabler-dll"])
        .status()?;

    let dll_path = current_dir()?
        .join("target")
        .join("release")
        .join("arxan_disabler_dll.dll");

    log::info!("Game path: {}", game_path.display());
    log::info!("DLL path: {}", dll_path.display());

    args.env_app_id.inspect(|id| {
        log::info!("Will override app ID with {}", id);
        std::env::set_var("SteamAppId", id.to_string());
    });

    let startup = STARTUPINFOA {
        cb: size_of::<STARTUPINFOA>().try_into()?,
        ..Default::default()
    };
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
        WaitForSingleObject(proc_info.hProcess, INFINITE);
    }

    Ok(())
}

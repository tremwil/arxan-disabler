use std::sync::{Mutex, OnceLock};
use std::{ffi::c_void, io::Write, ops::Range, sync::LazyLock};

use fxhash::FxHashSet;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
use pelite::pe::{Pe, PeObject};
use pelite::pe64::PeView;
use std::ptr::null;
use windows::core::PCSTR;
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::Memory::VirtualProtect;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{
        LibraryLoader::{DisableThreadLibraryCalls, GetModuleHandleA},
        Memory::{
            VirtualAlloc2, VirtualFree, MEM_ADDRESS_REQUIREMENTS, MEM_COMMIT,
            MEM_EXTENDED_PARAMETER, MEM_EXTENDED_PARAMETER_0, MEM_EXTENDED_PARAMETER_1,
            MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        SystemServices::DLL_PROCESS_ATTACH,
    },
};

use dsr_arxan_disabler::spider::find_arxan_stubs;

struct StaticContext {
    pe: PeView<'static>,
    base: u64,
    hook_buf: Mutex<CodeBuffer>,
    arxan_stub_call_imm_addr: u64,
    arxan_stub_imm32: i32,
    arxan_stub: unsafe extern "C" fn() -> (),
    called_stubs: Mutex<FxHashSet<u64>>,
}

static CONTEXT: LazyLock<StaticContext> = LazyLock::new(|| unsafe {
    let game_handle = GetModuleHandleA(PCSTR(null())).unwrap();
    let pe = PeView::module(game_handle.0 as *const _);
    let base = pe.optional_header().ImageBase;
    let hook_buf = CodeBuffer::new_near(0x1000000, pe.image().as_ptr_range(), 0x10000000).unwrap();

    let arxan_stub_call_imm_addr = base + pe.optional_header().AddressOfEntryPoint as u64 + 5;
    let arxan_stub_imm32 = (arxan_stub_call_imm_addr as *const i32).read_unaligned();
    let arxan_stub_addr =
        (arxan_stub_call_imm_addr + 4).wrapping_add_signed(arxan_stub_imm32 as i64);

    StaticContext {
        pe,
        base,
        hook_buf: Mutex::new(hook_buf),
        arxan_stub_call_imm_addr: arxan_stub_call_imm_addr,
        arxan_stub_imm32,
        arxan_stub: std::mem::transmute(arxan_stub_addr),
        called_stubs: Default::default(),
    }
});

unsafe extern "C" fn stub_log_cb(hook_addr: u64, rsp: u64) {
    if CONTEXT.called_stubs.lock().unwrap().insert(hook_addr) {
        log::info!("Stub for {hook_addr:016x} called | RSP = {rsp:016x}");
    }
}

unsafe extern "C" fn arxan_detour() {
    log::info!("Calling original arxan init stub...");

    let mut hook_buf = CONTEXT.hook_buf.lock().unwrap();
    (CONTEXT.arxan_stub_call_imm_addr as *mut i32).write_unaligned(CONTEXT.arxan_stub_imm32);
    (CONTEXT.arxan_stub)();

    log::info!("Patching hardcoded SteamAppId...");
    let harcoded_appid_imm = (CONTEXT.base + 0x137df8) as *mut u32;
    harcoded_appid_imm.write_unaligned(480);

    log::info!("Patching arxan check stubs...");

    find_arxan_stubs(CONTEXT.pe, |hook_addr, patch| {
        let log_stub_instructions = [
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::RSP).unwrap(),
            Instruction::with2(Code::And_rm64_imm8, Register::RSP, -0x10i64).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x30).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, hook_addr).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RSI).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, stub_log_cb as u64).unwrap(),
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::RSI).unwrap(),
        ];
        let mut code_bytes = BlockEncoder::encode(
            64,
            InstructionBlock::new(&log_stub_instructions, 0),
            BlockEncoderOptions::NONE,
        )
        .unwrap()
        .code_buffer;

        code_bytes.extend(patch.and_then(|p| p.assemble().ok()).unwrap());
        let hook = hook_buf.write(&code_bytes).unwrap().addr() as i64;
        let jmp_immediate: i32 = (hook - hook_addr as i64 - 5).try_into().unwrap();

        let mut to_patch = std::slice::from_raw_parts_mut(hook_addr as *mut u8, 5);
        to_patch.write(&[0xE9]).unwrap();
        to_patch.write(&jmp_immediate.to_le_bytes()).unwrap();

        log::debug!("Patched {:016x}", hook_addr);
    });
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    h_inst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *const (),
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(h_inst_dll.into()).ok();

        AllocConsole().unwrap();
        simplelog::TermLogger::init(
            simplelog::LevelFilter::Info,
            simplelog::Config::default(),
            simplelog::TerminalMode::Stdout,
            simplelog::ColorChoice::Auto,
        )
        .unwrap();

        log::info!("Making game image RWE");

        for section in CONTEXT.pe.section_headers() {
            let rva_range = section.virtual_range();
            let len = (rva_range.end - rva_range.start) as usize;

            let mut protect = Default::default();
            VirtualProtect(
                (CONTEXT.base + rva_range.start as u64) as *const _,
                len,
                PAGE_EXECUTE_READWRITE,
                &mut protect,
            )
            .unwrap();
        }

        log::info!("Detouring Arxan init stub");

        let mut thunk = b"\x48\xb8........\xff\xe0".to_owned();
        thunk[2..10].copy_from_slice(&(arxan_detour as usize).to_le_bytes());
        let thunk_ptr = CONTEXT.hook_buf.lock().unwrap().write(&thunk).unwrap();

        let imm_to_thunk: i32 = (thunk_ptr.addr() as i64)
            .wrapping_sub((CONTEXT.arxan_stub_call_imm_addr + 4) as i64)
            .try_into()
            .unwrap();
        (CONTEXT.arxan_stub_call_imm_addr as *mut i32).write_unaligned(imm_to_thunk);
    }
    1
}

struct CodeBuffer {
    alloc_base: *mut c_void,
    remaining: *mut [u8],
}

unsafe impl Send for CodeBuffer {}
unsafe impl Sync for CodeBuffer {}

impl CodeBuffer {
    pub fn new_near(size: usize, region: Range<*const u8>, min_dist: usize) -> Option<Self> {
        let region = region.start.addr()..region.end.addr();

        static ALLOC_GRANULARITY: LazyLock<usize> = LazyLock::new(|| {
            let mut sysinfo = SYSTEM_INFO::default();
            unsafe {
                GetSystemInfo(&mut sysinfo as *mut _);
            }
            sysinfo.dwAllocationGranularity as usize
        });
        let alloc_granularity = *ALLOC_GRANULARITY;

        let address_requirements = MEM_ADDRESS_REQUIREMENTS {
            LowestStartingAddress: {
                let minimum_unaligned = region.end.saturating_sub(min_dist);
                (minimum_unaligned + alloc_granularity - 1) & !(alloc_granularity - 1)
            } as *mut c_void,
            HighestEndingAddress: {
                let highest_unaligned = region.start.checked_add(min_dist)?;
                let highest_aligned =
                    (highest_unaligned & !(alloc_granularity - 1)).saturating_sub(1);
                highest_aligned.min((1 << 47) - 1) as *mut c_void
            },
            Alignment: 0,
        };

        let mut extended_params = [MEM_EXTENDED_PARAMETER {
            Anonymous1: MEM_EXTENDED_PARAMETER_0 { _bitfield: 1 },
            Anonymous2: MEM_EXTENDED_PARAMETER_1 {
                Pointer: &address_requirements as *const _ as *mut c_void,
            },
        }];

        let alloc_base = unsafe {
            VirtualAlloc2(
                None,
                None,
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE.0,
                Some(&mut extended_params),
            )
        };

        (!alloc_base.is_null()).then(|| Self {
            alloc_base,
            remaining: std::ptr::slice_from_raw_parts_mut(alloc_base as *mut u8, size),
        })
    }

    pub fn write(&mut self, code: &[u8]) -> std::io::Result<*const [u8]> {
        let current_ptr = self.remaining as *const u8;
        Write::write_all(self, code)
            .map(|_| std::ptr::slice_from_raw_parts(current_ptr, code.len()))
    }
}

impl Write for CodeBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut remaining = unsafe { &mut *self.remaining };
        remaining
            .write(buf)
            .inspect(|_| self.remaining = remaining as *mut _)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        Write::write(self, buf).map(|_| ())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for CodeBuffer {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.alloc_base, 0, MEM_RELEASE) }
            .inspect_err(|e| log::error!("VirtualFree failed: {e}"))
            .ok();
    }
}

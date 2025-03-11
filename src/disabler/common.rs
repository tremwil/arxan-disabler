use std::{
    io::Write,
    ptr::null,
    sync::{atomic::AtomicBool, LazyLock, Mutex},
};

use pelite::{
    pe::{Pe, PeObject},
    pe64::PeView,
};
use windows::{
    core::PCSTR,
    Win32::System::{
        LibraryLoader::GetModuleHandleA,
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE},
    },
};

#[cfg(feature = "disabler-debug")]
use fxhash::FxHashSet;
#[cfg(feature = "disabler-debug")]
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};

use crate::{patch::StubPatchInfo, spider::find_arxan_stubs};

use super::{call_hook::CallHook, code_buffer::CodeBuffer};

pub struct DisablerContext {
    pub pe: PeView<'static>,
    pub code_buffer: CodeBuffer,
    pub init_stub_hook: CallHook<unsafe extern "C" fn()>,
    pub post_disable_cb: Mutex<Option<Box<dyn FnMut() + Send + Sync>>>,
    pub disable_initiated: AtomicBool,

    // For logging purposes when in debug mode
    #[cfg(feature = "disabler-debug")]
    pub called_stubs: Mutex<FxHashSet<u64>>,
}

impl DisablerContext {
    pub unsafe fn find_and_patch(
        &self,
        mut stub_filter: impl FnMut(u64, Option<&StubPatchInfo>) -> bool,
    ) {
        find_arxan_stubs(self.pe, |hook_addr, patch| {
            if !stub_filter(hook_addr, patch.as_ref()) {
                return;
            }

            let encoded = patch.and_then(|p| p.assemble().ok()).expect(&format!(
                "Failed to create patch for stub at {:016x}",
                hook_addr
            ));

            #[cfg(feature = "disabler-debug")]
            let encoded: Vec<_> = Self::emit_log_call(hook_addr)
                .into_iter()
                .chain(encoded)
                .collect();

            let thunk = self.code_buffer.write(&encoded).unwrap().addr() as i64;
            let jmp_immediate: i32 = (thunk - hook_addr as i64 - 5).try_into().unwrap();
            let mut to_patch = unsafe { std::slice::from_raw_parts_mut(hook_addr as *mut u8, 5) };
            to_patch.write(&[0xE9]).unwrap();
            to_patch.write(&jmp_immediate.to_le_bytes()).unwrap();

            log::trace!("Patched arxan stub at {:016x}", hook_addr);
        });
    }

    #[cfg(feature = "disabler-debug")]
    unsafe extern "C" fn log_arxan_stub(hook_addr: u64, rsp: u64) {
        if DISABLER_CTX.called_stubs.lock().unwrap().insert(hook_addr) {
            log::trace!("Stub for {hook_addr:016x} called | RSP = {rsp:016x}");
        }
    }

    #[cfg(feature = "disabler-debug")]
    fn emit_log_call(hook_addr: u64) -> Vec<u8> {
        let log_stub_instructions = [
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::RSP).unwrap(),
            Instruction::with2(Code::And_rm64_imm8, Register::RSP, -0x10i64).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x30).unwrap(),
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, hook_addr).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RSI).unwrap(),
            Instruction::with2(
                Code::Mov_r64_imm64,
                Register::RAX,
                Self::log_arxan_stub as u64,
            )
            .unwrap(),
            Instruction::with1(Code::Call_rm64, Register::RAX).unwrap(),
            Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::RSI).unwrap(),
        ];
        BlockEncoder::encode(
            64,
            InstructionBlock::new(&log_stub_instructions, 0),
            BlockEncoderOptions::NONE,
        )
        .unwrap()
        .code_buffer
    }
}

pub static DISABLER_CTX: LazyLock<DisablerContext> = LazyLock::new(|| unsafe {
    let game_handle = GetModuleHandleA(PCSTR(null())).unwrap();
    let pe = PeView::module(game_handle.0 as *const _);

    // Entry point will look like this:
    // SUB rsp, 28
    // CALL arxan_init
    // ADD rsp, 28
    // JMP ...
    // We will call hook arxan_init.
    let init_stub_call = pe
        .image()
        .as_ptr()
        .add(pe.optional_header().AddressOfEntryPoint as usize + 4);

    DisablerContext {
        pe,
        code_buffer: CodeBuffer::alloc_near(pe.image(), 0x100_0000, 1 << 31).unwrap(),
        init_stub_hook: CallHook::new(init_stub_call as *mut _),
        post_disable_cb: Mutex::new(None),
        disable_initiated: AtomicBool::new(false),

        #[cfg(feature = "disabler-debug")]
        called_stubs: Default::default(),
    }
});

pub unsafe fn make_module_rwe(pe: PeView<'_>) {
    let base = pe.image().as_ptr().addr();
    for section in pe.section_headers() {
        let rva_range = section.virtual_range();
        let len = (rva_range.end - rva_range.start) as usize;

        let mut protect = Default::default();
        unsafe {
            VirtualProtect(
                (base + rva_range.start as usize) as *const _,
                len,
                PAGE_EXECUTE_READWRITE,
                &mut protect,
            )
            .unwrap();
        }
    }
}

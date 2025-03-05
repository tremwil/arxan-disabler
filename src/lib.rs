#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;

use iced_x86::{Mnemonic, Register};
use memchr::memmem;
use pelite::{
    pe::PeObject,
    pe64::{Pe, PeView},
};
use stub_patch::StubPatch;
use vm::{memory::MemoryStore, registers::Registers, ProgramState};

mod stub_patch;
pub mod vm;

#[derive(Debug)]
#[repr(C)]
pub struct ArxanStubPatchInfo {
    pub hook_address: u64,
    pub hook_code: *const u8,
    pub hook_code_size: usize,
    pub success: bool,
}

impl Default for ArxanStubPatchInfo {
    fn default() -> Self {
        Self {
            hook_address: 0,
            hook_code: std::ptr::dangling(),
            hook_code_size: 0,
            success: false,
        }
    }
}

pub type ArxanStubCallback = unsafe extern "C" fn(*mut c_void, *const ArxanStubPatchInfo);

#[no_mangle]
pub unsafe extern "C" fn find_arxan_stubs(
    image_base: *const u8,
    callback: ArxanStubCallback,
    user_context: *mut c_void,
) {
    const INIT_RSP: u64 = 1 << 46;
    const VOLATILE_REGS: &[Register] = &[
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ];

    let pe = unsafe { PeView::module(image_base) };
    let base = pe.optional_header().ImageBase;
    let test_rsp_rvas: Vec<_> =
        memmem::find_iter(pe.image(), b"\x48\xf7\xc4\x0f\x00\x00\x00").collect();

    for test_rsp_rva in test_rsp_rvas {
        let state = ProgramState {
            rip: Some(base + test_rsp_rva as u64),
            registers: Registers::new([(Register::RSP, INIT_RSP)]),
            memory: MemoryStore::new_initialized(pe, [(INIT_RSP, 0x10u64.to_le_bytes())]),
        };

        let mut patch = None;
        state.run(|step| {
            // don't follow any branches past depth 2 (ignore cmov or jxx paths)
            if patch.is_some() || step.past_forks.len() > 2 {
                step.state.rip = None;
                return Some(None);
            }
            // Don't follow unobfuscated calls
            if step.next_instruction.mnemonic() == Mnemonic::Call {
                step.state.rip = Some(step.next_instruction.next_ip());
                return Some(None);
            }

            // When rsp = INIT_RSP + 8, we got out of the stub
            if step.state.registers.rsp() == Some(INIT_RSP + 8) {
                let exit_stub_addr = step.state.rip.unwrap();
                let mut stack_state = Vec::new();
                step.state
                    .memory
                    .known_slices(INIT_RSP + 8, 0x200, |addr, slice| {
                        stack_state.push((addr - INIT_RSP, slice.to_owned()));
                    });

                patch = Some(StubPatch {
                    exit_stub_addr,
                    stack_state,
                });
                return Some(None);
            }

            // Process the instruction ourselves
            let maybe_fork = step
                .state
                .update_state(&step.next_instruction, step.info_factory);

            // If it jumps outside of the range, assume it was a function call and perform a return
            match (step.state.rip, step.state.registers.rsp_mut()) {
                (Some(rip), Some(rsp)) if rip.wrapping_sub(base) > pe.image().len() as u64 => {
                    step.state.rip = step.state.memory.read_int(*rsp, 8);
                    *rsp = rsp.wrapping_add(8);
                    // Clear volatile registers
                    for &r in VOLATILE_REGS {
                        *step.state.registers.gpr64_mut(r) = None;
                    }
                }
                _ => {}
            }

            Some(maybe_fork)
        });

        patch
            .and_then(|p| {
                let code = p.assemble().ok()?;
                let ffi_patch = ArxanStubPatchInfo {
                    hook_address: base + test_rsp_rva as u64,
                    hook_code: code.as_ptr(),
                    hook_code_size: code.len(),
                    success: true,
                };
                Some(unsafe { callback(user_context, &ffi_patch) })
            })
            .unwrap_or_else(|| unsafe { callback(user_context, &ArxanStubPatchInfo::default()) })
    }
}

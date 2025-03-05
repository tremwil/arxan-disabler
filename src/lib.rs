#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;

use iced_x86::{Mnemonic, Register};
use memchr::memmem;
use pelite::pe64::{Pe, PeView};
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
    image_size: usize,
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

    let pe_bytes = unsafe { std::slice::from_raw_parts(image_base, image_size) };
    let pe = PeView::from_bytes(pe_bytes).unwrap();
    let base = pe.optional_header().ImageBase;
    let test_rsp_rvas: Vec<_> =
        memmem::find_iter(&pe_bytes, b"\x48\xf7\xc4\x0f\x00\x00\x00").collect();

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
                let mut rsp_adjust = 0;
                step.state
                    .memory
                    .known_slices(INIT_RSP + 8, 0x200, |addr, slice| {
                        let offset = addr - INIT_RSP;
                        stack_state.push((offset, slice.to_owned()));
                        rsp_adjust = offset + slice.len() as u64;
                    });

                patch = Some(StubPatch {
                    exit_stub_addr,
                    rsp_adjust: rsp_adjust.try_into().unwrap(),
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
                (Some(rip), Some(rsp)) if rip.wrapping_sub(base) > pe_bytes.len() as u64 => {
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

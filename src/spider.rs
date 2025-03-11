use std::ops::ControlFlow;

use crate::patch::{ReturnGadgets, StubPatchInfo};
use crate::vm::{memory::MemoryStore, registers::Registers, ProgramState};
use crate::vm::{MaybeFork, RunStep};
use iced_x86::{Code, Mnemonic, Register};
use memchr::memmem;
use pelite::{
    pe::PeObject,
    pe64::{Pe, PeView},
};

const INIT_RSP: u64 = (1 << 46) + 8;
const VOLATILE_REGS: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

#[derive(Debug, Clone, Copy)]
enum SpiderState {
    Searching,
    GadgetsFound(ReturnGadgets),
    GadgetsValidated(ReturnGadgets),
}

struct Spider<'a> {
    pe: PeView<'a>,
    base: u64,
    hook_address: u64,
    init_rsp: u64,
    exit_stub_address: Option<u64>,
    found_gadgets_once: bool,
    state: SpiderState,
}

impl<'a> Spider<'a> {
    fn step(&mut self, step: RunStep<'a, '_>) -> Option<MaybeFork<'a>> {
        match self.state {
            SpiderState::Searching => self.searching(step),
            SpiderState::GadgetsFound(gadgets) => self.gadgets_found(gadgets, step),
            SpiderState::GadgetsValidated { .. } => Some(None),
        }
    }

    fn searching(&mut self, step: RunStep<'a, '_>) -> Option<MaybeFork<'a>> {
        // Only do first branch for unaligned stacks
        if (step.depth, step.past_forks.len()) == (1, 0) {
            step.state.rip = None;
            return Some(None);
        }
        if step.past_forks.len() > 4 || step.depth > 32 {
            step.state.rip = None;
            return Some(None);
        }
        // Don't follow unobfuscated calls
        else if step.next_instruction.mnemonic() == Mnemonic::Call {
            step.state.rip = Some(step.next_instruction.next_ip());
            return Some(None);
        }
        // When rsp = INIT_RSP + 8, we got to the exit stub
        else if step.state.registers.rsp() == Some(INIT_RSP + 8) {
            let address = step.state.rip.unwrap();
            match self.exit_stub_address.replace(address) {
                Some(diff) if diff != address => {
                    log::warn!("{:016x} Exit stub mismatch", self.hook_address)
                }
                _ => {}
            }

            let mut gadgets = [0; ReturnGadgets::GADGET_BYTES];
            if let Some(a) = step
                .state
                .memory
                .known_slices(INIT_RSP + 8, 0x200, |addr, _| ControlFlow::Break(addr))
                .break_value()
                .filter(|&a| step.state.memory.read(a, &mut gadgets).is_some())
            {
                self.found_gadgets_once = true;
                self.state = SpiderState::GadgetsFound(ReturnGadgets {
                    stack_offset: a - INIT_RSP,
                    bytes: gadgets,
                });
                return None;
            }
            step.state.rip = None;
            return Some(None);
        }

        // Process the instruction ourselves
        let maybe_fork = step
            .state
            .update_state(&step.next_instruction, step.info_factory);

        // If it jumps outside of the range, assume it was a function call and perform a return
        match (step.state.rip, step.state.registers.rsp_mut()) {
            (Some(rip), Some(rsp))
                if rip.wrapping_sub(self.base) > self.pe.image().len() as u64 =>
            {
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
    }

    fn gadgets_found(
        &mut self,
        gadgets: ReturnGadgets,
        step: RunStep<'a, '_>,
    ) -> Option<MaybeFork<'a>> {
        // Keep going until we hit an indirect jmp
        if step.next_instruction.code() == Code::Jmp_rm64 {
            // Check if jmp target address to read matches stack offset.
            // otherwise, go back to searching
            let expected = Some(self.init_rsp + gadgets.stack_offset);
            let actual = step.state.virtual_address(&step.next_instruction, 0);
            if actual == expected {
                self.state = SpiderState::GadgetsValidated(gadgets)
            } else {
                log::warn!("{:016x} stub validation failed", self.hook_address);
                log::warn!("Expected: {expected:016x?}, got: {actual:016x?}");
                log::warn!("{:x?}", gadgets);
                self.state = SpiderState::Searching
            }
            step.state.rip = None;
            return Some(None);
        }
        None
    }
}

pub fn find_arxan_stubs(pe: PeView<'_>, mut callback: impl FnMut(u64, Option<StubPatchInfo>)) {
    let base = pe.optional_header().ImageBase;

    // Search for TEST rsp, 15 instructions
    // These are extremely unlikely to be emitted by a compiler, but are present once at the
    // beginning of each Arxan stub
    for test_rsp_rva in memmem::find_iter(pe.image(), b"\x48\xf7\xc4\x0f\x00\x00\x00") {
        let hook_address = base + test_rsp_rva as u64;

        let state = ProgramState {
            rip: Some(hook_address),
            registers: Registers::new([(Register::RSP, INIT_RSP)]),
            memory: MemoryStore::new_initialized(pe, [(INIT_RSP, 0x10u64.to_le_bytes())]),
        };

        let mut spider = Spider {
            pe,
            base,
            hook_address,
            init_rsp: INIT_RSP,
            exit_stub_address: None,
            found_gadgets_once: false,
            state: SpiderState::Searching,
        };

        state.run(|step| spider.step(step));

        let patch = match spider.state {
            SpiderState::GadgetsValidated(g) => Some(StubPatchInfo {
                exit_stub_addr: spider.exit_stub_address.unwrap(),
                return_gadgets: Some(g),
            }),
            SpiderState::Searching
                if spider.exit_stub_address.is_some() && !spider.found_gadgets_once =>
            {
                Some(StubPatchInfo {
                    exit_stub_addr: spider.exit_stub_address.unwrap(),
                    return_gadgets: None,
                })
            }
            _ => None,
        };

        callback(hook_address, patch)
    }
}

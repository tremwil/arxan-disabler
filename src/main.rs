use byteorder::{ReadBytesExt, LE};
use memchr::memmem;
use pelite::pe::{Pe, PeView};
use std::error::Error;

use dsr_arxan_disabler::{arxan_visitor::arxan_visitor, StubPatchInfo};

use iced_x86::{Code, FastFormatter, FlowControl, OpKind, Register};

use dsr_arxan_disabler::StackMachineEntry;

fn main() -> Result<(), Box<dyn Error>> {
    let program_bytes = std::fs::read("dsr_dump.bin")?;
    // let text_sections: Vec<_> = pe.section_headers().iter()
    //     .filter(|s| s.name_bytes() == b".text")
    //     .collect();

    let pe = PeView::from_bytes(&program_bytes)?;
    let base = pe.optional_header().ImageBase;

    let test_rsp_rvas: Vec<_> =
        memmem::find_iter(&program_bytes, b"\x48\xf7\xc4\x0f\x00\x00\x00").collect();

    let mut formatter = FastFormatter::new();
    let mut output = String::new();

    for (i, &rva) in test_rsp_rvas.iter().enumerate() {
        let mut partial_exit_stub_ip = None;
        let mut expected_stack = Vec::new();
        let mut used_statics = vec![];

        #[derive(Default)]
        struct BasicBlockCtx {
            machine_entries: Vec<[u64; 2]>,
        }
        let mut basic_block = BasicBlockCtx::default();

        arxan_visitor(&pe, rva, |ins| {
            let mut flow_override = None;
            output.clear();
            formatter.format(ins, &mut output);

            match ins.code() {
                Code::Movupd_xmm_xmmm128
                    if ins.op1_kind() == OpKind::Memory && partial_exit_stub_ip.is_none() =>
                {
                    output.push_str(" EXIT STUB");
                    partial_exit_stub_ip = Some(ins.ip());
                    flow_override = Some(FlowControl::Interrupt);
                }
                Code::Mov_r64_rm64 if ins.is_ip_rel_memory_operand() => {
                    let static_val = pe
                        .read(ins.ip_rel_memory_address(), 8, 1)
                        .unwrap()
                        .read_u64::<LE>()
                        .unwrap();

                    output.push_str(&format!(" -> {:x}", static_val));
                    used_statics.push(static_val);
                }
                Code::Mov_rm64_r64
                    if ins.memory_index() != Register::None && used_statics.len() >= 2 =>
                {
                    let entry = *used_statics.last_chunk::<2>().unwrap();
                    basic_block.machine_entries.push(entry);

                    output.push_str(&format!(" ROP GADGET: {entry:x?}"));
                }
                _ => (),
            }

            if i >= 67 {
                println!("{:016x}   {}", ins.ip(), output);
            }

            if !matches!(
                ins.flow_control(),
                FlowControl::Next | FlowControl::UnconditionalBranch
            ) {
                if basic_block.machine_entries.len() >= 2 {
                    if !expected_stack.is_empty() {
                        println!("WARNING ({i}): multiple exit stack machine entries?!?!")
                    }

                    expected_stack.extend(basic_block.machine_entries.iter().map(
                        |&[offset, block_address]| StackMachineEntry {
                            offset,
                            block_address,
                        },
                    ));
                    output.push_str(" TO FUNCTION")
                }

                basic_block = BasicBlockCtx::default();
            }

            flow_override
        })?;

        let mut stub_info = StubPatchInfo {
            patch_address: base + rva as u64,
            partial_exit_stub_address: partial_exit_stub_ip.unwrap(),
            expected_stack_count: expected_stack.len() as u64,
            expected_stack: [StackMachineEntry::default(); 16],
        };
        stub_info.expected_stack[0..expected_stack.len()].copy_from_slice(&expected_stack);

        println!(
            "{i} {:08x} -> EXIT {:08x}, STACK {:x?}",
            rva,
            partial_exit_stub_ip.unwrap(),
            expected_stack
        );
    }

    Ok(())
}

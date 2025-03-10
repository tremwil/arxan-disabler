use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, IcedError, Instruction, InstructionBlock,
    MemoryOperand, Register,
};

#[derive(Debug, Clone, Copy)]
pub struct ReturnGadgets {
    pub stack_offset: u64,
    pub bytes: [u8; Self::GADGET_BYTES],
}
impl ReturnGadgets {
    pub const GADGET_BYTES: usize = 24;
}

#[derive(Debug)]
pub struct StubPatchInfo {
    pub exit_stub_addr: u64,
    pub return_gadgets: Option<ReturnGadgets>,
}

impl StubPatchInfo {
    pub fn assemble(&self) -> Result<Vec<u8>, IcedError> {
        let mut instructions = Vec::new();

        // Generate code to copy known stack state onto the stack
        if let Some(rg) = self.return_gadgets {
            let offset = rg.stack_offset;
            let mut i = 0;
            loop {
                let remaining = rg.bytes.len() as u64 - i;
                let src_mem = MemoryOperand::with_base_displ(Register::RIP, (offset + i) as i64);
                let dst_mem = MemoryOperand::with_base_displ(Register::RSP, (offset + i) as i64);
                instructions.extend(match remaining {
                    16.. => [
                        Instruction::with2(Code::Movupd_xmm_xmmm128, Register::XMM0, src_mem)?,
                        Instruction::with2(Code::Movupd_xmmm128_xmm, dst_mem, Register::XMM0)?,
                    ],
                    8.. => [
                        Instruction::with2(Code::Mov_r64_rm64, Register::RAX, src_mem)?,
                        Instruction::with2(Code::Mov_rm64_r64, dst_mem, Register::RAX)?,
                    ],
                    4.. => [
                        Instruction::with2(Code::Mov_r32_rm32, Register::EAX, src_mem)?,
                        Instruction::with2(Code::Mov_rm32_r32, dst_mem, Register::EAX)?,
                    ],
                    2.. => [
                        Instruction::with2(Code::Mov_r16_rm16, Register::AX, src_mem)?,
                        Instruction::with2(Code::Mov_rm16_r16, dst_mem, Register::AX)?,
                    ],
                    1.. => [
                        Instruction::with2(Code::Mov_r8_rm8, Register::AL, src_mem)?,
                        Instruction::with2(Code::Mov_rm8_r8, dst_mem, Register::AL)?,
                    ],
                    0 => break,
                });
                i += match remaining {
                    16.. => 16,
                    8.. => 8,
                    4.. => 4,
                    2.. => 2,
                    1.. => 1,
                    _ => unreachable!(),
                };
            }
        }

        // Final RSP adjustment and jump sequence
        instructions.extend_from_slice(&[
            Instruction::with2(Code::Add_rm64_imm8, Register::RSP, 8u32)?,
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, self.exit_stub_addr)?,
            Instruction::with1(Code::Jmp_rm64, Register::RAX)?,
        ]);

        // Store stack data after the code block
        if let Some(rg) = self.return_gadgets {
            instructions.extend(rg.bytes.iter().enumerate().map(|(i, &b)| {
                let mut instr = Instruction::with_declare_byte_1(b);
                instr.set_ip(rg.stack_offset + i as u64);
                instr
            }));
        }

        BlockEncoder::encode(
            64,
            InstructionBlock::new(&instructions, 0),
            BlockEncoderOptions::NONE,
        )
        .map(|r| r.code_buffer)
    }
}

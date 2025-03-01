use std::{u32, u64};

use fxhash::{FxHashMap, FxHashSet};
use pelite::pe::{Pe, PeObject, PeView};

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, IcedError, Instruction, InstructionInfoFactory,
    Mnemonic, OpAccess, OpKind, Register,
};
use smallvec::{smallvec, SmallVec};

/// Visit all instructions in `pe` reachable from the one at `start_rva`.
/// Able to see through Arxan indirect branches.
///
/// The order of instructions is similar, but not guaranteed to be the DFS ordering
/// of the underlying CFG.
pub fn arxan_visitor(
    pe: &PeView,
    start_rva: usize,
    mut visitor: impl FnMut(&Instruction) -> Option<FlowControl>,
) -> Result<(), IcedError> {
    let base = pe.optional_header().ImageBase;

    let text_ranges: Vec<_> = pe
        .section_headers()
        .iter()
        .filter(|s| s.name_bytes() == b".text")
        .map(|s| base + s.virtual_range().start as u64..base + s.virtual_range().end as u64)
        .collect();

    let mut decoder = Decoder::with_ip(64, pe.image(), base, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut visited: FxHashSet<u64> = Default::default();
    let mut ip_stack = vec![base + start_rva as u64];
    let mut indirect_stack = vec![];

    while let Some(ip) = ip_stack.pop() {
        if !visited.insert(ip) {
            continue;
        }

        decoder.set_position((ip - base) as usize)?;
        decoder.set_ip(ip);
        decoder.decode_out(&mut instruction);

        if let Some(indirect_va) = match instruction.code() {
            Code::Mov_r64_imm64 => Some(instruction.immediate64()),
            Code::Lea_r64_m => Some(instruction.ip_rel_memory_address()),
            _ => None,
        } {
            if matches!(
                instruction.op0_register(),
                Register::RBP | Register::RCX | Register::RDX
            ) && text_ranges.iter().any(|r| r.contains(&indirect_va))
            {
                indirect_stack.push(indirect_va)
            }
        }

        match visitor(&instruction).unwrap_or(instruction.flow_control()) {
            FlowControl::Next => ip_stack.push(instruction.next_ip()),
            FlowControl::UnconditionalBranch => ip_stack.push(instruction.near_branch_target()),
            FlowControl::ConditionalBranch | FlowControl::Call => {
                ip_stack
                    .extend_from_slice(&[instruction.next_ip(), instruction.near_branch_target()]);
            }
            FlowControl::IndirectBranch | FlowControl::IndirectCall | FlowControl::Return => {
                ip_stack.extend(indirect_stack.drain(..));
            }
            FlowControl::Exception | FlowControl::Interrupt => (),
            FlowControl::XbeginXabortXend => unimplemented!(),
        }
    }

    Ok(())
}

const GPR_COUNT: usize = 18;

enum Constraint {
    Register(Register),
    Constant(u64),
    Memory {
        disp_or_absolute_addr: u64,
        base: Register,
        index: Register,
        index_scale: u8,
    },
}

struct PointerValue {
    value: u64,
    constaints: SmallVec<[Constraint; 2]>,
}

type PossibleValues = SmallVec<[u64; 4]>;

#[derive(Clone)]
struct BasicBlockState<'a> {
    program: PeView<'a>,
    rip: u64,
    gpr_state: [PossibleValues; GPR_COUNT],
    memory_state: FxHashMap<u64, PossibleValues>,
}

fn is_write(access: OpAccess) -> bool {
    return matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    );
}

fn is_cmov(mnemonic: Mnemonic) -> bool {
    return mnemonic >= Mnemonic::Cmova && mnemonic <= Mnemonic::Cmovs;
}

#[derive(Debug, Clone)]
pub enum WriteValue {
    Uncond64(PossibleValues),
    Cond64(PossibleValues),
    OtherSize(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicBlockBranching {
    Stop,
    Single,
    Multiple,
}

impl<'a> BasicBlockState<'a> {
    fn new(program: PeView<'a>, rip: u64) -> Self {
        Self {
            program,
            rip,
            gpr_state: Default::default(),
            memory_state: Default::default(),
        }
    }

    fn gpr64(&self, r: Register) -> &PossibleValues {
        assert!(r.is_gpr64());
        &self.gpr_state[r as usize - Register::RAX as usize]
    }

    fn gpr64_mut(&mut self, r: Register) -> &mut PossibleValues {
        assert!(r.is_gpr64());
        &mut self.gpr_state[r as usize - Register::RAX as usize]
    }

    fn read_gpr(&self, r: Register) -> impl ExactSizeIterator<Item = u64> + Clone + '_ {
        let mask = u64::MAX >> (64 - 8 * r.size());
        self.gpr64(r.full_register()).iter().map(move |v| v & mask)
    }

    fn write_gpr(&mut self, r: Register, value: WriteValue) {
        let full_reg = r.full_register();
        let current_values = self.gpr64_mut(full_reg);
        if r.is_gpr32() {
            match value {
                WriteValue::Cond64(v) => {
                    current_values.extend(v.into_iter().map(|x| x & u32::MAX as u64))
                }
                WriteValue::Uncond64(v) => {
                    current_values.clear();
                    current_values.extend(v.into_iter().map(|x| x & u32::MAX as u64));
                }
                WriteValue::OtherSize(_) => current_values.clear(),
            }
        } else if r.is_gpr64() {
            match value {
                WriteValue::Cond64(v) => current_values.extend(v),
                WriteValue::Uncond64(v) => *current_values = v,
                WriteValue::OtherSize(_) => current_values.clear(),
            }
        } else {
            current_values.clear();
        }
    }

    fn virtual_addresses(&self, instr: &Instruction) -> PossibleValues {
        if instr.is_ip_rel_memory_operand() {
            return smallvec![instr.ip_rel_memory_address()];
        }

        let base_reg = instr.memory_base();
        let index_reg = instr.memory_index();

        let possible_bases = (base_reg != Register::None).then(|| self.read_gpr(base_reg));
        let possible_indices = (index_reg != Register::None).then(|| self.read_gpr(index_reg));

        let scale = instr.memory_index_scale() as u64;

        let disp = instr.memory_displacement64()
            & u64::MAX.wrapping_shr(64 - 8 * instr.memory_displ_size());

        let mut addrs = SmallVec::<[u64; 4]>::new();
        match (possible_bases, possible_indices) {
            (None, Some(i)) => i.for_each(|i| addrs.push(i * scale + disp)),
            (Some(b), None) => b.for_each(|b| addrs.push(b + disp)),
            (Some(b), Some(i)) => {
                b.for_each(|b| i.clone().for_each(|i| addrs.push(b + i * scale + disp)))
            }
            _ => (),
        }

        addrs
    }

    fn read_mem(&mut self, addr: u64) -> &PossibleValues {
        self.memory_state.entry(addr).or_insert_with(|| {
            self.program
                .read(addr, 8, 1)
                .ok()
                .and_then(|bytes| Some(smallvec![u64::from_le_bytes(bytes.try_into().ok()?)]))
                .unwrap_or_default()
        })
    }

    fn write_mem(&mut self, addr: u64, value: WriteValue) {
        let write_size = match value {
            WriteValue::Uncond64(v) => {
                self.memory_state.insert(addr, v);
                8
            }
            WriteValue::Cond64(v) => {
                self.memory_state.entry(addr).or_default().extend(v);
                8
            }
            WriteValue::OtherSize(s) => {
                self.memory_state.insert(addr, Default::default());
                s
            }
        };

        // Mark clobbered addresses as explicitly having no info
        for bad_addr in (addr - 7)..addr {
            self.memory_state.insert(bad_addr, Default::default());
        }
        for bad_addr in (addr + 1)..(addr + write_size as u64) {
            self.memory_state.insert(bad_addr, Default::default());
        }
    }

    fn increment_rsp(&mut self, increment: i32) {
        for val in self.gpr64_mut(Register::RSP) {
            *val = val.wrapping_add_signed(increment as i64)
        }
    }

    fn update_state(
        &mut self,
        info_factory: &mut InstructionInfoFactory,
        instruction: &Instruction,
        mut branch_store: impl Extend<Self>,
    ) -> BasicBlockBranching {
        // Not using smallvec for the return, since branches are rare

        // Need to keep this to use it for control flow later
        let mut ret_jumps: PossibleValues = smallvec![];

        // Handle effects of instructions to GPRs and memory
        match instruction.mnemonic() {
            Mnemonic::Mov => self.handle_mov(instruction, false),
            m if is_cmov(m) => self.handle_mov(instruction, true),
            Mnemonic::Lea => {
                let addresses = self.virtual_addresses(instruction);
                self.set_operand_values(instruction, 0, WriteValue::Uncond64(addresses));
            }
            Mnemonic::Push => {
                self.increment_rsp(instruction.stack_pointer_increment());

                let values = self.get_operand_values(instruction, 0).unwrap();
                // Note: We already adjusted RSP. Just write the values
                for rsp_val in self.gpr64(Register::RSP).clone() {
                    self.write_mem(rsp_val, WriteValue::Uncond64(values.clone()));
                }
            }
            Mnemonic::Pop => {
                let values = self
                    .gpr64(Register::RSP)
                    .clone()
                    .iter()
                    .flat_map(|&rsp| self.read_mem(rsp).clone())
                    .collect();

                self.set_operand_values(instruction, 0, WriteValue::Uncond64(values));
                self.increment_rsp(instruction.stack_pointer_increment());
            }
            Mnemonic::Xchg => {
                let op0_vals = self.get_operand_values(instruction, 0).unwrap();
                let op1_vals = self.get_operand_values(instruction, 1).unwrap();
                self.set_operand_values(instruction, 0, WriteValue::Uncond64(op1_vals));
                self.set_operand_values(instruction, 1, WriteValue::Uncond64(op0_vals));
            }
            Mnemonic::Call => {
                self.increment_rsp(instruction.stack_pointer_increment());
                for potential_stack in self.gpr64(Register::RSP).clone() {
                    self.write_mem(
                        potential_stack,
                        WriteValue::Uncond64(smallvec![instruction.next_ip()]),
                    );
                }
            }
            Mnemonic::Ret => {
                ret_jumps = self
                    .gpr64(Register::RSP)
                    .clone()
                    .iter()
                    .flat_map(|&rsp| self.read_mem(rsp).clone())
                    .collect();

                self.increment_rsp(instruction.stack_pointer_increment());
            }
            _ => self.handle_generic_instruction(info_factory, instruction),
        }

        let possible_branches = match instruction.flow_control() {
            FlowControl::Next => smallvec![instruction.next_ip()],
            FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch => {
                self.get_operand_values(instruction, 0).unwrap_or_default()
            }
            FlowControl::ConditionalBranch => {
                let mut branch_vals = self.get_operand_values(instruction, 0).unwrap_or_default();
                branch_vals.push(instruction.next_ip());
                branch_vals
            }
            FlowControl::Return => ret_jumps,
            FlowControl::Exception | FlowControl::Interrupt => smallvec![],
            _ => unimplemented!(),
        };

        match possible_branches.len() {
            0 => BasicBlockBranching::Stop,
            1 => {
                self.rip = possible_branches[0];
                BasicBlockBranching::Single
            }
            n => {
                self.rip = possible_branches[0];
                branch_store.extend(possible_branches[1..].iter().map(|br| BasicBlockState {
                    rip: *br,
                    ..self.clone()
                }));
                BasicBlockBranching::Multiple
            }
        }
    }

    fn get_operand_values(
        &mut self,
        instruction: &Instruction,
        operand: u32,
    ) -> Option<PossibleValues> {
        Some(match instruction.op_kind(operand) {
            OpKind::Register => self.read_gpr(instruction.op_register(operand)).collect(),
            OpKind::Memory => self
                .virtual_addresses(instruction)
                .iter()
                .flat_map(|&a| self.read_mem(a).clone())
                .collect(),
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64 => {
                smallvec![instruction.immediate(operand)]
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                smallvec![instruction.near_branch_target()]
            }
            _ => return None,
        })
    }

    fn set_operand_values(&mut self, instruction: &Instruction, operand: u32, value: WriteValue) {
        match instruction.op_kind(operand) {
            OpKind::Register => {
                self.write_gpr(instruction.op0_register(), value);
            }
            OpKind::Memory => {
                for addr in self.virtual_addresses(instruction) {
                    self.write_mem(addr, value.clone());
                }
            }
            _ => unimplemented!(),
        }
    }

    fn handle_mov(&mut self, instruction: &Instruction, conditional: bool) {
        let source_vals = self.get_operand_values(instruction, 1).unwrap();
        self.set_operand_values(
            instruction,
            0,
            match conditional {
                false => WriteValue::Uncond64(source_vals),
                true => WriteValue::Cond64(source_vals),
            },
        );
    }

    fn handle_generic_instruction(
        &mut self,
        info_factory: &mut InstructionInfoFactory,
        instruction: &Instruction,
    ) {
        // Adjust the stack
        self.increment_rsp(instruction.stack_pointer_increment());
        // Clobber used registers
        let instruction_info = info_factory.info(instruction);
        for used_register in instruction_info.used_registers() {
            if used_register.register().is_gpr()
                && matches!(
                    used_register.access(),
                    OpAccess::Write | OpAccess::ReadWrite
                )
            {
                self.gpr64_mut(used_register.register().full_register())
                    .clear();
            }
        }
        // Clobber used memory
        for used_memory in instruction_info.used_memory() {
            if matches!(used_memory.access(), OpAccess::Write | OpAccess::ReadWrite) {
                for addr in self.virtual_addresses(instruction) {
                    self.write_mem(
                        addr,
                        WriteValue::OtherSize(used_memory.memory_size().size()),
                    );
                }
            }
        }
    }
}

/// Visit all instructions in `pe` reachable from the one at `start_rva`.
/// Able to see through Arxan indirect branches.
///
/// The order of instructions is similar, but not guaranteed to be the DFS ordering
/// of the underlying CFG.
pub fn reliable_arxan_visitor(
    pe: &PeView,
    start_rva: usize,
    mut visitor: impl FnMut(&Instruction) -> Option<FlowControl>,
) -> Result<(), IcedError> {
    let base = pe.optional_header().ImageBase;

    let text_ranges: Vec<_> = pe
        .section_headers()
        .iter()
        .filter(|s| s.name_bytes() == b".text")
        .map(|s| base + s.virtual_range().start as u64..base + s.virtual_range().end as u64)
        .collect();

    let mut decoder = Decoder::with_ip(64, pe.image(), base, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut visited: FxHashSet<u64> = Default::default();
    let mut ip_stack = vec![base + start_rva as u64];
    let mut indirect_stack = vec![];

    while let Some(ip) = ip_stack.pop() {
        if !visited.insert(ip) {
            continue;
        }

        decoder.set_position((ip - base) as usize)?;
        decoder.set_ip(ip);
        decoder.decode_out(&mut instruction);

        if let Some(indirect_va) = match instruction.code() {
            Code::Mov_r64_imm64 => Some(instruction.immediate64()),
            Code::Lea_r64_m => Some(instruction.ip_rel_memory_address()),
            _ => None,
        } {
            if matches!(
                instruction.op0_register(),
                Register::RBP | Register::RCX | Register::RDX
            ) && text_ranges.iter().any(|r| r.contains(&indirect_va))
            {
                indirect_stack.push(indirect_va)
            }
        }

        match visitor(&instruction).unwrap_or(instruction.flow_control()) {
            FlowControl::Next => ip_stack.push(instruction.next_ip()),
            FlowControl::UnconditionalBranch => ip_stack.push(instruction.near_branch_target()),
            FlowControl::ConditionalBranch | FlowControl::Call => {
                ip_stack
                    .extend_from_slice(&[instruction.next_ip(), instruction.near_branch_target()]);
            }
            FlowControl::IndirectBranch | FlowControl::IndirectCall | FlowControl::Return => {
                ip_stack.extend(indirect_stack.drain(..));
            }
            FlowControl::Exception | FlowControl::Interrupt => (),
            FlowControl::XbeginXabortXend => unimplemented!(),
        }
    }

    Ok(())
}

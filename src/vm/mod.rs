use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use indexmap::IndexSet;
use pelite::pe::{Pe, PeObject, PeView};

pub mod memory;
pub mod registers;
pub mod util;

use memory::MemoryStore;
use registers::Registers;

// By using IndexSet, we can iterate through the visited list backwards to trace the full branch execution
// for essentially no cost
type FxIndexSet<T> = IndexSet<T, fxhash::FxBuildHasher>;

#[derive(Debug, Clone)]
pub struct ProgramState<'a> {
    pub rip: Option<u64>,
    pub registers: Registers,
    pub memory: MemoryStore<'a>,
}

#[derive(Debug)]
pub struct PastFork<'a> {
    pub state: ProgramState<'a>,
    pub visited: FxIndexSet<u64>,
}

pub struct RunStep<'a, 'b> {
    pub next_instruction: &'b mut Instruction,
    pub info_factory: &'b mut InstructionInfoFactory,
    pub state: &'b mut ProgramState<'a>,
    pub visited: &'b mut FxIndexSet<u64>,
    pub past_forks: &'b mut [PastFork<'a>],
}

impl<'a> ProgramState<'a> {
    pub fn with_rip(image: PeView<'a>, rip: u64) -> Self {
        Self {
            rip: Some(rip),
            registers: Registers::default(),
            memory: MemoryStore::new(image),
        }
    }

    pub fn run<F>(self, mut on_step: F)
    where
        F: for<'b> FnMut(RunStep<'a, 'b>) -> Option<Option<ProgramState<'a>>>,
    {
        let pe = self.memory.image();
        let base = pe.optional_header().ImageBase;

        let mut decoder = Decoder::new(64, pe.image(), DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut info_factory = InstructionInfoFactory::new();

        let mut shared_visit_state: Vec<FxIndexSet<u64>> = Vec::new();
        let mut fork_stack = vec![PastFork {
            state: self,
            visited: FxIndexSet::<u64>::default(),
        }];

        while !fork_stack.is_empty() {
            let depth = fork_stack.len() - 1;
            let (past_forks, tail) = fork_stack.split_at_mut(depth);
            let PastFork { state, visited } = &mut tail[0];

            #[rustfmt::skip]
            let was_visited = state.rip.map(|ip| {
                let prv_visit = shared_visit_state[..depth].iter().rev().any(|v| v.contains(&ip));
                prv_visit || !visited.insert(ip)
            });
            if was_visited != Some(false) {
                fork_stack.pop();

                if let Some(PastFork { visited, .. }) = fork_stack.last_mut() {
                    // Merge shared state back into its parent
                    // We do this instead of extending `visited` as shared_visited
                    // will typically be much bigger
                    let mut shared_visited = shared_visit_state.pop().unwrap();
                    shared_visited.extend(visited.iter().copied());
                    *visited = shared_visited;
                }
                continue;
            };

            let ip = state.rip.unwrap();
            decoder.set_ip(ip);
            if let Err(_) = decoder.set_position((ip - base) as usize) {
                state.rip = None;
                continue;
            }

            decoder.decode_out(&mut instruction);

            let run_step = RunStep {
                next_instruction: &mut instruction,
                info_factory: &mut info_factory,
                state,
                visited,
                past_forks,
            };
            if let Some(forked) = on_step(run_step)
                .unwrap_or_else(|| state.update_state(&instruction, &mut info_factory))
            {
                // Split visited state into shared stack to allow both programs to progress
                // independently
                shared_visit_state.push(std::mem::take(visited));
                fork_stack.push(PastFork {
                    state: forked,
                    visited: Default::default(),
                });
            }
        }
    }

    pub fn update_state(
        &mut self,
        instr: &Instruction,
        info_factory: &mut InstructionInfoFactory,
    ) -> Option<ProgramState<'a>> {
        // Address populated by custom flow control driven by per-mnemonic logic
        let mut flow_override = None;

        match instr.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx => {
                let _ = self.set_operand_value(instr, 0, self.get_operand_value(instr, 1));
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let sign_extended = self
                    .get_operand_value(instr, 1)
                    .map(|arg| util::reinterpret_signed(arg, util::op_size(instr, 0)) as u64);
                let _ = self.set_operand_value(instr, 0, sign_extended);
            }
            Mnemonic::Xchg => self.handle_xchg(instr),
            Mnemonic::Lea => {
                let addr = self.virtual_address(instr, 1);
                let _ = self.set_operand_value(instr, 0, addr);
            }
            Mnemonic::Add => {
                let result = self
                    .get_operand_value(instr, 0)
                    .and_then(|lhs| Some(lhs.wrapping_add(self.get_operand_value(instr, 1)?)));
                let _ = self.set_operand_value(instr, 0, result);
            }
            Mnemonic::Sub => {
                let result = self
                    .get_operand_value(instr, 0)
                    .and_then(|lhs| Some(lhs.wrapping_sub(self.get_operand_value(instr, 1)?)));
                let _ = self.set_operand_value(instr, 0, result);
            }
            Mnemonic::Push => {
                self.adjust_rsp(instr.stack_pointer_increment());
                if let Some(rsp) = self.registers.rsp() {
                    let pushed_value = self
                        .get_operand_value(instr, 0)
                        .map(|v| util::reinterpret_signed(v, util::op_size(instr, 0)) as u64);
                    self.memory.write_int(rsp, pushed_value, 8);
                }
            }
            Mnemonic::Pop => {
                if let Some(rsp) = self.registers.rsp() {
                    let popped_value = self.memory.read_int(rsp, util::op_size(instr, 0));
                    let _ = self.set_operand_value(instr, 0, popped_value);
                }
                self.adjust_rsp(instr.stack_pointer_increment());
            }
            Mnemonic::Call => {
                flow_override = self.get_operand_value(instr, 0);

                self.adjust_rsp(instr.stack_pointer_increment());
                if let Some(rsp) = self.registers.rsp() {
                    self.memory.write_int(rsp, Some(instr.next_ip()), 8);
                }
            }
            Mnemonic::Ret => {
                if let Some(rsp) = self.registers.rsp() {
                    flow_override = self.memory.read_int(rsp, 8);
                }
                self.adjust_rsp(instr.stack_pointer_increment());
            }
            m if util::is_cmov(m) => {
                let original_value = self.get_operand_value(instr, 0);
                let potential_write = self.get_operand_value(instr, 1);

                match (original_value, potential_write) {
                    // Both values are present, so we fork
                    (Some(_), Some(_)) => {
                        self.rip = Some(instr.next_ip());
                        let mut forked = self.clone();
                        let _ = forked.set_operand_value(instr, 0, potential_write);
                        return Some(forked);
                    }
                    // Only new value is present, write it (original path has no extra info)
                    (None, Some(_)) => {
                        let _ = self.set_operand_value(instr, 0, potential_write);
                    }
                    // new value is missing, do nothing (cond path has no extra info)
                    _ => {}
                }
            }
            _ => self.handle_generic(instr, info_factory),
        }

        if flow_override.is_some() {
            self.rip = flow_override;
            return None;
        }
        match instr.flow_control() {
            FlowControl::Next => self.rip = Some(instr.next_ip()),
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                self.rip = self.get_operand_value(instr, 0);
            }
            FlowControl::ConditionalBranch => {
                self.rip = Some(instr.next_ip());
                return Some(Self {
                    rip: Some(instr.near_branch_target()),
                    ..self.clone()
                });
            }
            _ => self.rip = None,
        }

        None
    }

    fn virtual_address_cb(&self, reg: Register) -> Option<u64> {
        match reg {
            Register::CS | Register::DS | Register::ES | Register::SS => Some(0),
            _ if reg.is_gpr() => self.registers.read_gpr(reg),
            _ => None,
        }
    }

    pub fn virtual_address(&self, instr: &Instruction, op: u32) -> Option<u64> {
        instr.virtual_address(op, 0, |reg, _, _| self.virtual_address_cb(reg))
    }

    pub fn get_operand_value(&self, instr: &Instruction, op: u32) -> Option<u64> {
        match instr.op_kind(op) {
            OpKind::Register => self.registers.read_gpr(instr.op_register(op)),
            OpKind::Memory => {
                let addr = self.virtual_address(instr, op)?;
                self.memory.read_int(addr, instr.memory_size().size())
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(instr.near_branch_target())
            }
            _ => instr.try_immediate(op).ok(),
        }
    }

    pub fn set_operand_value(
        &mut self,
        instr: &Instruction,
        op: u32,
        val: Option<u64>,
    ) -> Result<(), ()> {
        match instr.op_kind(op) {
            OpKind::Register => self.registers.write_gpr(instr.op_register(op), val),
            OpKind::Memory => {
                let addr = self.virtual_address(instr, op).ok_or(())?;
                self.memory.write_int(addr, val, instr.memory_size().size());
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    fn adjust_rsp(&mut self, increment: i32) {
        self.registers
            .rsp_mut()
            .as_mut()
            .map(|rsp| *rsp = rsp.wrapping_add_signed(increment as i64));
    }

    fn handle_xchg(&mut self, instr: &Instruction) {
        let mut to_swap = [(None, None); 2];
        for (i, (addr, val)) in to_swap.iter_mut().enumerate() {
            *addr = self.virtual_address(instr, i as u32);
            *val = match instr.op_kind(i as u32) {
                OpKind::Register => self.registers.read_gpr(instr.op_register(i as u32)),
                OpKind::Memory => {
                    addr.and_then(|a| self.memory.read_int(a, instr.memory_size().size()))
                }
                _ => unreachable!(),
            }
        }
        for (i, (addr, _)) in to_swap.iter().enumerate() {
            let other_value = to_swap[1 - i].1;
            match instr.op_kind(i as u32) {
                OpKind::Register => self
                    .registers
                    .write_gpr(instr.op_register(i as u32), other_value),
                OpKind::Memory => {
                    if let Some(a) = addr {
                        self.memory
                            .write_int(*a, other_value, instr.memory_size().size())
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    fn handle_generic(&mut self, instr: &Instruction, info_factory: &mut InstructionInfoFactory) {
        let used_memory = info_factory.info(instr);

        for mem in used_memory.used_memory() {
            let addr = match mem.virtual_address(0, |reg, _, _| self.virtual_address_cb(reg)) {
                Some(addr) => addr,
                None => continue,
            };
            let access_size = mem.memory_size().size();

            match mem.access() {
                // We are definitely writing to this address. Invalidate the written range.
                OpAccess::Write | OpAccess::ReadWrite => {
                    self.memory.invalidate(addr, access_size);
                }
                // We may be writing to this address. This would normally fork,
                // but the path where we invalidate the memory is worthless as it does
                // not provide any new information, so we don't consider it.
                OpAccess::CondWrite | OpAccess::ReadCondWrite => {}
                _ => {}
            }
        }
        for reg in used_memory.used_registers() {
            // RSP is used implicitly and not present in the rest of the instruction
            if reg.register() == Register::RSP
                && instr.is_stack_instruction()
                && !(0..instr.op_count()).any(|i| instr.op_register(i) == Register::RSP)
                && instr.memory_base() != Register::RSP
                && instr.memory_index() != Register::RSP
            {
                self.adjust_rsp(instr.stack_pointer_increment());
                continue;
            }
            match reg.access() {
                // We are definitely writing to this register. Invalidate it.
                OpAccess::Write | OpAccess::ReadWrite if reg.register().is_gpr() => {
                    self.registers.write_gpr(reg.register(), None);
                }
                _ => {}
            }
        }
    }
}

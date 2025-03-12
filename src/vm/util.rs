use iced_x86::{Instruction, Mnemonic, OpKind};

pub(super) fn is_cmov(mnemonic: Mnemonic) -> bool {
    mnemonic >= Mnemonic::Cmova && mnemonic <= Mnemonic::Cmovs
}

pub(super) fn op_size(instr: &Instruction, op: u32) -> usize {
    match instr.op_kind(op) {
        OpKind::Register => instr.op_register(op).size(),
        OpKind::Memory => instr.memory_size().size(),
        OpKind::Immediate8 => 1,
        OpKind::Immediate16 | OpKind::Immediate8to16 => 2,
        OpKind::Immediate32 | OpKind::Immediate8to32 => 4,
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => 8,
        _ => unimplemented!(),
    }
}

pub(super) fn reinterpret_unsigned(val: u64, size_bytes: usize) -> u64 {
    let mask = match size_bytes {
        8 => u64::MAX,
        s => 1 << (8 * s - 1),
    };
    val & mask
}

pub(super) fn reinterpret_signed(val: u64, size_bytes: usize) -> i64 {
    let sign_bit = 1u64 << (8 * size_bytes - 1);
    (val | (val & sign_bit).wrapping_neg()) as i64
}

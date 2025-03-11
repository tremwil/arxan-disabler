use std::mem::transmute_copy;

use super::code_buffer::CodeBuffer;

pub struct CallHook<F: Copy> {
    imm_ptr: *mut i32,
    original: F,
}

unsafe impl<F: Copy + Send> Send for CallHook<F> {}
unsafe impl<F: Copy + Sync> Sync for CallHook<F> {}

impl<F: Copy> CallHook<F> {
    pub unsafe fn new(call_ptr: *mut u8) -> Self {
        const {
            assert!(
                size_of::<F>() == size_of::<usize>(),
                "Call hook generic parameter must be pointer-sized"
            );
        }

        let imm_ptr = call_ptr.wrapping_add(1) as *mut i32;
        let imm = unsafe { imm_ptr.read_unaligned() };
        let target = (imm_ptr.addr() + 4).wrapping_add_signed(imm as isize);

        Self {
            imm_ptr,
            original: unsafe { transmute_copy(&target) },
        }
    }

    pub fn original(&self) -> F {
        self.original
    }

    pub unsafe fn hook_with(&self, new_target: F) {
        let address: isize = unsafe { transmute_copy(&new_target) };
        let imm: i32 = address
            .wrapping_sub_unsigned(self.imm_ptr.addr() + 4)
            .try_into()
            .unwrap();

        unsafe { self.imm_ptr.write_unaligned(imm) };
    }

    pub unsafe fn hook_with_thunk(&self, new_target: F, thunk_buffer: &CodeBuffer) {
        let next_instr = self.imm_ptr.addr() + 4;
        let start_dist = (thunk_buffer.range().start as isize).wrapping_sub_unsigned(next_instr);
        let end_dist = (thunk_buffer.range().end as isize).wrapping_sub_unsigned(next_instr);
        if start_dist.max(end_dist).abs() > i32::MAX as isize {
            panic!("Code buffer not in range of the target call instruction");
        }

        // MOVABS rax, new_target
        // JMP rax
        let mut thunk = b"\x48\xb8........\xff\xe0".to_owned();
        thunk[2..10].copy_from_slice(&unsafe { transmute_copy::<_, [u8; 8]>(&new_target) });

        let mem_ptr = thunk_buffer.write(&thunk).unwrap();
        unsafe { self.hook_with(transmute_copy(&mem_ptr.addr())) };
    }

    pub unsafe fn unhook(&self) {
        unsafe { self.hook_with(self.original) }
    }
}

impl<F: Copy> Drop for CallHook<F> {
    fn drop(&mut self) {
        unsafe { self.unhook() }
    }
}

pub mod arxan_visitor;

pub const EXPECTED_STACK_MAX_COUNT: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    Success = 0,
    Error = 1,
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct StackMachineEntry {
    pub offset: u64,
    pub block_address: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct StubPatchInfo {
    pub patch_address: u64,
    pub partial_exit_stub_address: u64,
    pub expected_stack_count: u64,
    pub expected_stack: [StackMachineEntry; EXPECTED_STACK_MAX_COUNT],
}

pub type StubInfoCallback = unsafe extern "C" fn(*const StubPatchInfo);

#[no_mangle]
pub unsafe extern "C" fn find_arxan_stubs(
    image_base: *const u8,
    image_size: usize,
    callback: StubInfoCallback,
) -> ErrorCode {
    todo!()
}

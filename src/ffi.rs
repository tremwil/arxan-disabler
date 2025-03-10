use std::{ffi::c_void, ptr::dangling};

use pelite::pe64::PeView;

use crate::spider;

#[derive(Debug)]
#[repr(C)]
pub struct ArxanStubPatchInfo {
    pub hook_address: u64,
    pub hook_code: *const u8,
    pub hook_code_size: usize,
    pub success: bool,
}

pub type ArxanStubCallback = unsafe extern "C" fn(*mut c_void, *const ArxanStubPatchInfo);

#[no_mangle]
pub unsafe extern "C" fn find_arxan_stubs(
    image_base: *const u8,
    callback: ArxanStubCallback,
    user_context: *mut c_void,
) {
    let pe = unsafe { PeView::module(image_base) };
    spider::find_arxan_stubs(pe, |hook_address, patch_info| {
        if let Some(code) = patch_info.and_then(|p| p.assemble().ok()) {
            let ffi_info = ArxanStubPatchInfo {
                hook_address,
                hook_code: code.as_ptr(),
                hook_code_size: code.len(),
                success: true,
            };
            unsafe { callback(user_context, &ffi_info) };
        } else {
            let ffi_info = ArxanStubPatchInfo {
                hook_address,
                hook_code: dangling(),
                hook_code_size: 0,
                success: false,
            };
            unsafe { callback(user_context, &ffi_info) }
        }
    });
}

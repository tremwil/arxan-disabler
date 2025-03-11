use std::sync::atomic::Ordering;

use common::{make_module_rwe, DISABLER_CTX};

use crate::patch::StubPatchInfo;

mod call_hook;
mod code_buffer;
mod common;

pub mod dsr;

pub trait ArxanDisabler {
    /// Internal to the disabler implementation.
    ///
    /// Filters patches before they are applied by the default
    /// [`ArxanDisabler::patch_stubs`] implementation.
    ///
    /// The default simply performs all patches.
    #[allow(unused_variables)]
    fn filter_patch(hook_address: u64, patch: Option<&StubPatchInfo>) -> bool {
        true
    }

    /// Finds and applies code patches to Arxan stubs.
    ///
    /// Called by the default implementation of [`ArxanDisabler::_init_stub_detour`].
    ///
    /// While you can could call this directly at any time after game initialization, it may
    /// lead to data races and crashes. Consider calling [`ArxanDisabler::disable`] before the
    /// entry point runs instead.
    unsafe fn patch_stubs() {
        log::debug!("Finding and patching Arxan stubs");
        unsafe { DISABLER_CTX.find_and_patch(Self::filter_patch) };
    }

    /// Internal to the disabler implementation.
    ///
    /// Function to hook the Arxan initialization stub with. Takes care of performing all required patches.
    ///
    /// By default, the detour will be removed and the original initialization stub run to decrypt information.
    /// Then, [`ArxanDisabler::patch_stubs`] will be run to patch Arxan stubs, before running the user-provided
    /// callback that was passed to [`ArxanDisabler::disable`]
    unsafe extern "C" fn _init_stub_detour() {
        log::debug!("Undoing Arxan initialization stub hook");
        unsafe { DISABLER_CTX.init_stub_hook.unhook() };

        log::debug!("Running Arxan initialization stub");
        unsafe { DISABLER_CTX.init_stub_hook.original()() };

        unsafe { Self::patch_stubs() };

        log::debug!("Arxan disabled, running user callback");
        DISABLER_CTX
            .post_disable_cb
            .lock()
            .unwrap()
            .as_mut()
            .map(|cb| cb());
    }

    /// Performs the appropriate patches to disable Arxan.
    /// The callback will be triggered once patching is complete, and can be
    /// used to initialize hooks/etc.
    ///
    /// This must be called **exactly once** before the game's entry point runs.
    /// It is generally safe to call from within DllMain.
    unsafe fn disable<F>(callback: F)
    where
        F: FnMut() + Send + Sync + 'static,
    {
        let ctx = &*DISABLER_CTX;
        assert!(
            !ctx.disable_initiated.swap(true, Ordering::Relaxed),
            "ArxanDisabler::disable already called"
        );

        log::debug!("Making game image RWE");
        unsafe {
            make_module_rwe(ctx.pe);
        }

        // Set callback
        ctx.post_disable_cb
            .lock()
            .unwrap()
            .replace(Box::new(callback));

        log::debug!("Detouring Arxan init stub");
        unsafe {
            ctx.init_stub_hook
                .hook_with_thunk(Self::_init_stub_detour, &ctx.code_buffer)
        };
    }
}

macro_rules! ffi_impl {
    ($disabler:ty, $ffi_disable:ident, $ffi_patch:ident) => {
        #[cfg(feature = "ffi")]
        pub mod ffi {
            use super::*;
            use std::ffi::c_void;

            #[no_mangle]
            pub unsafe extern "C" fn $ffi_disable(
                callback: unsafe extern "C" fn(*mut c_void),
                context: *mut c_void,
            ) {
                let ptr_addr = context.addr();
                unsafe {
                    <$disabler as $crate::disabler::ArxanDisabler>::disable(move || {
                        callback(ptr_addr as *mut c_void)
                    })
                }
            }

            #[no_mangle]
            pub unsafe extern "C" fn $ffi_patch() {
                unsafe { <$disabler as $crate::disabler::ArxanDisabler>::patch_stubs() }
            }
        }
    };
}
pub(crate) use ffi_impl;

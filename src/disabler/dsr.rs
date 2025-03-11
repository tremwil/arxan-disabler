use super::{ffi_impl, ArxanDisabler};

/// Arxan disabler for Dark Souls Remastered 1.3.1.
///
/// Will *not* work for other versions out of the box, but can be adapted if the
/// omitted patches defined in [`DSRArxanDisabler::filter_patch`] are updated.
pub struct DSRArxanDisabler;
impl ArxanDisabler for DSRArxanDisabler {
    fn filter_patch(hook_address: u64, _: Option<&crate::patch::StubPatchInfo>) -> bool {
        // These two
        !matches!(hook_address, 0x142FF5D21 | 0x143001ED0)
    }
}

ffi_impl!(DSRArxanDisabler, disable_arxan_dsr, patch_arxan_stubs_dsr);

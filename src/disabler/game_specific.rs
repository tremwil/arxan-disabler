use crate::patch::StubPatchInfo;

use super::{ffi_impl, ArxanDisabler};

/// Arxan disabler for Dark Souls Remastered 1.3.1.
///
/// Will *not* work for other versions out of the box, but can be adapted if the
/// omitted patches defined in [`DSRArxanDisabler::filter_patch`] are updated.
#[derive(Default)]
pub struct DSRArxanDisabler;
impl ArxanDisabler for DSRArxanDisabler {
    fn filter_patch(&mut self, hook_address: u64, _: Option<&StubPatchInfo>) -> bool {
        // These two decrypt the game's named property list. If they don't run, things
        // go horribly wrong!
        //
        // there doesn't appear to be any other game data encrypted by Arxan.
        !matches!(hook_address, 0x142FF5D21 | 0x143001ED0)
    }
}

ffi_impl!(DSRArxanDisabler, disable_arxan_dsr);

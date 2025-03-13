Provides a Rust library and static library with C bindings to disable the Arxan anti-debug/DRM
from FromSoftware games.

At the moment, only the latest Dark Souls Remastered is supported, but support for Dark Souls III,
Elden Ring and Armored Core VI is also on the roadmap.

# Features
The crate is feature gated and supports the following:
- `ffi`: Exports FFI-compatible functions to be used by foreign code linking to the static library.
    **Required if building the static library for a non-Rust project**.
- `disabler`: Includes code for disabling Arxan at runtime, performing all required patches.
    **Without this feature, the crate can only be used statically**.
- `disabler-debug`: Like `disabler`, but instruments the Arxan stubs will logging calls that
    trigger when the stub is first executed. May be useful for reverse engineering.

# Warning!
<div class="warning">
Many DLL injectors or mod launchers do not suspend the process upon creation or otherwise
provide a method to execute your code before the game's entry point is invoked. If they
are used with this module, the game will likely crash.
</div>

## Example usage 

Rust (feature `disabler` needs to be enabled)
```rust
#[cfg(feature = "disabler")]
unsafe fn my_entry_point() {
    use arxan_disabler::disabler::{ArxanDisabler, DSRArxanDisabler};

    DSRArxanDisabler::disable(|| {
        println!("Arxan disabled!");
        // This is a good place to do your hooks.
        // Once this callback returns, the game's true entry point
        // will be invoked.
    });
}
```

C/C++, via static linking (features `disabler` and `ffi` need to be enabled):
```cpp
#include <iostream>
#include "arxan_disabler.h"

void my_entry_point() {
    const char* context = "Arxan disabled!";

    disable_arxan_dsr([](void* ctx){
        std::cout << reinterpret_cast<char*>(ctx) << std::endl;
    }, context);
}
```
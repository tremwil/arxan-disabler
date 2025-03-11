#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/// @brief Describes a code patch which skips an obfuscated Arxan stub.
typedef struct _ArxanStubPatchInfo {
    /// @brief Virtual address at which to install the hook.
    /// The instruction at this address should be overwritten with a jump to the hook code.
    uint64_t hook_address;
    /// @brief Pointer to the hook's bytecode.
    /// @warning lifetime is limited to the stack frame of the callback function receiving
    /// this struct. Write the bytes somewhere else to store them.
    const uint8_t* hook_code;
    /// @brief Size of the hook's bytecode.
    size_t hook_code_size;
    /// @brief Whether a patch was able to be generated for this stub.
    bool success;
} ArxanStubPatchInfo;

/// @brief Callback providing the bytecode for patching a specific Arxan stub.
/// To be used with `find_arxan_stubs`.
typedef void (*ArxanStubCallback)(
    void* user_context, 
    const ArxanStubPatchInfo* patch_info
);

/// @brief Finds all Arxan stubs in the given memory-mapped PE image.
/// @param image_base Base of the PE image, can be obtained using `GetModuleHandle` at runtime.
/// @param callback Callback which receives the patch details for each patch.
/// @param user_context User context object
void find_arxan_stubs(
    const uint8_t* image_base,
    ArxanStubCallback callback,
    void* user_context
);

#ifdef __cplusplus
};
#endif
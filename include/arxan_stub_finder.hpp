#pragma once
#include <cstdint>

namespace arxan_stub_finder 
{
    static const size_t EXPECTED_STACK_MAX_COUNT = 16;
    
    enum ErrorCode: uint8_t {
        Success = 0,
        Error = 1
    };

    struct StackMachineEntry {
        uint64_t offset;
        uint64_t block_address;
    };

    struct StubPatchInfo {
        uint64_t partial_stub_address;
        StackMachineEntry expected_stack[EXPECTED_STACK_MAX_COUNT];
    };

    typedef void (*StubInfoCallback)(const StubPatchInfo*);
}

#ifdef _MSC_VER
#define ARXAN_STUB_FINDER_DLLIMPORT __declspec(dllimport)
#else
#define ARXAN_STUB_FINDER_DLLIMPORT
#endif

extern "C" ARXAN_STUB_FINDER_DLLIMPORT arxan_stub_finder::ErrorCode find_arxan_stubs(
    const uint8_t* image_base, 
    size_t image_size,
    arxan_stub_finder::StubInfoCallback callback
);
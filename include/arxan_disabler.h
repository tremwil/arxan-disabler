#pragma once

/// @brief Sets up the required hooks to disable Arxan for DSR. 
/// Once patches have been applied, the supplied user callback is invoked.
/// 
/// @warning Currently only supports version 1.3.1.
/// Must be called exactly once before the game's entry point is run.
extern "C" void disable_arxan_dsr(void(*callback)(void* ctx), void* ctx);

/// @brief Applies the required patches to DSR to disable Arxan.
/// 
/// @warning Currently only supports version 1.3.1.
/// Not recommended, but necessary if you can't run before the game's entry point.
/// Please use `disable_arxan_dsr` instead.
extern "C" void patch_arxan_stubs_dsr();
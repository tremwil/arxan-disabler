#pragma once

/// @brief Sets up the required hooks to disable Arxan for DSR. 
/// Once patches have been applied, the supplied user callback is invoked.
/// 
/// @warning Currently only supports version 1.3.1.
/// Must be called exactly once before the game's entry point is run.
extern "C" void disable_arxan_dsr(void(*callback)(void* ctx), void* ctx);

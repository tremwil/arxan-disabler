#pragma once

/// @brief Sets up the required hooks to disable Arxan for DSR. 
/// Once patches have been applied, the supplied user callback is invoked.
/// 
/// @warning Currently only supports version 1.3.1.
/// Must be called exactly once before the game's entry point is run.
extern "C" void disable_arxan_dsr(void(*callback)(void* ctx), void* ctx);


/// @brief Sets up the required hooks to disable Arxan for DS2 SOTFS. 
/// Once patches have been applied, the supplied user callback is invoked.
/// 
/// @warning Supports the latest version (1.03) and will probably work on older ones.
/// Must be called exactly once before the game's entry point is run.
extern "C" void disable_arxan_ds2(void(*callback)(void* ctx), void* ctx);

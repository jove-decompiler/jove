_HIDDEN void _jove_recover_dyn_target(uint32_t CallerBBIdx, uintptr_t CalleeAddr);
_HIDDEN void _jove_recover_function(uint32_t IndCallBBIdx, uintptr_t FuncAddr);
_HIDDEN void _jove_recover_basic_block(uint32_t IndBrBBIdx, uintptr_t BBAddr);
_HIDDEN void _jove_recover_returned(uint32_t CallerBBIdx);
_HIDDEN void _jove_recover_ABI(uint32_t FIdx);

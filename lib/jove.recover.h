_HIDDEN void _jove_recover_dyn_target(uint32_t CallerBBIdx, uintptr_t CalleeAddr);
_HIDDEN void _jove_recover_function(uint32_t IndCallBBIdx, uintptr_t FuncAddr);
_HIDDEN void _jove_recover_basic_block(uint32_t IndBrBBIdx, uintptr_t BBAddr);
_HIDDEN void _jove_recover_returned(uint32_t CallerBBIdx);
_HIDDEN void _jove_recover_ABI(uint32_t FIdx);
_HIDDEN void _jove_recover_foreign_function(uint32_t IndCallBBIdx,
                                            uintptr_t CalleeAddr);
_HIDDEN _NORET void _jove_recover_foreign_function_at_offset(uint32_t IndCallBBIdx,
                                                             uint32_t CalleeBIdx,
                                                             uintptr_t CalleeOffset);
_HIDDEN void _jove_recover_foreign_binary(uintptr_t CalleeAddr);
_NORET static void _jove_recover_foreign_binary_with_path(const char *path);

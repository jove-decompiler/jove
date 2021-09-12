#include <stdint.h>

//
// jove-llvm fills in the definition for the following functions
//

extern uintptr_t _jove_sections_start_file_addr(void);
extern uintptr_t _jove_sections_global_beg_addr(void);
extern uintptr_t _jove_sections_global_end_addr(void);
extern uint32_t _jove_binary_index(void);
extern bool _jove_trace_enabled(void);
extern bool _jove_dfsan_enabled(void);
extern void _jove_call_entry(void);
extern uintptr_t *_jove_get_function_table(void);
extern uintptr_t *_jove_get_dynl_function_table(void);
extern uintptr_t *_jove_get_vdso_function_table(void);
extern void _jove_do_tpoff_hack(void);
extern void _jove_do_emulate_copy_relocations(void);
extern const char *_jove_dynl_path(void);
extern uint32_t    _jove_foreign_lib_count(void);
extern const char *_jove_foreign_lib_path(uint32_t Idx);
extern uintptr_t  *_jove_foreign_lib_function_table(uint32_t Idx);

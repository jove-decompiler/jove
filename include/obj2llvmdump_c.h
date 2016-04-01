#pragma once

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

void obj2llvmdump_print_ops(void);
uint64_t obj2llvmdump_last_tcg_op_addr(void);

#ifdef __cplusplus
}
#endif

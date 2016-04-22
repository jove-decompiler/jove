#pragma once

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

void libqemutcg_init(void);
void libqemutcg_set_code(const uint8_t *p, unsigned long len, unsigned long pc);
unsigned libqemutcg_translate(unsigned long pc);
void libqemutcg_dump_globals(void);
unsigned libqemutcg_max_ops(void);
unsigned libqemutcg_max_params(void);
unsigned libqemutcg_num_tmps(void);
unsigned libqemutcg_first_op_index(void);
void libqemutcg_copy_ops(void*);
void libqemutcg_copy_params(void*);
void libqemutcg_copy_tmps(void*);
void libqemutcg_print_ops(void);
uint64_t libqemutcg_last_tcg_op_addr(void);

#ifdef __cplusplus
}
#endif

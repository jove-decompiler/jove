#pragma once

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

void libqemutcg_init(void);
void libqemutcg_set_code(const uint8_t *p, unsigned long pc);
void libqemutcg_translate(unsigned long pc);
void libqemutcg_dump_globals(void);

#ifdef __cplusplus
}
#endif

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void libqemutcg_init(void);
void libqemutcg_set_code(const uint8_t* p, unsigned long pc);
void libqemutcg_translate(unsigned long pc);
void libqemutcg_test(void);

#ifdef __cplusplus
}
#endif

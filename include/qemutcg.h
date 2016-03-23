#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void libqemutcg_init(void);
void libqemutcg_set_code(const uint8_t* p);
void libqemutcg_translate(unsigned off);
void libqemutcg_test(void);

#ifdef __cplusplus
}
#endif

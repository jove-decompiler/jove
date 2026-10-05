#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

struct SafeTCGGlobalSet : public ip_mt_base_rw_accessible<true> {
  tcg_global_set_t Set{0};
};

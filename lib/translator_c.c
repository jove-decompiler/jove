#include <tcg.h>

GHashTable* translator_tcg_helpers(void);

GHashTable* translator_tcg_helpers() {
  return tcg_ctx.helpers;
}

struct translator;
void translator_enumerate_tcg_helpers(struct translator*);
void translator_tcg_helper(struct translator*, uintptr_t addr, const char* name);

/* XXX */
typedef struct TCGHelperInfo {
    void *func;
    const char *name;
    unsigned flags;
    unsigned sizemask;
} TCGHelperInfo;
/* XXX */

void translator_enumerate_tcg_helpers(struct translator* T) {
  GHashTableIter iter;
  gpointer key, value;

  g_hash_table_iter_init(&iter, tcg_ctx.helpers);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    TCGHelperInfo* h = value;
    translator_tcg_helper(T, (uintptr_t)h->func, h->name);
  }
}

#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"

GHashTable* translator_tcg_helpers(void);

GHashTable* translator_tcg_helpers() {
  return tcg_ctx.helpers;
}

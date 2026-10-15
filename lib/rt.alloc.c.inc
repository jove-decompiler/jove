#ifndef JOVE_TRACK_ALLOCATIONS
#error
#endif

#include "rt.util.c.inc"
#include "rt.mutex.h"

#include <stddef.h>

static struct jove_allocation_t alloc_arr[1024];
static struct jove_allocation_t *allocp = &alloc_arr[0];

static DEFINE_RAW_SPINLOCK(alloc_list_lock);
static struct hlist_head alloc_list = HLIST_HEAD_INIT;

_EXPORT void _jove_rt_track_alloc(uintptr_t beg, size_t len, const char *desc) {
  struct jove_allocation_t *p;

  if (allocp >= &alloc_arr[ARRAY_SIZE(alloc_arr)])
    return; /* out of memory */

  _jove_spin_lock(alloc_list_lock);

  p = allocp++;
  p->beg = beg;
  p->len = len;
  p->desc = desc;

  hlist_add_head(&p->hlist, &alloc_list);

  _jove_spin_unlock(alloc_list_lock);
}

_EXPORT void _jove_rt_track_free(uintptr_t beg, size_t len) {
  struct jove_allocation_t *cur;
  struct hlist_node *tmp_node;

  _jove_spin_lock(alloc_list_lock);

  hlist_for_each_entry_safe(cur, tmp_node, &alloc_list, hlist) {
    if (cur->beg == beg) {
      hlist_del(&cur->hlist);
      break;
    }
  }

  _jove_spin_unlock(alloc_list_lock);
}

_EXPORT const char *_jove_rt_description_for_alloc(uintptr_t beg) {
  struct jove_allocation_t *cur;
  struct hlist_node *tmp_node;

  const char *res = NULL;

  _jove_spin_lock(alloc_list_lock);

  hlist_for_each_entry_safe(cur, tmp_node, &alloc_list, hlist) {
    if (cur->beg == beg) {
      res = cur->desc;
      break;
    }
  }

  _jove_spin_unlock(alloc_list_lock);

  return res;
}

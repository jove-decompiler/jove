#pragma once
#include "jove.macros.h"
#include "jove.sys.h" /* for _jove_sys_futex() */

#include <stdatomic.h>
#include <stdint.h>

#include <linux/futex.h> /* for FUTEX_WAIT / FUTEX_WAKE */

typedef _Atomic uint32_t futex_t;

static _INL long _futex_wait(futex_t *futexp, uint32_t expect_val) {
  return _jove_sys_futex(futexp, FUTEX_WAIT, expect_val, NULL, NULL, 0);
}

static _INL long _futex_wake(futex_t *futexp, uint32_t num_waiters) {
  return _jove_sys_futex(futexp, FUTEX_WAKE, num_waiters, NULL, NULL, 0);
}

typedef futex_t mutex_t;

#define JOVE_MUTEX_INIT JOVE_UNLOCKED

#define JOVE_LOCKED 1
#define JOVE_UNLOCKED 0

static _UNUSED void _mutex_lock(mutex_t *mtx) {
  uint32_t expected = JOVE_UNLOCKED;
  while (unlikely(!atomic_compare_exchange_weak(mtx, &expected, JOVE_LOCKED))) {
    expected = JOVE_UNLOCKED; /* reset expected value */

    /* wait until the lock becomes available */
    _futex_wait(mtx, JOVE_LOCKED);
  }
}

static _UNUSED void _mutex_unlock(mutex_t *mtx) {
  atomic_store(mtx, JOVE_UNLOCKED);

  /* wake up one waiting thread */
  _futex_wake(mtx, 1);
}

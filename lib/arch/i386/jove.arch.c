#ifndef JOVE_ARCH_H
#define JOVE_ARCH_H

static uintptr_t _mmap_rw_anonymous_private_memory(size_t len) {
  return _jove_sys_mmap_pgoff(0x0, len, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
}

static void _jove_sleep(void) {
  for (;;)
    _jove_sys_sched_yield(); /* TODO */
}

static int _jove_open(const char *path, int flags, mode_t mode) {
  return _jove_sys_open(path, flags, mode);
}

#endif

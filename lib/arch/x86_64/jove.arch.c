uintptr_t _mmap_rw_anonymous_private_memory(size_t len) {
  return _jove_sys_mmap(0x0, len, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
}

void _jove_sleep(void) {
  struct timespec t;
  t.tv_sec = 10;
  t.tv_nsec = 0;

  _jove_sys_nanosleep(&t, NULL);
}

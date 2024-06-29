static uintptr_t _mmap_rw_anonymous_private_memory(size_t len) {
  return _jove_sys_mips_mmap(0x0, len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
}

typedef int32_t	old_time32_t;

struct old_timespec32 {
	old_time32_t	tv_sec;
	int32_t		tv_nsec;
};

static void _jove_sleep(void) {
  struct old_timespec32 t;
  t.tv_sec = 1;
  t.tv_nsec = 0;

  _jove_sys_nanosleep_time32((void *)&t, NULL);
}

static int _jove_open(const char *path, int flags, mode_t mode) {
  return _jove_sys_open(path, flags, mode);
}

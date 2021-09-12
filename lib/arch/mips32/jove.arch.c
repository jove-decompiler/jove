uintptr_t _jove_alloc_stack(void) {
  long ret = _jove_sys_mips_mmap(0x0, JOVE_STACK_SIZE, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096) {
    _UNREACHABLE();
  }

  //
  // create guard pages on both sides
  //
  unsigned long beg = (unsigned long)ret;
  unsigned long end = beg + JOVE_STACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  return beg;
}

void _jove_free_stack(uintptr_t beg) {
  if (_jove_sys_munmap(beg, JOVE_STACK_SIZE) < 0) {
    _UNREACHABLE();
  }
}

uintptr_t _jove_alloc_callstack(void) {
  long ret =
      _jove_sys_mips_mmap(0x0, JOVE_CALLSTACK_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0 && ret > -4096) {
    _UNREACHABLE();
  }

  unsigned long uret = (unsigned long)ret;

  //
  // create guard pages on both sides
  //
  unsigned long beg = uret;
  unsigned long end = beg + JOVE_CALLSTACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    _UNREACHABLE();
  }

  return beg;
}

void _jove_free_callstack(uintptr_t start) {
  if (_jove_sys_munmap(start - JOVE_PAGE_SIZE /* XXX */, JOVE_CALLSTACK_SIZE) < 0) {
    _UNREACHABLE();
  }
}

typedef int32_t	old_time32_t;

struct old_timespec32 {
	old_time32_t	tv_sec;
	int32_t		tv_nsec;
};

void _jove_sleep(void) {
  struct old_timespec32 t;
  t.tv_sec = 1;
  t.tv_nsec = 0;

  _jove_sys_nanosleep_time32(&t, NULL);
}

extern /* __thread */ uint64_t *__jove_trace;
extern /* __thread */ uint64_t *__jove_trace_begin;

extern /* __thread */ uint64_t *__jove_callstack;
extern /* __thread */ uint64_t *__jove_callstack_begin;

extern uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES];

uintptr_t *__jove_foreign_function_tables[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

_HIDDEN void _jove_install_foreign_function_tables(void);

_CTOR static void _jove_initialize(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  _jove_install_foreign_function_tables();
  __jove_function_tables[_jove_binary_index()] = _jove_get_function_table();

  _jove_do_tpoff_hack();
  _jove_do_emulate_copy_relocations();
}

#if !defined(__x86_64__) && defined(__i386__)
_REGPARM
#endif
_HIDDEN void _jove_init(
#if defined(__x86_64__)
                        uint64_t rdi,
                        uint64_t rsi,
                        uint64_t rdx,
                        uint64_t rcx,
                        uint64_t r8,
                        uint64_t r9
#elif defined(__i386__)
                        uint32_t eax,
                        uint32_t edx,
                        uint32_t ecx
#elif defined(__aarch64__)
                        uint64_t x0,
                        uint64_t x1,
                        uint64_t x2,
                        uint64_t x3,
                        uint64_t x4,
                        uint64_t x5,
                        uint64_t x6,
                        uint64_t x7
#elif defined(__mips64__)
                        uint64_t a0,
                        uint64_t a1,
                        uint64_t a2,
                        uint64_t a3
#elif defined(__mips__)
                        uint32_t a0,
                        uint32_t a1,
                        uint32_t a2,
                        uint32_t a3
#else
#error
#endif
                                   ) {
  _jove_initialize();

  uintptr_t initfn = _jove_get_init_fn();
  if (!initfn)
    return;

  //
  // save things
  //
#if defined(__x86_64__) || defined(__i386__)
  const uintptr_t saved_emusp = __jove_env.regs[R_ESP];
#elif defined(__aarch64__)
  const uintptr_t saved_emusp = __jove_env.xregs[31];
#elif defined(__mips64__) || defined(__mips__)
  const uintptr_t saved_emusp = __jove_env.active_tc.gpr[29];
#else
#error
#endif

  const uintptr_t saved_callstack_begin = __jove_callstack_begin;
  const uintptr_t saved_callstack = __jove_callstack;

  //
  // setup new callstack and emulated-stack
  //
  const uintptr_t new_callstack = _jove_alloc_callstack();
  __jove_callstack_begin = __jove_callstack = new_callstack + JOVE_PAGE_SIZE;

  const uintptr_t new_emu_stack = _jove_alloc_stack();
  uintptr_t new_emusp = new_emu_stack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE;

#if defined(__x86_64__)
  new_emusp &= 0xfffffffffffffff0; // align the stack
  new_emusp -= sizeof(uint64_t); /* return address on the stack */

  __jove_env.regs[R_ESP] = new_emusp;
#elif defined(__i386__)
  new_emusp &= 0xfffffff0; // align the stack
  new_emusp -= sizeof(uint32_t); /* return address on the stack */

  __jove_env.regs[R_ESP] = new_emusp;
#elif defined(__aarch64__)
  new_emusp &= 0xfffffffffffffff0; // align the stack

  __jove_env.xregs[31 /* sp */] = new_emusp;
#elif defined(__mips64__)
  new_emusp &= 0xfffffffffffffff0; // align the stack

  __jove_env.active_tc.gpr[29 /* sp */] = new_emusp;
#elif defined(__mips__)
  new_emusp &= 0xfffffff0; // align the stack

  __jove_env.active_tc.gpr[29 /* sp */] = new_emusp;
#else
#error
#endif

  //
  // call the DT_INIT function
  //
#if defined(__x86_64__)
  ((void (*)(uint64_t,
             uint64_t,
             uint64_t,
             uint64_t,
             uint64_t,
             uint64_t))initfn)(rdi,
                               rsi,
                               rdx,
                               rcx,
                               r8,
                               r9);
#elif defined(__i386__)
  ((_REGPARM void (*)(uint32_t,
                      uint32_t,
                      uint32_t))initfn)(eax,
                                        edx,
                                        ecx);
#elif defined(__aarch64__)
  ((void (*)(uint64_t,
             uint64_t,
             uint64_t,
             uint64_t,
             uint64_t,
             uint64_t,
             uint64_t,
             uint64_t))initfn)(x0,
                               x1,
                               x2,
                               x3,
                               x4,
                               x5,
                               x6,
                               x7);
#elif defined(__mips64__)
  __jove_env.active_tc.gpr[25 /* t9 */] = _jove_get_init_fn_sect_ptr();

  ((void (*)(uint64_t,
             uint64_t,
             uint64_t,
             uint64_t))initfn)(a0,
                               a1,
                               a2,
                               a3);
#elif defined(__mips__)
  __jove_env.active_tc.gpr[25 /* t9 */] = _jove_get_init_fn_sect_ptr();

  ((void (*)(uint32_t,
             uint32_t,
             uint32_t,
             uint32_t))initfn)(a0,
                               a1,
                               a2,
                               a3);
#else
#error
#endif

  //
  // restore things
  //
#if defined(__x86_64__) || defined(__i386__)
  __jove_env.regs[R_ESP] = saved_emusp;
#elif defined(__aarch64__)
  __jove_env.xregs[31 /* sp */] = saved_emusp;
#elif defined(__mips64__) || defined(__mips__)
  __jove_env.active_tc.gpr[29 /* sp */] = saved_emusp;
#else
#error
#endif

  __jove_callstack_begin = saved_callstack_begin;
  __jove_callstack = saved_callstack;

  _jove_free_stack(new_emu_stack);
  _jove_free_callstack(new_callstack);
}

static _INL uintptr_t _parse_vdso_load_bias(char *maps, const unsigned n) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = _memchr(line, '\n', left);

    //
    // second hex address
    //
    if (eol[-1] == ']' &&
        eol[-2] == 'o' &&
        eol[-3] == 's' &&
        eol[-4] == 'd' &&
        eol[-5] == 'v' &&
        eol[-6] == '[') {
      char *dash = _memchr(line, '-', left);
      return _u64ofhexstr(line, dash);
    }
  }

  _UNREACHABLE();
}

static _INL uintptr_t _parse_dynl_load_bias(char *maps, const unsigned n) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  const char *const dynl_path_beg = _jove_dynl_path();
  const unsigned    dynl_path_len = _strlen(dynl_path_beg);
  const char *const dynl_path_end = &dynl_path_beg[dynl_path_len];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = _memchr(line, '\n', left);

    //
    // second hex address
    //
    bool match = true;

    {
      const char *s1 = dynl_path_end - 1;
      const char *s2 = eol - 1;
      for (;;) {
        if (*s1 != *s2) {
          match = false;
          break;
        }

        if (s1 == dynl_path_beg)
          break; /* we're done here */

        --s1;
        --s2;
      }
    }

    if (match) {
      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      bool x = *xp == 'x';
      if (!x)
        continue;

      char *dash = _memchr(line, '-', left);
      uint64_t res = _u64ofhexstr(line, dash);

      // offset may be nonzero for dynamic linker
      uint64_t off;
      {
        char *offset = pp + 2;
        unsigned _left = n - (offset - beg);
        char *offset_end = _memchr(offset, ' ', _left);

        off = _u64ofhexstr(offset, offset_end);
      }

      return res - off;
    }
  }

  _UNREACHABLE();
}


void _jove_install_foreign_function_tables(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  /* we need to get the load addresses for the dynamic linker and VDSO by
   * parsing /proc/self/maps */
  char maps[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[n] = '\0';

  uintptr_t dynl_load_bias = _parse_dynl_load_bias(maps, n);
  uintptr_t vdso_load_bias = _parse_vdso_load_bias(maps, n);

  uintptr_t *dynl_fn_tbl = _jove_get_dynl_function_table();
  uintptr_t *vdso_fn_tbl = _jove_get_vdso_function_table();

  for (uintptr_t *p = dynl_fn_tbl; *p; ++p)
    *p += dynl_load_bias;
  for (uintptr_t *p = vdso_fn_tbl; *p; ++p)
    *p += vdso_load_bias;

  __jove_foreign_function_tables[1] = dynl_fn_tbl;
  __jove_foreign_function_tables[2] = vdso_fn_tbl;

  unsigned N = _jove_foreign_lib_count();
  if (N > 0) {
    char *const beg = &maps[0];
    char *const end = &maps[n];

    char *eol;
    for (char *line = beg; line != end; line = eol + 1) {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);

      char *space = _memchr(line, ' ', left);

      char *rp = space + 1;
      char *wp = space + 2;
      char *xp = space + 3;
      char *pp = space + 4;

      if (*xp != 'x') /* is the mapping executable? */
        continue;

      char *dash = _memchr(line, '-', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      //
      // found the mapping where the address is located
      //
      uint64_t off;
      {
        char *offset = pp + 2;
        char *offset_end = _memchr(offset, ' ', n - (offset - beg));

        off = _u64ofhexstr(offset, offset_end);
      }

      //
      // search the foreign libs
      //
      for (unsigned i = 0; i < N; ++i) {
        const char *foreign_dso_path_beg = _jove_foreign_lib_path(i);
        const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
        const char *foreign_dso_path_end = &foreign_dso_path_beg[foreign_dso_path_len];

        bool match = true;
        {
          const char *s1 = foreign_dso_path_end - 1;
          const char *s2 = eol - 1;
          for (;;) {
            if (*s1 != *s2) {
              match = false;
              break;
            }

            if (s1 == foreign_dso_path_beg)
              break; /* we're done here */

            --s1;
            --s2;
          }
        }

        if (match && __jove_foreign_function_tables[i + 3] == NULL) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          uintptr_t load_bias = min - off;
          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          break;
        }
      }
    }
  }
}

static bool _jove_is_readable_mem(uintptr_t Addr) {
  pid_t pid;
  {
    long ret = _jove_sys_getpid();
    if (unlikely(ret < 0))
      _UNREACHABLE();

    pid = ret;
  }

  struct iovec lvec[1];
  struct iovec rvec[1];

  uint8_t byte;

  lvec[0].iov_base = &byte;
  lvec[0].iov_len = sizeof(byte);

  rvec[0].iov_base = (void *)Addr;
  rvec[0].iov_len = sizeof(byte);

  long ret = _jove_sys_process_vm_readv(pid,
                                        lvec, ARRAY_SIZE(lvec),
                                        rvec, ARRAY_SIZE(rvec),
                                        0);

  return ret == sizeof(byte);
}

static _INL uintptr_t _get_stack_end(void) {
  char buff[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
  buff[n] = '\0';

  uintptr_t res = _parse_stack_end_of_maps(buff, n);
  return res;
}

_NORET void _jove_fail1(uintptr_t a0) {
  char maps[4096 * 8];
  const unsigned n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[n] = '\0';

  {
    char s[4096 * 8];
    s[0] = '\0';

    _strcat(s, "_jove_fail1: 0x");
    {
      char buff[65];
      _uint_to_string(a0, buff, 0x10);

      _strcat(s, buff);
    }
    {
      char buff[65];
      _description_of_address_for_maps(buff, a0, maps, n);
      _strcat(s, " <");
      _strcat(s, buff);
      _strcat(s, "> [");
    }

    {
      char buff[65];
      _uint_to_string(_jove_sys_gettid(), buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, "]\n");
    _strcat(s, maps);

    //
    // dump message for user
    //
    _robust_write(2 /* stderr */, s, _strlen(s));
  }

  for (;;)
    _jove_sleep();

  __builtin_unreachable();
}

_NORET void _jove_fail2(uintptr_t a0,
                        uintptr_t a1) {
  char maps[4096 * 8];
  const unsigned n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[n] = '\0';

  {
    char s[4096 * 8];
    s[0] = '\0';

    _strcat(s, "_jove_fail2: 0x");
    {
      char buff[65];
      _uint_to_string(a0, buff, 0x10);

      _strcat(s, buff);
    }
    {
      char buff[65];
      _description_of_address_for_maps(buff, a0, maps, n);
      _strcat(s, " <");
      _strcat(s, buff);
      _strcat(s, ">");
    }
    _strcat(s, "\n             0x");
    {
      char buff[65];
      _uint_to_string(a0, buff, 0x10);

      _strcat(s, buff);
    }
    {
      char buff[65];
      _description_of_address_for_maps(buff, a1, maps, n);
      _strcat(s, " <");
      _strcat(s, buff);
      _strcat(s, "> [");
    }

    {
      char buff[65];
      _uint_to_string(_jove_sys_gettid(), buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, "]\n");
    _strcat(s, maps);

    //
    // dump message for user
    //
    _robust_write(2 /* stderr */, s, _strlen(s));
  }

  for (;;)
    _jove_sleep();

  __builtin_unreachable();
}

#if defined(JOVE_DFSAN)
void _jove_check_return_address(uintptr_t RetAddr,
                                uintptr_t NativeRetAddr) {
  return;

  if (RetAddr == 0x0 /* XXX? */ || _jove_is_readable_mem(RetAddr))
    return;

#if 1
  _jove_fail2(RetAddr, NativeRetAddr);
#else
  _UNREACHABLE("stack smashing detected");
#endif
}

#if (defined(__mips__) && !defined(__mips64)) || \
    (defined(__i386__) && !defined(__x86_64__))
//
// 32-bit DFSan
//
extern struct shadow_t __df32_shadow_mem[65536];

static dfsan_label *__df32_shadow_for(uint32_t A) {
  const uint16_t AddrUpperBits = A >> 16;
  const uint16_t AddrLowerBits = A & 0xFFFF;

  unsigned Region = AddrLowerBits / JOVE_SHADOW_REGION_SIZE;
  unsigned Offset = AddrLowerBits % JOVE_SHADOW_REGION_SIZE;

  dfsan_label **shadowp = &__df32_shadow_mem[AddrUpperBits].X[Region];

  dfsan_label *shadow = *shadowp;
  if (unlikely(!shadow)) {
#if defined(__mips__)
    unsigned long shadow_base = _jove_sys_mips_mmap(0x0, JOVE_SHADOW_SIZE,
                                                    PROT_READ | PROT_WRITE,
                                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                                    -1L, 0);
#elif defined(__i386__)
    unsigned long shadow_base = _jove_sys_mmap_pgoff(0x0, JOVE_SHADOW_SIZE,
                                                     PROT_READ | PROT_WRITE,
                                                     MAP_PRIVATE | MAP_ANONYMOUS,
                                                     -1L, 0);
#else
#error
#endif

    if (IS_ERR_VALUE(shadow_base)) {
      __builtin_trap();
      __builtin_unreachable();
    }

    shadow = (dfsan_label *)shadow_base;

    *shadowp = shadow;
  }

  return &shadow[Offset];
}

#endif
#endif

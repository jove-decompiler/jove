_CTOR static void _jove_install_foreign_function_tables(void);

_CTOR static void _jove_tpoff_hack(void) {
  _jove_do_tpoff_hack();
}

static bool __jove_did_emu_copy_reloc = false;

_CTOR static void _jove_emulate_copy_relocations(void) {
  if (!__jove_did_emu_copy_reloc) {
    __jove_did_emu_copy_reloc = true;

    _jove_do_emulate_copy_relocations();
  }
}

_CTOR _HIDDEN void _jove_install_function_table(void) {
  _jove_install_foreign_function_tables();

  __jove_function_tables[_jove_binary_index()] = _jove_get_function_table();
  _jove_do_tpoff_hack(); /* for good measure */

  if (!__jove_did_emu_copy_reloc) {
    __jove_did_emu_copy_reloc = true;

    _jove_do_emulate_copy_relocations();
  }
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
  static bool Done = false;
  if (Done)
    return;
  Done = true;

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

static bool _jove_is_readable_mem(uintptr_t Addr);

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
  if (RetAddr == 0x0 /* XXX? */ || _jove_is_readable_mem(RetAddr))
    return;

#if 1
  _jove_fail2(RetAddr, NativeRetAddr);
#else
  _UNREACHABLE("stack smashing detected");
#endif
}

#if defined(__mips__) || defined(__i386__)
//
// 32-bit DFSan
//

typedef uint16_t dfsan_label;

#define JOVE_SHADOW_NUM_REGIONS 32
#define JOVE_SHADOW_REGION_SIZE (0x10000 / JOVE_SHADOW_NUM_REGIONS)
#define JOVE_SHADOW_SIZE (sizeof(dfsan_label) * JOVE_SHADOW_REGION_SIZE)

struct shadow_t {
  uint16_t *X[JOVE_SHADOW_NUM_REGIONS];
};

extern struct shadow_t __df32_shadow_mem[65536];

static dfsan_label *__df32_shadow_for(uint32_t A) {
  const uint16_t AddrUpperBits = A >> 16;
  const uint16_t AddrLowerBits = A & 0xFFFF;

  unsigned Region = AddrLowerBits / JOVE_SHADOW_REGION_SIZE;
  unsigned Offset = AddrLowerBits % JOVE_SHADOW_REGION_SIZE;

  struct dfsan_label **shadowp = &__df32_shadow_mem[AddrUpperBits].X[Region];

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

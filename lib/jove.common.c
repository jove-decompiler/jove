extern /* __thread */ uint64_t *__jove_trace;
extern /* __thread */ uint64_t *__jove_trace_begin;

       static uint64_t **__jove_trace_clunk = &__jove_trace;
       static uint64_t **__jove_trace_begin_clunk = &__jove_trace_begin;

extern /* __thread */ uint64_t *__jove_callstack;
extern /* __thread */ uint64_t *__jove_callstack_begin;

       static uint64_t **__jove_callstack_clunk = &__jove_callstack;
       static uint64_t **__jove_callstack_begin_clunk = &__jove_callstack_begin;

extern uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES];
extern uintptr_t *__jove_sections_tables[_JOVE_MAX_BINARIES];

       static uintptr_t **__jove_function_tables_clunk = &__jove_function_tables;
       static uintptr_t **__jove_sections_tables_clunk = &__jove_sections_tables;

extern uintptr_t *__jove_foreign_function_tables[_JOVE_MAX_BINARIES];

extern DECLARE_HASHTABLE(__jove_function_map, JOVE_FUNCTION_MAP_HASH_BITS);

extern void _jove_flush_trace(void);

typedef void (*__jove_flush_trace_t)(void);
static __jove_flush_trace_t _jove_flush_trace_clunk = &_jove_flush_trace;

_HIDDEN void _jove_install_foreign_function_tables(void);

#if defined(JOVE_DFSAN)
extern void __dfsan_log_global_buffers(void);
#endif

static void _jove_install_function_table(void);
static void _jove_install_sections_table(void);

static void _jove_install_function_mappings(void);

static void _jove_make_sections_executable(void);

extern void _jove_rt_init(void);

_HIDDEN void _jove_initialize(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  _jove_install_foreign_function_tables();

  _jove_install_function_table();
  _jove_install_sections_table();

  _jove_install_function_mappings();

  _jove_do_manual_relocations();
  _jove_do_emulate_copy_relocations();

#if defined(JOVE_DFSAN)
  __dfsan_log_global_buffers();
#endif

  _jove_make_sections_executable();
}

void _jove_install_function_table(void) {
  __jove_function_tables_clunk[_jove_binary_index()] = _jove_get_function_table();
}

void _jove_install_sections_table(void) {
  static uintptr_t _Entry[3];

  _Entry[0] = _jove_sections_global_beg_addr();
  _Entry[1] = _jove_sections_global_end_addr();
  _Entry[2] = _jove_sections_start_file_addr();

  __jove_sections_tables_clunk[_jove_binary_index()] = &_Entry[0];
}

void _jove_make_sections_executable(void) {
  const unsigned n = QEMU_ALIGN_UP(_jove_sections_global_end_addr() -
                                   _jove_sections_global_beg_addr(), JOVE_PAGE_SIZE);
  const uintptr_t x = QEMU_ALIGN_DOWN(_jove_sections_global_beg_addr(), JOVE_PAGE_SIZE);

  if (_jove_sys_mprotect(x, n, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
    _UNREACHABLE("failed to make sections executable\n");
}

void _jove_install_function_mappings(void) {
  //
  // allocate memory for function_info_t structures
  //
  uintptr_t fninfo_arr_addr = _mmap_rw_anonymous_private_memory(
      QEMU_ALIGN_UP(_jove_function_count() * sizeof(struct _jove_function_info_t),
      JOVE_PAGE_SIZE));

  if (IS_ERR_VALUE(fninfo_arr_addr))
    _UNREACHABLE("failed to allocate memory for function_info_t array");

  //
  // add the mappings
  //
  memory_barrier();
  {
    struct _jove_function_info_t *fninfo_p =
        (struct _jove_function_info_t *)fninfo_arr_addr;

    unsigned FIdx = 0;
    for (uintptr_t *fn_p = _jove_get_function_table(); fn_p[0]; fn_p += 3) {
      fninfo_p->BIdx = _jove_binary_index();
      fninfo_p->FIdx = FIdx++;

      fninfo_p->IsForeign = 0;

      fninfo_p->Recompiled.SectPtr = fn_p[0];
      fninfo_p->RecompiledFunc     = fn_p[2];

      hash_add(__jove_function_map, &fninfo_p->hlist, fninfo_p->pc /* key */);

      ++fninfo_p;
    }
  }
  memory_barrier();
}

typedef void (*_jove_rt_init_t)(void);
static _jove_rt_init_t _jove_rt_init_clunk = &_jove_rt_init;

#if defined(__aarch64__)
_HIDDEN void _jove_init(
                        #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) uintptr_t reg##i

                        BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                        #undef __REG_ARG
                       ) {
  //
  // magic sequence of NOP instructions...
  //
#if defined(__aarch64__)
  asm("mov xzr, x0\n"
      "mov xzr, x1\n"
      "mov xzr, x2\n"
      "mov xzr, x3\n"
      "mov xzr, x4\n"
      "mov xzr, x5\n"
      "mov xzr, x6\n"
      "mov xzr, x7\n"
      "mov xzr, x8\n"
      "mov xzr, x7\n"
      "mov xzr, x6\n"
      "mov xzr, x5\n"
      "mov xzr, x4\n"
      "mov xzr, x3\n"
      "mov xzr, x2\n"
      "mov xzr, x1\n"
      "mov xzr, x0\n");
#else
#error
#endif

  _jove_initialize();

  const uintptr_t initfn = _jove_get_init_fn();
  if (!initfn)
    return;

  target_ulong *const emusp_ptr = emulated_stack_pointer_of_cpu_state(__jove_env_clunk);

  //
  // save things
  //
  const uintptr_t saved_emusp = *emusp_ptr;

  uint64_t *const saved_callstack_begin = *__jove_callstack_begin_clunk;
  uint64_t *const saved_callstack = *__jove_callstack_clunk;

  //
  // setup new callstack and emulated-stack
  //
  const uintptr_t new_callstack = _jove_alloc_callstack() + JOVE_PAGE_SIZE;
  *__jove_callstack_begin_clunk = *__jove_callstack_clunk = (uint64_t *)new_callstack;

  const uintptr_t new_emu_stack = _jove_alloc_stack();

  uintptr_t new_emusp = new_emu_stack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE;

  {
    //
    // align the emulated stack
    //
    const uintptr_t align_val = 15;
    const uintptr_t align_mask = ~align_val;

    new_emusp &= align_mask;
  }

#if defined(__x86_64__)
  new_emusp -= sizeof(uint64_t); /* return address on the stack */
#endif

  *emusp_ptr = new_emusp;

#if defined(__mips64) || defined(__mips__)
  //
  // (mips) set t9
  //
  __jove_env_clunk->active_tc.gpr[25] = _jove_get_init_fn_sect_ptr();
#endif

  //
  // call the DT_INIT function
  //
  ((void (*)(
             #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) uintptr_t

             BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

             #undef __REG_ARG
            ))initfn)(
                      #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) reg##i

                      BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                      #undef __REG_ARG
                     );

  //
  // restore things
  //
  *emusp_ptr = saved_emusp;

  *__jove_callstack_begin_clunk = saved_callstack_begin;
  *__jove_callstack_clunk = saved_callstack;

  _jove_free_stack(new_emu_stack);
  _jove_free_callstack(new_callstack);
}

//
// XXX hack for glibc 2.32+
//
_HIDDEN void _jove__libc_early_init(
                                    #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) uintptr_t reg##i

                                    BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                                    #undef __REG_ARG
                                   ) {
  _jove_rt_init_clunk();

  const uintptr_t fn = _jove_get_libc_early_init_fn();
  if (!fn)
    return;

  _jove_initialize();

  target_ulong *const emusp_ptr = emulated_stack_pointer_of_cpu_state(__jove_env_clunk);

  //
  // save things
  //
  const uintptr_t saved_emusp = *emusp_ptr;

  uint64_t *const saved_callstack_begin = *__jove_callstack_begin_clunk;
  uint64_t *const saved_callstack = *__jove_callstack_clunk;

  //
  // setup new callstack and emulated-stack
  //
  const uintptr_t new_callstack = _jove_alloc_callstack() + JOVE_PAGE_SIZE;
  *__jove_callstack_begin_clunk = *__jove_callstack_clunk = (uint64_t *)new_callstack;

  const uintptr_t new_emu_stack = _jove_alloc_stack();

  uintptr_t new_emusp = new_emu_stack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE;

  {
    //
    // align the emulated stack
    //
    const uintptr_t align_val = 15;
    const uintptr_t align_mask = ~align_val;

    new_emusp &= align_mask;
  }

#if defined(__x86_64__)
  new_emusp -= sizeof(uint64_t); /* return address on the stack */
#endif

  *emusp_ptr = new_emusp;

#if defined(__mips64) || defined(__mips__)
  //
  // (mips) set t9
  //
  __jove_env_clunk->active_tc.gpr[25] = _jove_get_libc_early_init_fn_sect_ptr();
#endif

  //
  // call the real __libc_early_init
  //
  ((void (*)(
             #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) uintptr_t

             BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

             #undef __REG_ARG
            ))fn)(
                  #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) reg##i

                  BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                  #undef __REG_ARG
                 );

  //
  // restore things
  //
  *emusp_ptr = saved_emusp;

  *__jove_callstack_begin_clunk = saved_callstack_begin;
  *__jove_callstack_clunk = saved_callstack;

  _jove_free_stack(new_emu_stack);
  _jove_free_callstack(new_callstack);
}

#else
//
// see definition of _jove_init and _jove__libc_early_init in lib/arch/<arch>/jove.c
//
#endif

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

  _UNREACHABLE("failed to find dynamic linker");
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

  _UNREACHABLE("failed to find [vdso]");
}

void _jove_install_foreign_function_tables(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  /* we need to get the load addresses for the dynamic linker and VDSO by
   * parsing /proc/self/maps */
  char maps[JOVE_PROC_MAPS_BUF_LEN];
  unsigned n = _jove_read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
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

  //
  // allocate memory for function_info_t structures
  //
  uintptr_t fninfo_arr_addr = _mmap_rw_anonymous_private_memory(
      QEMU_ALIGN_UP(_jove_foreign_functions_count() * sizeof(struct _jove_function_info_t),
      JOVE_PAGE_SIZE));

  if (IS_ERR_VALUE(fninfo_arr_addr))
    _UNREACHABLE("failed to allocate memory for function_info_t array");

  //
  // install function mappings
  //
  memory_barrier();
  {
    struct _jove_function_info_t *fninfo_p =
        (struct _jove_function_info_t *)fninfo_arr_addr;

    for (unsigned BIdx = 1; BIdx < 3 + N; ++BIdx) {
      uintptr_t *fns = __jove_foreign_function_tables[BIdx];
      if (!fns)
        continue;

      for (unsigned FIdx = 0; fns[FIdx]; ++FIdx) {
        fninfo_p->BIdx = BIdx;
        fninfo_p->FIdx = FIdx;

        fninfo_p->IsForeign = 1;

        fninfo_p->Foreign.Func = fns[FIdx];

        hash_add(__jove_function_map, &fninfo_p->hlist, fninfo_p->pc /* key */);

        ++fninfo_p;
      }
    }
  }
  memory_barrier();
}

_NORET void _jove_fail1(uintptr_t a0, const char *reason) {
  char maps[JOVE_PROC_MAPS_BUF_LEN];
  const unsigned n = _jove_read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[n] = '\0';

  {
    char s[JOVE_PROC_MAPS_BUF_LEN];
    s[0] = '\0';

    _strcat(s, "_jove_fail1: ");
    _strcat(s, reason);
    _strcat(s, "\n0x");
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

    _strcat(s, "]\n\n");
    _strcat(s, maps);

    //
    // dump message for user
    //
    _jove_robust_write(2 /* stderr */, s, _strlen(s));
  }

  _jove_flush_trace_clunk();

#if 1
  for (;;)
    _jove_sleep();
#else
  _jove_sys_exit_group(0x77);
#endif

  __builtin_unreachable();
}

_NORET void _jove_fail2(uintptr_t a0,
                        uintptr_t a1) {
  char maps[JOVE_PROC_MAPS_BUF_LEN];
  const unsigned n = _jove_read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[n] = '\0';

  {
    char s[JOVE_PROC_MAPS_BUF_LEN];
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
    _jove_robust_write(2 /* stderr */, s, _strlen(s));
  }

  for (;;)
    _jove_sleep();

  __builtin_unreachable();
}

void _jove_log1(const char *msg,
                uintptr_t x) {
  char s[4096 * 8];
  s[0] = '\0';

  _strcat(s, msg);

  _strcat(s, " (0x");
  {
    char buff[65];
    _uint_to_string(x, buff, 0x10);

    _strcat(s, buff);
  }
  _strcat(s, ")\n");

  _jove_robust_write(2 /* stderr */, s, _strlen(s));
}

void _jove_log2(const char *msg,
                uintptr_t x,
                uintptr_t y) {
  char s[4096 * 8];
  s[0] = '\0';

  _strcat(s, msg);

  _strcat(s, " (0x");
  {
    char buff[65];
    _uint_to_string(x, buff, 0x10);

    _strcat(s, buff);
  }
  _strcat(s, ", 0x");
  {
    char buff[65];
    _uint_to_string(y, buff, 0x10);

    _strcat(s, buff);
  }
  _strcat(s, ")\n");

  _jove_robust_write(2 /* stderr */, s, _strlen(s));
}

_HIDDEN void _jove_recover_function(uint32_t IndCallBBIdx,
                                    uintptr_t FuncAddr);

_HIDDEN
#if !defined(__x86_64__) && defined(__i386__)
_REGPARM
#endif
jove_thunk_return_t _jove_call(
                               #define __REG_ARG(n, i, data) uintptr_t reg##i,

                               BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                               #undef __REG_ARG

                               uintptr_t pc, uint32_t BBIdx) {
  _jove_install_foreign_function_tables();

  struct _jove_function_info_t Callee;

  //
  // lookup in __jove_function_map
  //
  {
    struct _jove_function_info_t *finfo;

    hash_for_each_possible(__jove_function_map, finfo, hlist, pc) {
      if (finfo->pc != pc) {
        continue;
      } else {
        Callee = *finfo;

        goto found;
      }
    }
  }

  //
  // lookup in __jove_function_map failed, now try brute force search
  //
  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES ; ++BIdx) {
    uintptr_t *fns = __jove_function_tables_clunk
                         ? __jove_function_tables_clunk[BIdx]
                         : NULL;
    if (!fns) {
      if (BIdx == 1 ||
          BIdx == 2) { /* rtld or vdso */
        fns = __jove_foreign_function_tables[BIdx];
        if (!fns) {
          _UNREACHABLE("_jove_call: rtld or vdso function table is NULL!");
          continue;
        }
      } else {
        continue;
      }
    }

    if (BIdx == 1 || BIdx == 2) { /* XXX */
      for (unsigned FIdx = 0; fns[FIdx]; ++FIdx) {
        if (pc == fns[FIdx]) {
          Callee.IsForeign = 1;

          Callee.BIdx = BIdx;
          Callee.FIdx = FIdx;

          Callee.Foreign.Func = pc;

          goto found;
        }
      }
    } else {
      for (unsigned FIdx = 0; fns[3 * FIdx]; ++FIdx) {
        if (pc == fns[3 * FIdx + 0]) {
          Callee.IsForeign = 0;

          Callee.BIdx = BIdx;
          Callee.FIdx = FIdx;

          Callee.Recompiled.SectPtr = pc;
          Callee.RecompiledFunc = fns[3 * FIdx + 2];

          goto found;
        }
      }
    }
  }

  unsigned N = _jove_foreign_lib_count();

  bool FoundAll = true;
  for (unsigned j = 3; j < N + 3; ++j) {
    if (__jove_foreign_function_tables[j] == NULL) {
      FoundAll = false;
      break;
    }
  }

  if (!FoundAll) {
    char maps[JOVE_PROC_MAPS_BUF_LEN];
    unsigned n = _jove_read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
    maps[n] = '\0';

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

  if (N > 0) {
    //
    // see if this is a function in a foreign DSO
    //
    char maps[JOVE_PROC_MAPS_BUF_LEN];
    unsigned n = _jove_read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
    maps[n] = '\0';

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

      if (!(pc >= min && pc < max))
        continue;

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

        if (match) {
          uintptr_t *ForeignFnTbl = _jove_foreign_lib_function_table(i);

          for (unsigned FIdx = 0; ForeignFnTbl[FIdx]; ++FIdx) {
            if (pc == ForeignFnTbl[FIdx]) {
              Callee.IsForeign = 1;

              Callee.BIdx = i + 3;
              Callee.FIdx = FIdx;

              Callee.Foreign.Func = pc;

              goto found;
            }
          }
        }
      }
    }
  }

  //
  // check for the possibility that _jove_init is our given pc, which may happen
  // if the code (usually in the dynamic linker) that calls the init functions
  // of a newly dlopen'd shared library is, itself, recompiled. to know whether
  // _jove_init is being called, we look for a unique sequence of nop
  // instructions that are hard-coded into the function's (asm) definition
  //
  bool IsJoveInit = false;

#if defined(__mips64) || defined(__mips__)

#  if defined(__mips64)
#    define PC_OFF_IN_WORDS 12
#  else /* defined(__mips__) */
#    define PC_OFF_IN_WORDS 10
#  endif

  {
    const uint32_t *const p = (const uint32_t *)pc + PC_OFF_IN_WORDS;

#  undef PC_OFF_IN_WORDS

    //
    // 24000929        li      zero,2345
    // 24000159        li      zero,345
    // 2400002d        li      zero,45
    // 24000005        li      zero,5
    // 24000036        li      zero,54
    // 2400021f        li      zero,543
    // 24001538        li      zero,5432
    //

    IsJoveInit = p[0] == 0x24000929 &&
                 p[1] == 0x24000159 &&
                 p[2] == 0x2400002d &&
                 p[3] == 0x24000005 &&
                 p[4] == 0x24000036 &&
                 p[5] == 0x2400021f &&
                 p[6] == 0x24001538;
  }
#elif defined(__x86_64__)
  {
    const uint8_t *const p = (const uint8_t *)pc;

    //
    // 4d 87 ff                xchg   %r15,%r15
    // 4d 87 f6                xchg   %r14,%r14
    // 4d 87 ed                xchg   %r13,%r13
    // 4d 87 e4                xchg   %r12,%r12
    // 4d 87 db                xchg   %r11,%r11
    //

    IsJoveInit = p[0*3+0] == 0x4d && p[0*3+1] == 0x87 && p[0*3+2] == 0xff &&
                 p[1*3+0] == 0x4d && p[1*3+1] == 0x87 && p[1*3+2] == 0xf6 &&
                 p[2*3+0] == 0x4d && p[2*3+1] == 0x87 && p[2*3+2] == 0xed &&
                 p[3*3+0] == 0x4d && p[3*3+1] == 0x87 && p[3*3+2] == 0xe4 &&
                 p[4*3+0] == 0x4d && p[4*3+1] == 0x87 && p[4*3+2] == 0xdb;
  }
#elif defined(__i386__)
  {
    const uint8_t *const p = (const uint8_t *)pc;

    //
    // 87 db                   xchg   %ebx,%ebx
    // 87 c9                   xchg   %ecx,%ecx
    // 87 d2                   xchg   %edx,%edx
    // 87 f6                   xchg   %esi,%esi
    // 87 ff                   xchg   %edi,%edi
    //

    IsJoveInit = p[0*2+0] == 0x87 && p[0*2+1] == 0xdb &&
                 p[1*2+0] == 0x87 && p[1*2+1] == 0xc9 &&
                 p[2*2+0] == 0x87 && p[2*2+1] == 0xd2 &&
                 p[3*2+0] == 0x87 && p[3*2+1] == 0xf6 &&
                 p[4*2+0] == 0x87 && p[4*2+1] == 0xff;
  }
#elif defined(__aarch64__)
  {
    static const uint32_t magic_insns[] = {
      0xaa0003ff,  // mov xzr, x0
      0xaa0103ff,  // mov xzr, x1
      0xaa0203ff,  // mov xzr, x2
      0xaa0303ff,  // mov xzr, x3
      0xaa0403ff,  // mov xzr, x4
      0xaa0503ff,  // mov xzr, x5
      0xaa0603ff,  // mov xzr, x6
      0xaa0703ff,  // mov xzr, x7
      0xaa0803ff,  // mov xzr, x8
      0xaa0703ff,  // mov xzr, x7
      0xaa0603ff,  // mov xzr, x6
      0xaa0503ff,  // mov xzr, x5
      0xaa0403ff,  // mov xzr, x4
      0xaa0303ff,  // mov xzr, x3
      0xaa0203ff,  // mov xzr, x2
      0xaa0103ff,  // mov xzr, x1
      0xaa0003ff,  // mov xzr, x0
    };

    IsJoveInit = !!_memmem((const uint8_t *)pc, 2 * sizeof(magic_insns),
                           &magic_insns[0], sizeof(magic_insns));
  }
#else
#error
#endif

  if (unlikely(IsJoveInit))
    return BOOST_PP_CAT(_jove_thunk,TARGET_NUM_REG_ARGS)(
                        #define __REG_ARG(n, i, data) reg##i,

                        BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                        #undef __REG_ARG
                        pc, emulated_stack_pointer_of_cpu_state(__jove_env_clunk));

  //
  // we found new code?
  //
  _jove_recover_function(BBIdx, pc);

  {
    _jove_fail1(pc, "_jove_call failed");

    __builtin_unreachable();
  }

found:
  if (Callee.IsForeign) {
    if (unlikely(!__jove_env_clunk)) {
      //
      // when might __jove_env_clunk be NULL? in an ifunc resolver, that's when
      //
      uintptr_t dummy_stack = _jove_alloc_stack();

      typeof(__jove_env) dummy_env = {0};

      target_ulong *const emusp_ptr = emulated_stack_pointer_of_cpu_state(&dummy_env);

      *emusp_ptr = dummy_stack + JOVE_STACK_SIZE - 2 * JOVE_PAGE_SIZE;

      jove_thunk_return_t res =
             BOOST_PP_CAT(_jove_thunk,TARGET_NUM_REG_ARGS)(
                          #define __REG_ARG(n, i, data) reg##i,

                          BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                          #undef __REG_ARG
                          pc, emusp_ptr);

      _jove_free_stack(dummy_stack);

      return res;
    } else {
      target_ulong *const emusp_ptr = emulated_stack_pointer_of_cpu_state(__jove_env_clunk);

      return BOOST_PP_CAT(_jove_thunk,TARGET_NUM_REG_ARGS)(
                          #define __REG_ARG(n, i, data) reg##i,

                          BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                          #undef __REG_ARG
                          pc, emusp_ptr);
    }
  } else {
#if !defined(__x86_64__) && defined(__i386__)
#define CALLCONV_ATTR _REGPARM
#else
#define CALLCONV_ATTR
#endif

    return ((CALLCONV_ATTR jove_thunk_return_t (*)(
                         #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) uintptr_t

                         BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                         #undef __REG_ARG
                         ))Callee.RecompiledFunc)(
                                                 #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) reg##i

                                                 BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                                                 #undef __REG_ARG
                                                 );
#undef CALLCONV_ATTR
  }
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
static struct shadow_t *__df32_shadow_mem_clunk = &__df32_shadow_mem[0];

static dfsan_label *__df32_shadow_for(uint32_t A) {
  const uint16_t AddrUpperBits = A >> 16;
  const uint16_t AddrLowerBits = A & 0xFFFF;

  unsigned Region = AddrLowerBits / JOVE_SHADOW_REGION_SIZE;
  unsigned Offset = AddrLowerBits % JOVE_SHADOW_REGION_SIZE;

  dfsan_label **shadowp = &__df32_shadow_mem_clunk[AddrUpperBits].X[Region];

  dfsan_label *shadow = *shadowp;
  if (unlikely(!shadow)) {
    uintptr_t shadow_base = _mmap_rw_anonymous_private_memory(JOVE_SHADOW_SIZE);

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

void __nodce(void **p) {
  *p++ = &__jove_trace_clunk;
  *p++ = &__jove_trace_begin_clunk;
  *p++ = &_jove_trace_enabled;
  *p++ = &_jove_dfsan_enabled;
  *p++ = &_jove_get_init_fn_sect_ptr;
  *p++ = &_jove_get_libc_early_init_fn;
  *p++ = &_jove_get_libc_early_init_fn_sect_ptr;
  *p++ = &__jove_callstack_clunk;
  *p++ = &__jove_callstack_begin_clunk;
  *p++ = &_jove_flush_trace_clunk;
  *p++ = &_jove_rt_init_clunk;
  *p++ = &__jove_function_tables_clunk;
  *p++ = &__jove_sections_tables_clunk;
  *p++ = &__jove_env_clunk;
  *p++ = &_jove_alloc_stack;
  *p++ = &_jove_free_stack;
  *p++ = &_jove_alloc_callstack;
  *p++ = &_jove_free_callstack;
  *p++ = &_jove_call;
#ifdef JOVE_DFSAN
#if (defined(__mips__) && !defined(__mips64)) || \
    (defined(__i386__) && !defined(__x86_64__))
  *p++ = &__df32_shadow_for;
  *p++ = &__df32_shadow_mem_clunk;
#endif
#endif
}

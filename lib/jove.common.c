extern __JTHREAD struct CPUArchState __jove_env __attribute__((aligned(64)));

#ifdef JOVE_MT
static /* __thread */ struct CPUArchState __jove_local_env;
#endif

static /* __thread */ struct CPUArchState *__jove_env_clunk =
#ifdef JOVE_MT
    &__jove_local_env
#else
    &__jove_env
#endif
    ;

extern __JTHREAD uint64_t *__jove_trace;
extern __JTHREAD uint64_t *__jove_trace_begin;

extern __JTHREAD uint64_t *__jove_callstack;
extern __JTHREAD uint64_t *__jove_callstack_begin;

extern uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES];
extern uintptr_t *__jove_sections_tables[_JOVE_MAX_BINARIES];

extern uintptr_t *__jove_foreign_function_tables[_JOVE_MAX_BINARIES];

extern DECLARE_HASHTABLE(__jove_function_map, JOVE_FUNCTION_MAP_HASH_BITS);

extern void _jove_flush_trace(void);

_HIDDEN void _jove_install_foreign_function_tables(void);

#if defined(JOVE_DFSAN)
extern void __dfsan_log_global_buffers(void);
#endif

static void _jove_install_function_table(void);
static void _jove_install_sections_table(void);

static void _jove_install_function_mappings(void);

static void _jove_check_sections_laid_out(void);
static void _jove_make_sections_executable(void);

static void _jove_see_through_tramps(struct jove_function_info_t *);

extern void _jove_rt_init(void);

typedef void (*_jove_rt_init_t)(void);
static _jove_rt_init_t _jove_rt_init_clunk = &_jove_rt_init;

extern int _jove_needs_single_threaded_runtime(void);
extern int _jove_needs_multi_threaded_runtime(void);

typedef int (*_jove_needs_runtime_t)(void);
static _jove_needs_runtime_t _jove_needs_runtime =
#ifdef JOVE_MT
    &_jove_needs_multi_threaded_runtime
#else
    &_jove_needs_single_threaded_runtime
#endif
    ;

_HIDDEN void _jove_initialize(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  /* it's possible to get here before the dynamic linker has processed funcs */
  {
    _jove_rt_init_t rt_init = _jove_rt_init_clunk;

    if (rt_init)
      rt_init();
  }

  if (unlikely(__jove_opts.Debug.Inits)) _DUMP_FUNC();

  /* we made it */
  {
    _jove_needs_runtime_t needs_runtime = _jove_needs_runtime;
    if (needs_runtime)
      needs_runtime();
  }

  _jove_install_foreign_function_tables();

  _jove_install_function_table();
  _jove_install_sections_table();

  _jove_install_function_mappings();

  _jove_do_manual_relocations();
  _jove_do_emulate_copy_relocations();

#if defined(JOVE_DFSAN)
  __dfsan_log_global_buffers();
#endif

  _jove_check_sections_laid_out();

  _jove_make_sections_executable();
}

void _jove_install_function_table(void) {
  __jove_function_tables[_jove_binary_index()] = _jove_get_function_table();
}

void _jove_install_sections_table(void) {
  static uintptr_t _Entry[3];

  _Entry[0] = _jove_sections_global_beg_addr();
  _Entry[1] = _jove_sections_global_end_addr();
  _Entry[2] = _jove_sections_start_file_addr();

  __jove_sections_tables[_jove_binary_index()] = &_Entry[0];
}

static uintptr_t actual_addr_of_laid_out(unsigned i) {
  _ASSERT(i < _jove_laid_out_sections_count());

  uintptr_t res = _jove_laid_out_sections()[2 * i];
  _ASSERT(res);

  return res;
}

static uintptr_t expected_size_of_laid_out(unsigned i) {
  _ASSERT(i < _jove_laid_out_sections_count());

  uintptr_t res = _jove_laid_out_sections()[2 * i + 1];
  _ASSERT(res);

  return res;
}

void _jove_check_sections_laid_out(void) {
  if (_jove_laid_out_sections_count() == 0)
    return;

  uintptr_t cursor = actual_addr_of_laid_out(0); /* top */
  for (unsigned i = 1; i < _jove_laid_out_sections_count(); ++i) {
    const uintptr_t expect_addr_before = cursor;
    const uintptr_t expect_size_before =
        expected_size_of_laid_out(i - 1);

    cursor += expect_size_before;

    const uintptr_t expect_addr = cursor;
    const uintptr_t actual_addr = actual_addr_of_laid_out(i);

    /* does it match? */
    if (unlikely(actual_addr != expect_addr)) {
      const uintptr_t actual_addr_before =
          actual_addr_of_laid_out(i - 1);

      _ASSERT(actual_addr > actual_addr_before);

      const uintptr_t actual_size_before =
          actual_addr_of_laid_out(i) -
          actual_addr_of_laid_out(i - 1);

      _ASSERT(actual_addr_before + actual_size_before == actual_addr);
      _ASSERT(expect_addr_before + expect_size_before == expect_addr);

      char s[1024];
      s[0] = '\0';

      _strcat(s, "(FATAL) _jove_check_sections_laid_out: [");
      {
        char buff[65];
        _uint_to_string(i - 1, buff, 10);

        _strcat(s, buff);
      }
      _strcat(s, "] 0x");
      {
        char buff[65];
        _uint_to_string(actual_addr_before, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, " + ");
      {
        char buff[65];
        _uint_to_string(actual_size_before, buff, 10);

        _strcat(s, buff);
      }
      _strcat(s, " (0x");
      {
        char buff[65];
        _uint_to_string(actual_addr, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, ") != 0x");
      {
        char buff[65];
        _uint_to_string(expect_addr_before, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, " + ");
      {
        char buff[65];
        _uint_to_string(expect_size_before, buff, 10);

        _strcat(s, buff);
      }
      _strcat(s, " (0x");
      {
        char buff[65];
        _uint_to_string(expect_addr, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, ")\n");

      _jove_dump_on_crash(s, strlen(s));
      __UNREACHABLE();
    }
  }
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
      QEMU_ALIGN_UP(sizeof(struct jove_function_info_t) *
                        (_jove_function_count() + _jove_possible_tramps_count()),
                    JOVE_PAGE_SIZE));

  if (IS_ERR_VALUE(fninfo_arr_addr))
    _UNREACHABLE("failed to allocate memory for function_info_t array");

  //
  // add the mappings
  //
  mb();
  {
    struct jove_function_info_t *fninfo_p =
        (struct jove_function_info_t *)fninfo_arr_addr;

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

    if (_jove_possible_tramps_count() > 0)
      _jove_see_through_tramps(fninfo_p);
  }

  mb();
}

void _jove_see_through_tramps(struct jove_function_info_t *fninfo_p) {
  for (unsigned i = 0; i < _jove_possible_tramps_count(); ++i) {
    const uintptr_t poss = *((uintptr_t *)(_jove_possible_tramps()[i]));

    uintptr_t pc = ~0UL;
    if (!_jove_see_through_tramp((const void *)poss, &pc))
      pc = *((uintptr_t *)poss); /* XXX wtf? */

    {
      struct jove_function_info_t *finfo;

      hash_for_each_possible(__jove_function_map, finfo, hlist, pc) {
        if (finfo->pc != pc) {
          continue;
        } else {
          *fninfo_p = *finfo;
          goto found;
        }
      }
    }

    continue;

found:
    if (unlikely(__jove_opts.Debug.Tramps))
    {
      char s[1024];
      s[0] = '\0';

      _strcat(s, "_jove_see_through_tramps: 0x");
      {
        char buff[65];
        _uint_to_string(poss, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, " -> 0x");
      {
        char buff[65];
        _uint_to_string((uintptr_t)pc, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, " (");
      {
        char buff[65];
        _uint_to_string(fninfo_p->BIdx, buff, 10);

        _strcat(s, buff);
      }
      _strcat(s, ", ");
      {
        char buff[65];
        _uint_to_string(fninfo_p->FIdx, buff, 10);

        _strcat(s, buff);
      }
      _strcat(s, ")\n");

      _jove_robust_write(2 /* stderr */, s, _strlen(s));
    }

    fninfo_p->pc = poss;
    hash_add(__jove_function_map, &fninfo_p->hlist, poss /* key */);
    ++fninfo_p;
  }
}

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

  target_ulong *const emusp_ptr = emulated_stack_pointer_of_cpu_state(&__jove_env);

  //
  // save things
  //
  const uintptr_t saved_emusp = *emusp_ptr;

  uint64_t *const saved_callstack_begin = __jove_callstack_begin;
  uint64_t *const saved_callstack = __jove_callstack;

  //
  // setup new callstack and emulated-stack
  //
  const uintptr_t new_callstack = _jove_alloc_callstack() + JOVE_PAGE_SIZE;
  __jove_callstack_begin = __jove_callstack = (uint64_t *)new_callstack;

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
  __jove_env.active_tc.gpr[25] = _jove_get_init_fn_sect_ptr();
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

  __jove_callstack_begin = saved_callstack_begin;
  __jove_callstack = saved_callstack;

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
  _jove_rt_init();

  const uintptr_t fn = _jove_get_libc_early_init_fn();
  if (!fn)
    return;

  _jove_initialize();

  target_ulong *const emusp_ptr = emulated_stack_pointer_of_cpu_state(&__jove_env);

  //
  // save things
  //
  const uintptr_t saved_emusp = *emusp_ptr;

  uint64_t *const saved_callstack_begin = __jove_callstack_begin;
  uint64_t *const saved_callstack = __jove_callstack;

  //
  // setup new callstack and emulated-stack
  //
  const uintptr_t new_callstack = _jove_alloc_callstack() + JOVE_PAGE_SIZE;
  __jove_callstack_begin = __jove_callstack = (uint64_t *)new_callstack;

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
  __jove_env.active_tc.gpr[25] = _jove_get_libc_early_init_fn_sect_ptr();
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

  __jove_callstack_begin = saved_callstack_begin;
  __jove_callstack = saved_callstack;

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
  JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);

  unsigned n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

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
      QEMU_ALIGN_UP(_jove_foreign_functions_count() * sizeof(struct jove_function_info_t),
      JOVE_PAGE_SIZE));

  if (IS_ERR_VALUE(fninfo_arr_addr))
    _UNREACHABLE("failed to allocate memory for function_info_t array");

  //
  // install function mappings
  //
  mb();
  {
    struct jove_function_info_t *fninfo_p =
        (struct jove_function_info_t *)fninfo_arr_addr;

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
  mb();
}

_NORET void _jove_fail1(uintptr_t a0, const char *reason) {
  JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);
  unsigned n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

  {
    JOVE_BUFF(s, JOVE_LARGE_BUFF_SIZE);
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
      char buff[PATH_MAX];
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
    // show message to user
    //
    _jove_robust_write(2 /* stderr */, s, _strlen(s));
  }

  _jove_flush_trace();

  _jove_on_crash(__jove_opts.OnCrash);
  __UNREACHABLE();
}

_NORET void _jove_fail2(uintptr_t a0,
                        uintptr_t a1) {
  JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);
  unsigned n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

  {
    JOVE_BUFF(s, JOVE_LARGE_BUFF_SIZE);
    s[0] = '\0';

    _strcat(s, "_jove_fail2: 0x");
    {
      char buff[65];
      _uint_to_string(a0, buff, 0x10);

      _strcat(s, buff);
    }
    {
      char buff[PATH_MAX];
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
      char buff[PATH_MAX];
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

    _strcat(s, "]\n\n");
    _strcat(s, maps);

    //
    // dump message for user
    //
    _jove_robust_write(2 /* stderr */, s, _strlen(s));
  }

  _jove_flush_trace();

  _jove_on_crash(__jove_opts.OnCrash);
  __UNREACHABLE();
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

static
_REGPARM
jove_thunk_return_t _jove_call(
                               #define __REG_ARG(n, i, data) uintptr_t reg##i,

                               BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                               #undef __REG_ARG

                               uintptr_t pc, uint32_t BBIdx) {
  if (unlikely(__jove_opts.Debug.Calls))
  {
    char s[1024];
    s[0] = '\0';

    _strcat(s, "_jove_call: -> 0x");
    {
      char buff[65];
      _uint_to_string(pc, buff, 0x10);

      _strcat(s, buff);
    }
    if (__jove_opts.Debug.Stack) {
      _strcat(s, " <0x");
      {
        uintptr_t emusp = *emulated_stack_pointer_of_cpu_state(&__jove_env);

        char buff[65];
        _uint_to_string(emusp, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, ">");
    }
    _strcat(s, "\n");

    _jove_robust_write(2 /* stderr */, s, _strlen(s));
  }

  _jove_install_foreign_function_tables();

  struct jove_function_info_t Callee;

  //
  // lookup in __jove_function_map
  //
  {
    struct jove_function_info_t *finfo;

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
    uintptr_t *fns = __jove_function_tables
                         ? __jove_function_tables[BIdx]
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
    JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);

    unsigned n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

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
    JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);

    unsigned n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

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

      _UNREACHABLE("found vm mapping for address but no foreign binary match");
    }
  }

  if (unlikely(pc == 0x0))
    _UNREACHABLE("_jove_call passed NULL");

  //
  // check for the possibility that _jove_init is our given pc, which may happen
  // if the code (usually in the dynamic linker) that calls the init functions
  // of a newly dlopen'd shared library is, itself, recompiled. to know whether
  // _jove_init is being called, we look for a unique sequence of nop
  // instructions that are hard-coded into the function's (asm) definition
  //
  bool IsJoveInit = false;

  {
#if defined(__mips64) || defined(__mips__)
    static const uint32_t magic_insns[] = {
      0x24000929,  // li      zero,2345
      0x24000159,  // li      zero,345
      0x2400002d,  // li      zero,45
      0x24000005,  // li      zero,5
      0x24000036,  // li      zero,54
      0x2400021f,  // li      zero,543
      0x24001538   // li      zero,5432
    };
#elif defined(__x86_64__)
    static const uint8_t magic_insns[] = {
      0x4d, 0x87, 0xff,  // xchg   %r15,%r15
      0x4d, 0x87, 0xf6,  // xchg   %r14,%r14
      0x4d, 0x87, 0xed,  // xchg   %r13,%r13
      0x4d, 0x87, 0xe4,  // xchg   %r12,%r12
      0x4d, 0x87, 0xdb   // xchg   %r11,%r11
    };
#elif defined(__i386__)
    static const uint8_t magic_insns[] = {
      0x87, 0xdb,  // xchg   %ebx,%ebx
      0x87, 0xc9,  // xchg   %ecx,%ecx
      0x87, 0xd2,  // xchg   %edx,%edx
      0x87, 0xf6,  // xchg   %esi,%esi
      0x87, 0xff   // xchg   %edi,%edi
    };
#elif defined(__aarch64__)
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
#else
#error
#endif

    IsJoveInit = !!_memmem((const uint8_t *)pc, 2 * sizeof(magic_insns),
                           &magic_insns[0], sizeof(magic_insns));
  }

  if (unlikely(IsJoveInit))
    return BOOST_PP_CAT(_jove_thunk,TARGET_NUM_REG_ARGS)(
                        #define __REG_ARG(n, i, data) reg##i,

                        BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                        #undef __REG_ARG
                        pc, emulated_stack_pointer_of_cpu_state(&__jove_env));

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
    const bool in_ifunc = __jove_env_clunk == NULL;

    uintptr_t RealEntry = __jove_foreign_function_tables[Callee.BIdx][Callee.FIdx];
    if (unlikely(in_ifunc)) {
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
                          RealEntry, emusp_ptr);

      _jove_free_stack(dummy_stack);

      return res;
    } else {
      target_ulong *const emusp_ptr = emulated_stack_pointer_of_cpu_state(&__jove_env);

      if (unlikely(__jove_opts.Debug.Stack)) {
        const uintptr_t emusp = *emusp_ptr;

#if defined(__x86_64__) || defined(__i386__)
        _ASSERT((emusp + sizeof(uintptr_t)) % 16 == 0); /* per the ABI */
#endif
      }

      jove_thunk_return_t res = BOOST_PP_CAT(_jove_thunk,TARGET_NUM_REG_ARGS)(
                          #define __REG_ARG(n, i, data) reg##i,

                          BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                          #undef __REG_ARG
                          RealEntry, emusp_ptr);

      if (unlikely(__jove_opts.Debug.Stack)) {
        const uintptr_t emusp = *emusp_ptr;

#if defined(__x86_64__) || defined(__i386__)
        _ASSERT(emusp % 16 == 0);
#endif

        if (__jove_opts.Debug.Calls) {
          char s[1024];
          s[0] = '\0';

          _strcat(s, "\t<0x");
          {
            char buff[65];
            _uint_to_string(emusp, buff, 0x10);

            _strcat(s, buff);
          }
          _strcat(s, ">\n");

          _DUMP(s);
        }
      }

      return res;
    }
  } else {
#define CALLCONV_ATTR _REGPARM

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

static dfsan_label *__df32_shadow_for(uint32_t A) {
  const uint16_t AddrUpperBits = A >> 16;
  const uint16_t AddrLowerBits = A & 0xFFFF;

  unsigned Region = AddrLowerBits / JOVE_SHADOW_REGION_SIZE;
  unsigned Offset = AddrLowerBits % JOVE_SHADOW_REGION_SIZE;

  dfsan_label **shadowp = &__df32_shadow_mem[AddrUpperBits].X[Region];

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
  *p++ = &_jove_trace_enabled;
  *p++ = &_jove_dfsan_enabled;
  *p++ = &_jove_get_init_fn_sect_ptr;
  *p++ = &_jove_get_libc_early_init_fn;
  *p++ = &_jove_get_libc_early_init_fn_sect_ptr;
  *p++ = &_jove_rt_init_clunk;
  *p++ = &_jove_needs_runtime;
  *p++ = &__jove_trace;
  *p++ = &__jove_trace_begin;
  *p++ = &__jove_callstack;
  *p++ = &__jove_callstack_begin;
  *p++ = &__jove_env_clunk;
  *p++ = &_jove_alloc_stack;
  *p++ = &_jove_free_stack;
  *p++ = &_jove_alloc_callstack;
  *p++ = &_jove_free_callstack;
  *p++ = &_jove_call;
#ifdef JOVE_MT
  *p++ = &__jove_local_env;
#endif
#ifdef JOVE_DFSAN
#if (defined(__mips__) && !defined(__mips64)) || \
    (defined(__i386__) && !defined(__x86_64__))
  *p++ = &__df32_shadow_for;
#endif
#endif
}

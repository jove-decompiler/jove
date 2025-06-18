#include "jove.llvm.c.inc"
#include "jove.util.c.inc"
#include "jove.recover.h"

DECLARE_JOVE_RT_THREAD_GLOBAL(struct CPUArchState, env)

#ifdef JOVE_MT
static struct CPUArchState __jove_local_env;
#endif

#ifdef JOVE_CLUNK
static struct CPUArchState *__jove_env_clunk =
#ifdef JOVE_MT
    &__jove_local_env
#else
    &__jove_env
#endif
    ;
#endif

DECLARE_JOVE_RT_THREAD_GLOBAL(uint64_t *, trace)
DECLARE_JOVE_RT_THREAD_GLOBAL(uint64_t *, trace_begin)

DECLARE_JOVE_RT_THREAD_GLOBAL(uint64_t *, callstack)
DECLARE_JOVE_RT_THREAD_GLOBAL(uint64_t *, callstack_begin)

extern uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES];
extern uintptr_t *__jove_sections_tables[_JOVE_MAX_BINARIES];

extern uintptr_t *__jove_foreign_function_tables[_JOVE_MAX_BINARIES];
static ptrdiff_t __jove_foreign_function_tables_bias[_JOVE_MAX_BINARIES];

extern DECLARE_HASHTABLE(__jove_function_map, JOVE_FUNCTION_MAP_HASH_BITS);

static DEFINE_HASHTABLE(__jove_trampolines_pending, 9);

extern void _jove_flush_trace(void);

_HIDDEN void _jove_install_foreign_function_tables(void);

#if defined(JOVE_DFSAN)
extern void __dfsan_log_global_buffers(void);
#endif

static void _jove_install_function_table(void);
static void _jove_install_sections_table(void);

static void _jove_install_function_mappings(void);

static void _jove_check_sections_laid_out(void);
static void _jove_check_sections_at_base_address(void);
static void _jove_make_sections_not_executable(void);
static void _jove_make_sections_executable(void);

static void _jove_identify_trampolines(struct jove_trampoline_t *,
                                       struct jove_function_info_t *);

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

  if (_jove_laid_out_sections_count() > 0)
    _jove_check_sections_laid_out();
  if (_jove_is_fixed_base_address())
    _jove_check_sections_at_base_address();

  if (unlikely(__jove_opts.SectsExe))
    _jove_make_sections_executable();
  else
    _jove_make_sections_not_executable();

  if (_jove_trace_enabled() && !__jove_opts.Trace)
    _UNREACHABLE("must set $JOVETRACE in trace mode");
  if (_jove_callstack_enabled() && !__jove_opts.CallS)
    _UNREACHABLE("must set $JOVECALLS in call-stack mode");
}

void _jove_install_function_table(void) {
  __jove_function_tables[_jove_binary_index()] = _jove_get_function_table();
}

void _jove_install_sections_table(void) {
  static uintptr_t _Entry[3];

  _Entry[0] = _jove_sections_begin();
  _Entry[1] = _jove_sections_end();
  _Entry[2] = _jove_sections_start_addr();

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
  _VERBOSE_DUMP_FUNC();

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

      char *s;
      JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
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

void _jove_check_sections_at_base_address(void) {
  _ASSERT(_jove_sections_begin() == _jove_sections_start_addr());
}

void _jove_make_sections_executable(void) {
  static bool _Done = false;
  if (unlikely(__jove_opts.SectsExe) && _Done)
    return; // nothing to do
  _Done = true;

  const unsigned n = QEMU_ALIGN_UP(_jove_sections_end() -
                                   _jove_sections_begin(), JOVE_PAGE_SIZE);
  const uintptr_t x = QEMU_ALIGN_DOWN(_jove_sections_begin(), JOVE_PAGE_SIZE);

  if (unlikely(__jove_opts.Debug.Verbose)) {
    char s[512];

    _strcpy(s, "mprotecting +xrw [0x");
    {
      char buff[65];
      _uint_to_string(x, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, ", 0x");
    {
      char buff[65];
      _uint_to_string(x + n, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, ")\n");
    _DUMP(s);
  }

  if (_jove_sys_mprotect(x, n, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
    _UNREACHABLE("failed to make sections executable\n");
}

void _jove_make_sections_not_executable(void) {
  if (unlikely(__jove_opts.SectsExe))
    return; // overriden by user

  const unsigned n = QEMU_ALIGN_UP(_jove_sections_end() -
                                   _jove_sections_begin(), JOVE_PAGE_SIZE);
  const uintptr_t x = QEMU_ALIGN_DOWN(_jove_sections_begin(), JOVE_PAGE_SIZE);

  if (unlikely(__jove_opts.Debug.Verbose)) {
    char s[512];

    _strcpy(s, "mprotecting -x+rw [0x");
    {
      char buff[65];
      _uint_to_string(x, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, ", 0x");
    {
      char buff[65];
      _uint_to_string(x + n, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, ")\n");
    _DUMP(s);
  }

  if (_jove_sys_mprotect(x, n, PROT_READ | PROT_WRITE) < 0)
    _UNREACHABLE("failed to make sections not executable\n");
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

  if (_jove_possible_tramps_count() == 0)
    return;

  uintptr_t tramp_arr_addr = _mmap_rw_anonymous_private_memory(
      QEMU_ALIGN_UP(sizeof(struct jove_trampoline_t) *
                        _jove_possible_tramps_count(),
                    JOVE_PAGE_SIZE));

  struct jove_trampoline *tramp_p = (struct jove_trampoline *)tramp_arr_addr;

  _jove_identify_trampolines(tramp_p, fninfo_p);
}

static bool trampoline_slot(const void *poss, uintptr_t **out);

void _jove_identify_trampolines(struct jove_trampoline_t *tramp_p,
                                struct jove_function_info_t *fninfo_p) {
  _VERBOSE_DUMP_FUNC();

  for (unsigned i = 0; i < _jove_possible_tramps_count(); ++i) {
    uintptr_t SectPtr = _jove_possible_tramps()[i];
    const uintptr_t poss = *((uintptr_t *)SectPtr);

    // poss being NULL can be an indicator of the loader not being able to
    // resolve a symbol, which can be caused by a mismatch of wine versions
    if (unlikely(!poss)) {
      char *s;
      JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
      s[0] = '\0';

      _strcat(s, "_jove_identify_trampolines: NULL @ 0x");
      {
        char buff[65];
        _uint_to_string(SectPtr, buff, 0x10);

        _strcat(s, buff);
      }
      _strcat(s, "\n");

      _DUMP(s);
    }
    _ASSERT(poss);

    uintptr_t *slotp = NULL;
    const bool slot = trampoline_slot((const void *)poss, &slotp);

    {
      uintptr_t pc = slot ? *slotp : *((uintptr_t *)poss) /* wtf? */;
      bool found = false;

      struct jove_function_info_t *finfo = NULL;
      hash_for_each_possible(__jove_function_map, finfo, hlist, pc) {
        if (finfo->pc == pc) {
          found = true;
          break;
        }
      }

      if (found) { /* recognized function */
        _ASSERT(finfo);

        if (unlikely(__jove_opts.Debug.Tramps)) {
          char *s;
          JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
          s[0] = '\0';

          _strcat(s, "_jove_identify_trampolines: 0x");
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
            _uint_to_string(finfo->BIdx, buff, 10);

            _strcat(s, buff);
          }
          _strcat(s, ", ");
          {
            char buff[65];
            _uint_to_string(finfo->FIdx, buff, 10);

            _strcat(s, buff);
          }
          _strcat(s, ")\n");

          _DUMP(s);
        }

        __builtin_memcpy_inline(fninfo_p, finfo, sizeof(*finfo));

        fninfo_p->pc = poss;
        hash_add(__jove_function_map, &fninfo_p->hlist, poss /* key */);
        ++fninfo_p;
        continue;
      }
    }

    /* addr @ slot could simply be a function we don't know about */
    if (slot) {
      _ASSERT(slotp);

      if (unlikely(__jove_opts.Debug.Tramps)) {
        char s[1024];
        s[0] = '\0';

        _strcat(s, "_jove_identify_trampolines: 0x");
        {
          char buff[65];
          _uint_to_string(poss, buff, 0x10);

          _strcat(s, buff);
        }
        _strcat(s, ": slot @ 0x");
        {
          char buff[65];
          _uint_to_string((uintptr_t)slotp, buff, 0x10);

          _strcat(s, buff);
        }
        _strcat(s, "\n");

        _DUMP(s);
      }

      tramp_p->slotp = slotp;

      tramp_p->pc = poss;
      hash_add(__jove_trampolines_pending, &tramp_p->hlist, poss /* key */);
      ++tramp_p;
    }
  }
}

#ifdef JOVE_COFF
#if defined(__x86_64__) || defined(__i386__)

uint32_t _tls_index = 0;

void WINAPI JoveWinMain(void) {
  _UNREACHABLE("JoveWinMain is no longer in use");
}

#endif
#endif

static _UNUSED uintptr_t _jove_begin_setup_emulated_stack(uintptr_t init_sp) {
  char *m;
  unsigned n;
  LOAD_PROC_SELF_MAPS(m, n);

  if (unlikely(__jove_opts.Debug.Stack)) {
    char *s;
    JOVE_SCOPED_BUFF(s, 2*PATH_MAX);

    _strcpy(s, "initial stack pointer is 0x");
    {
      char buff[65];
      _uint_to_string(init_sp, buff, 0x10);

      _strcat(s, buff);
    }

    {
      char *buff;
      JOVE_SCOPED_BUFF(buff, 2*PATH_MAX);

      if (_description_of_address_for_maps(buff, init_sp, m, n)) {
        _strcat(s, " <");
        _strcat(s, buff);
        _strcat(s, ">");
      }
    }

    _strcat(s, "\n");
    _DUMP(s);

#if defined(__x86_64__) || defined(__i386__)
    _ASSERT(init_sp % 16 == 0 && "initial stack pointer is aligned");
#endif
  }

  uintptr_t stack_end = _end_of_mapping_at_address(init_sp, m, n);
  _ASSERT(stack_end);

  //
  // there may be a nonempty sequence of contiguous readable mappings directly
  // following whatever mapping the initial stack pointer lies in (typically
  // [stack], but not necessarily (e.g. under valgrind)). we consider the end of
  // such mappings to be the true "end of the stack".
  //
  for (;;) {
    uintptr_t end = _end_of_normal_readable_map_beginning_at(stack_end, m, n);
    if (!end)
      break; /* no such mapping */

    if (unlikely(__jove_opts.Debug.Stack)) {
      char s[128];

      _strcpy(s, "mapping afterwards at 0x");
      {
	char buff[65];
	_uint_to_string(end, buff, 0x10);

	_strcat(s, buff);
      }

      _strcat(s, "\n");
      _DUMP(s);
    }

    stack_end = end;
  }

  _ASSERT(stack_end);
  _ASSERT(init_sp < stack_end);

  unsigned len = stack_end - init_sp; /* amount of data currently on "stack" */

  uintptr_t emu_stack_beg = _jove_alloc_stack();
  uintptr_t emu_stack_end = emu_stack_beg + JOVE_STACK_SIZE;

  if (unlikely(__jove_opts.Debug.Stack)) {
    char s[256];

    _strcpy(s, "copying ");
    {
      char buff[65];
      _uint_to_string(len, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, " bytes to emulated stack at [0x");
    {
      char buff[65];
      _uint_to_string(emu_stack_beg, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, ", 0x");
    {
      char buff[65];
      _uint_to_string(emu_stack_end, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, ")\n");

    _DUMP(s);
  }

  uintptr_t emu_sp = emu_stack_end - JOVE_PAGE_SIZE - len;
  _memcpy((void *)emu_sp, (const void *)init_sp, len); /* copy data */

  return emu_sp;
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

  target_ulong *const emusp_ptr =
      emulated_stack_pointer_of_cpu_state(JOVE_RT_THREAD_GLOBALP(env));

  //
  // save things
  //
  const uintptr_t saved_emusp = *emusp_ptr;

#if 0
  uint64_t *const saved_callstack_begin = __jove_callstack_begin;
  uint64_t *const saved_callstack = __jove_callstack;
#endif

  //
  // setup new callstack and emulated-stack
  //
#if 0
  const uintptr_t new_callstack = _jove_alloc_callstack() + JOVE_PAGE_SIZE;
  __jove_callstack_begin = __jove_callstack = (uint64_t *)new_callstack;
#endif

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
  JOVE_RT_THREAD_GLOBAL(env).active_tc.gpr[25] = _jove_get_init_fn_sect_ptr();
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

#if 0
  __jove_callstack_begin = saved_callstack_begin;
  __jove_callstack = saved_callstack;
#endif

  _jove_free_stack(new_emu_stack);
#if 0
  _jove_free_callstack(new_callstack);
#endif
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

  target_ulong *const emusp_ptr =
      emulated_stack_pointer_of_cpu_state(JOVE_RT_THREAD_GLOBALP(env));

  //
  // save things
  //
  const uintptr_t saved_emusp = *emusp_ptr;

#if 0
  uint64_t *const saved_callstack_begin = __jove_callstack_begin;
  uint64_t *const saved_callstack = __jove_callstack;
#endif

  //
  // setup new callstack and emulated-stack
  //
#if 0
  const uintptr_t new_callstack = _jove_alloc_callstack() + JOVE_PAGE_SIZE;
  __jove_callstack_begin = __jove_callstack = (uint64_t *)new_callstack;
#endif

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
  JOVE_RT_THREAD_GLOBAL(env).active_tc.gpr[25] = _jove_get_libc_early_init_fn_sect_ptr();
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

#if 0
  __jove_callstack_begin = saved_callstack_begin;
  __jove_callstack = saved_callstack;
#endif

  _jove_free_stack(new_emu_stack);
#if 0
  _jove_free_callstack(new_callstack);
#endif
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

  return ~0ul; /* doesn't exist */
}

void _jove_install_foreign_function_tables(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  /* we need to get the load addresses for the dynamic linker and VDSO by
   * parsing /proc/self/maps */
  char *maps;
  unsigned n;
  LOAD_PROC_SELF_MAPS(maps, n);

  uintptr_t dynl_load_bias = _parse_dynl_load_bias(maps, n); /* cannot fail */
  uintptr_t vdso_load_bias = _parse_vdso_load_bias(maps, n); /* cannot fail */

  uintptr_t *dynl_fn_tbl = _jove_get_dynl_function_table();
  uintptr_t *vdso_fn_tbl = _jove_get_vdso_function_table();

  for (uintptr_t *p = dynl_fn_tbl; *p; ++p) *p += dynl_load_bias;
  for (uintptr_t *p = vdso_fn_tbl; *p; ++p) *p += vdso_load_bias;

  __jove_foreign_function_tables_bias[1] = dynl_load_bias;
  __jove_foreign_function_tables_bias[2] = vdso_load_bias;

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
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
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
          if (!match)
            continue;
        }

        if (match && __jove_foreign_function_tables[i + 3] == NULL) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          uintptr_t load_bias = min - off;
          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables_bias[i + 3] = load_bias;
          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          goto matched;
        }
      }
      }
matched:
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
  char *maps;
  unsigned n;
  LOAD_PROC_SELF_MAPS(maps, n);

  {
    char *s;
    JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
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
      char *buff;
      JOVE_SCOPED_BUFF(buff, 2*PATH_MAX);
      buff[0] = '\0';

      if (_description_of_address_for_maps(buff, a0, maps, n)) {
        _strcat(s, " <");
        _strcat(s, buff);
        _strcat(s, ">");
      }
    }
    _strcat(s, " [");

    {
      char buff[65];
      _uint_to_string(_jove_sys_gettid(), buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, "]\n\n");
    _strcat(s, maps);

    _DUMP(s);
  }

  _jove_flush_trace();

  _jove_on_crash(__jove_opts.OnCrash);
  __UNREACHABLE();
}

_NORET void _jove_fail2(uintptr_t a0,
                        uintptr_t a1) {
  char *maps;
  unsigned n;
  LOAD_PROC_SELF_MAPS(maps, n);

  {
    char *s;
    JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
    s[0] = '\0';

    _strcat(s, "_jove_fail2: 0x");
    {
      char buff[65];
      _uint_to_string(a0, buff, 0x10);

      _strcat(s, buff);
    }
    {
      char *buff;
      JOVE_SCOPED_BUFF(buff, 2*PATH_MAX);
      buff[0] = '\0';

      if (_description_of_address_for_maps(buff, a0, maps, n)) {
        _strcat(s, " <");
        _strcat(s, buff);
        _strcat(s, ">");
      }
    }
    _strcat(s, "\n             0x");
    {
      char buff[65];
      _uint_to_string(a0, buff, 0x10);

      _strcat(s, buff);
    }
    {
      char *buff;
      JOVE_SCOPED_BUFF(buff, 2*PATH_MAX);
      buff[0] = '\0';

      if (_description_of_address_for_maps(buff, a1, maps, n)) {
        _strcat(s, " <");
        _strcat(s, buff);
        _strcat(s, "> [");
      }
    }

    {
      char buff[65];
      _uint_to_string(_jove_sys_gettid(), buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, "]\n\n");
    _strcat(s, maps);

    _DUMP(s);
  }

  _jove_flush_trace();

  _jove_on_crash(__jove_opts.OnCrash);
  __UNREACHABLE();
}

void _jove_log1(const char *msg,
                uintptr_t x) {
  char *s;
  JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
  s[0] = '\0';

  _strcat(s, msg);

  _strcat(s, " (0x");
  {
    char buff[65];
    _uint_to_string(x, buff, 0x10);

    _strcat(s, buff);
  }
  _strcat(s, ")\n");

  _DUMP(s);
}

void _jove_log2(const char *msg,
                uintptr_t x,
                uintptr_t y) {
  char *s;
  JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
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

  _DUMP(s);
}


//
// declare _jove_thunk_*()
//
#ifndef JOVE_THUNK_EXTRA_ATTR
#define JOVE_THUNK_EXTRA_ATTR
#endif

#define __REG_ARG0(n, i, data) BOOST_PP_COMMA_IF(i) uintptr_t
#define __REG_ARG1(n, i, data)                                                 \
  _HIDDEN JOVE_THUNK_EXTRA_ATTR _NAKED jove_thunk_return_t _jove_thunk##i(     \
      BOOST_PP_CAT(BOOST_PP_REPEAT_,n)(i, __REG_ARG0, void)                    \
          BOOST_PP_COMMA_IF(i) uintptr_t, uintptr_t *);

BOOST_PP_REPEAT(BOOST_PP_INC(TARGET_NUM_REG_ARGS), __REG_ARG1, void)

#undef __REG_ARG0
#undef __REG_ARG1

//
// indirect control-transfer
//
_REGPARM
jove_thunk_return_t _jove_call(
                               #define __REG_ARG(n, i, data) uintptr_t reg##i,

                               BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                               #undef __REG_ARG

                               uintptr_t pc, const uint32_t BBIdx) {
  MAYBE_PAUSE(Call);

  if (unlikely(__jove_opts.Debug.Calls))
  {
    char s[512];
    s[0] = '\0';

    _strcat(s, "_jove_call(... 0x");
    {
      char buff[65];
      _uint_to_string(pc, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, ")");

    _DUMP(s);
  }

  _jove_install_foreign_function_tables();

  struct jove_function_info_t Callee;

  //
  // lookup in __jove_function_map
  //
  {
    struct jove_function_info_t *finfo;
    hash_for_each_possible(__jove_function_map, finfo, hlist, pc) {
      if (finfo->pc == pc) {
        Callee = *finfo;
        goto found;
      }
    }
  }

  //
  // if it's a trampoline, we want to look at the address in its "slot"
  //
  {
    struct jove_trampoline_t *tramp;
    hash_for_each_possible(__jove_trampolines_pending, tramp, hlist, pc) {
      if (tramp->pc == pc) {
        pc = *tramp->slotp;
        break;
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

  const unsigned N = _jove_foreign_lib_count();

#if 0
  bool FoundAll = true;
  for (unsigned j = 3; j < N + 3; ++j) {
    if (__jove_foreign_function_tables[j] == NULL) {
      FoundAll = false;
      break;
    }
  }

  if (!FoundAll) {
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

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
        const char **pforeign_dso_path_beg;
        for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
        const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
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
          if (!match)
            continue;
        }

        ptrdiff_t curr_bias = __jove_foreign_function_tables_bias[i + 3];
        ptrdiff_t load_bias = min - off;
        if (match && (__jove_foreign_function_tables[i + 3] == NULL ||
                      load_bias != curr_bias)) {
          uintptr_t *foreign_fn_tbl = _jove_foreign_lib_function_table(i);

          if (curr_bias) {
            //
            // DSO was reloaded at different address
            //
	    {
              char *s;
              JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
	      s[0] = '\0';

	      _strcat(s, "_jove_call: DSO reloaded (1): ");
	      _strcat(s, foreign_dso_path_beg);
	      _strcat(s, "\n");

	      _DUMP(s);
	    }

            for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
              foreign_fn_tbl[FIdx] -= curr_bias; /* undo */
          }

          for (unsigned FIdx = 0; foreign_fn_tbl[FIdx]; ++FIdx)
            foreign_fn_tbl[FIdx] += load_bias;

          __jove_foreign_function_tables_bias[i + 3] = load_bias;
          __jove_foreign_function_tables[i + 3] = foreign_fn_tbl; /* install */
          goto matched;
        }
      }
      }
matched:
    }
  }
#endif

  if (N > 0) {
    //
    // see if this is a function in a foreign DSO
    //
    char *maps;
    unsigned n;
    LOAD_PROC_SELF_MAPS(maps, n);

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

      char *path = _memchr(line, '/', eol - line);
      if (path) {
        //
        // search the foreign libs
        //
        for (unsigned i = 0; i < N; ++i) {
          const char **pforeign_dso_path_beg;
          for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
            const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
            const unsigned foreign_dso_path_len = _strlen(foreign_dso_path_beg);
            const char *foreign_dso_path_end =
                &foreign_dso_path_beg[foreign_dso_path_len];

            {
              bool match = true;

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

              if (!match)
                continue;
            }

            //
            // we've found a match.
            //
            uintptr_t *const fntbl = _jove_foreign_lib_function_table(i);

            ptrdiff_t curr_bias = __jove_foreign_function_tables_bias[i + 3];
            ptrdiff_t load_bias = min - off;

            bool JustLoaded = __jove_foreign_function_tables[i + 3] == NULL;
            bool Reloaded = !JustLoaded && load_bias != curr_bias;
            const bool Changed = JustLoaded || Reloaded;

            if (Changed) {
              if (unlikely(__jove_opts.Debug.Verbose)) {
                char *s;
                JOVE_SCOPED_BUFF(s, 2 * PATH_MAX);
                s[0] = '\0';

                _strcat(s, "[found \"");
                _strcat(s, foreign_dso_path_beg);
                _strcat(s, "\" ");
                if (Reloaded)
                  _strcat(s, "now ");
                _strcat(s, "@ 0x");
                {
                  char buff[65];
                  _uint_to_string(load_bias, buff, 0x10);

                  _strcat(s, buff);
                }
                if (Reloaded) {
                  _strcat(s, " was @ 0x");
                  {
                    char buff[65];
                    _uint_to_string(curr_bias, buff, 0x10);

                    _strcat(s, buff);
                  }
                }
                _strcat(s, "]\n");

                _DUMP(s);
              }

              if (Reloaded) {
                //
                // undo our modifications to the function pointers
                //
                for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx)
                  fntbl[FIdx] -= curr_bias;
              }

              for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx)
                fntbl[FIdx] += load_bias;

              __jove_foreign_function_tables_bias[i + 3] = load_bias;
              if (JustLoaded) {
                __jove_foreign_function_tables[i + 3] = fntbl;
              }
            }

            //
            // determine if given program counter is already regarded as fn
            //
            for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx) {
              if (pc == fntbl[FIdx]) {
                //
                // yep, we know about it.
                //
                Callee.IsForeign = 1;

                Callee.BIdx = i + 3;
                Callee.FIdx = FIdx;

                Callee.Foreign.Func = pc;

                goto found;
              }
            }

            //
            // nope, we don't know about this function
            //
            _jove_recover_foreign_function_at_offset(BBIdx, i + 3,
                                                     pc - (min - off));
            _UNREACHABLE();
          }
        }

        //
        // we haven't seen this binary before
        //
        *eol = '\0';
        _jove_recover_foreign_binary_with_path(path);
        __UNREACHABLE();
      } else {
        //
        // anonymous memory.
        //

#ifdef JOVE_COFF
        //
        // under certain conditions, the wine loader will read() the
        // contents of a DSO into such a region, which is obviously troublesome.
        //
        const char *const wine_stderr_path = _getenv("WINEDEBUGLOG");
        if (wine_stderr_path) {
          char *beg;
          JOVE_SCOPED_BUFF(beg, JOVE_LARGE_BUFF_SIZE);
          unsigned n = _jove_read_pseudo_file(wine_stderr_path, beg,
                                              JOVE_LARGE_BUFF_SIZE);

          char *line;
          char *eol;
          for_each_str_eos_delim_know_end(line, eol, '\n', beg, n) {
            unsigned left = eol - line;
            const char *needle1 = ":trace:module:map_image_into_view mapping ";
            char *map_image_into_view =
                _memmem(line, left, needle1, _strlen(needle1));
            if (!map_image_into_view)
              continue;

            char *path_beg = map_image_into_view + _strlen(needle1);

            char *p = map_image_into_view; /* space */
            left = eol - p;

            // const char *needle2 = "section .text at ";
            const char *needle2 = " section ";

            char *section = _memmem(p, left, needle2, _strlen(needle2));
            if (!section)
              continue;

            char *const path_end = section;

            char *const sectnm_beg = section + _strlen(needle2);
            char *const sectnm_end = _memchr(sectnm_beg, ' ', eol - sectnm_beg);
            _ASSERT(sectnm_end);

            p = sectnm_end;
            _ASSERT(p[0] == ' ' && p[1] == 'a' && p[2] == 't' && p[3] == ' ' &&
                    p[4] == '0' && p[5] == 'x');

            char *const min_beg = p + _strlen(" at 0x");
            char *const min_end = _memchr(min_beg, ' ', eol - min_beg);
            _ASSERT(min_end);

            uint64_t min = _u64ofhexstr(min_beg, min_end);

            char *const off_beg = min_end + _strlen(" off ");
            char *const off_end = _memchr(off_beg, ' ', eol - off_beg);
            _ASSERT(off_end);

            uint64_t off = _u64ofhexstr(off_beg, off_end);

            char *const size_beg = off_end + _strlen("size  ");
            char *const size_end = _memchr(size_beg, ' ', eol - size_beg);
            _ASSERT(size_end);

            uint64_t size = _u64ofhexstr(size_beg, size_end);

            if (!(pc >= min && pc < min + size))
              continue;

            //
            // we've found a relevant mapping from WINEDEBUGLOG!
            //
            *path_end = '\0';

#if 0
            if (unlikely(__jove_opts.Debug.Verbose)) {
              char *s;
              JOVE_SCOPED_BUFF(s, 2 * PATH_MAX);
              s[0] = '\0';

              _strcat(s, "anonymous region (WINE): ");
              if (Found)
                _strcat(s, "found ");
              _strcat(s, "0x");
              {
                char buff[65];
                _uint_to_string(min, buff, 0x10);

                _strcat(s, buff);
              }
              _strcat(s, " off 0x");
              {
                char buff[65];
                _uint_to_string(off, buff, 0x10);

                _strcat(s, buff);
              }
              _strcat(s, " size 0x");
              {
                char buff[65];
                _uint_to_string(size, buff, 0x10);

                _strcat(s, buff);
              }

              _strcat(s, "\t");
              _strcat(s, path_beg);
              _strcat(s, "\n");

              _DUMP(s);
            }
#endif

            //
            // enumerate (known) foreign libs
            //
            for (unsigned i = 0; i < N; ++i) {
              const char **pforeign_dso_path_beg;
              for_each_binary_paths(i + 3, pforeign_dso_path_beg) {
                const char *const foreign_dso_path_beg = *pforeign_dso_path_beg;
                const unsigned foreign_dso_path_len =
                    _strlen(foreign_dso_path_beg);
                const char *foreign_dso_path_end =
                    &foreign_dso_path_beg[foreign_dso_path_len];

                {
                  bool match = true;

                  const char *s1 = foreign_dso_path_end - 1;
                  const char *s2 = path_end - 1;
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

                  if (!match)
                    continue;
                }

                //
                // we've found a match.
                //
                uintptr_t *const fntbl = _jove_foreign_lib_function_table(i);

                const ptrdiff_t curr_bias =
                    __jove_foreign_function_tables_bias[i + 3];
                const ptrdiff_t load_bias = min - off;

                bool JustLoaded = __jove_foreign_function_tables[i + 3] == NULL;
                bool Reloaded = !JustLoaded && load_bias != curr_bias;
                const bool Changed = JustLoaded || Reloaded;

                if (Changed) {
                  if (unlikely(__jove_opts.Debug.Verbose)) {
                    char *s;
                    JOVE_SCOPED_BUFF(s, 2 * PATH_MAX);
                    s[0] = '\0';

                    _strcat(s, "[found \"");
                    _strcat(s, foreign_dso_path_beg);
                    _strcat(s, "\" ");
                    if (Reloaded)
                      _strcat(s, "now ");
                    _strcat(s, "@ 0x");
                    {
                      char buff[65];
                      _uint_to_string(load_bias, buff, 0x10);

                      _strcat(s, buff);
                    }
                    if (Reloaded) {
                      _strcat(s, " was @ 0x");
                      {
                        char buff[65];
                        _uint_to_string(curr_bias, buff, 0x10);

                        _strcat(s, buff);
                      }
                    }
                    _strcat(s, "]\n");

                    _DUMP(s);
                  }

                  if (Reloaded) {
                    //
                    // undo our modifications to the function pointers
                    //
                    for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx)
                      fntbl[FIdx] -= curr_bias;
                  }

                  for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx)
                    fntbl[FIdx] += load_bias;

                  __jove_foreign_function_tables_bias[i + 3] = load_bias;
                  if (JustLoaded) {
                    __jove_foreign_function_tables[i + 3] = fntbl;
                  }
                }

                //
                // determine if given program counter is already regarded as fn
                //
                for (unsigned FIdx = 0; fntbl[FIdx]; ++FIdx) {
                  if (pc == fntbl[FIdx]) {
                    //
                    // yep, we know about it.
                    //
                    Callee.IsForeign = 1;

                    Callee.BIdx = i + 3;
                    Callee.FIdx = FIdx;

                    Callee.Foreign.Func = pc;

                    goto found;
                  }
                }

                //
                // nope, we don't know about this function
                //
                _jove_recover_foreign_function_at_offset(BBIdx, i + 3,
                                                         (pc - min) + off);
                _UNREACHABLE();
              }
            }

            //
            // we haven't seen this binary before
            //
            _jove_recover_foreign_binary_with_path(path_beg);
            __UNREACHABLE();
          }

          //
          // we found nothing
          //
          {
            char s[1024];
            s[0] = '\0';

            _strcat(s, "giving up; program counter in unknown anonymous memory region (0x");
            {
              char buff[65];
              _uint_to_string(pc, buff, 0x10);

              _strcat(s, buff);
            }
            _strcat(s, ")\n");

            _DUMP(s);
          }

          _jove_sys_exit_group(1);
          __UNREACHABLE();
        }
#endif
      }
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
                        pc, emulated_stack_pointer_of_cpu_state(JOVE_RT_THREAD_GLOBALP(env)));

  //
  // we found new code?
  //
  MAYBE_PAUSE(UnknownCallee);
  _jove_recover_function(BBIdx, pc);
  _jove_recover_foreign_function(BBIdx, pc); /* NOTE: currently unnecessary */
  _jove_recover_foreign_binary(pc); /* NOTE: currently unnecessary */

  {
    _jove_fail1(pc, "_jove_call failed");

    __builtin_unreachable();
  }

found:
  if (unlikely(__jove_opts.Hoard))
    _jove_found_dyn_target(BBIdx, Callee.BIdx, Callee.FIdx);

  if (_jove_callstack_enabled()) {
    const uint32_t BIdx = _jove_binary_index();

    uint64_t *callstack = JOVE_RT_THREAD_GLOBAL(callstack);
    *callstack++ = JOVE_COMBINE_B_AND_BB(BIdx, BBIdx);
    *callstack = 0; /* clear */

    JOVE_RT_THREAD_GLOBAL(callstack) = callstack;
  }

  if (unlikely(__jove_opts.Debug.Interactive)) {
    char buff;
    while (_jove_sys_read(STDIN_FILENO, &buff, 1) > 0 && buff != '\n');
  }

  if (Callee.IsForeign) {
    const bool in_ifunc =
#ifdef JOVE_CLUNK
        __jove_env_clunk == NULL
#else
        false
#endif
        ;

    uintptr_t RealEntry = __jove_foreign_function_tables[Callee.BIdx][Callee.FIdx];

    if (unlikely(__jove_opts.Debug.Calls))
    {
      char s[512];
      s[0] = '\0';

      _strcat(s, " F<");
      {
	char buff[65];
	_uint_to_string(Callee.BIdx, buff, 10);

	_strcat(s, buff);
      }
      _strcat(s, ", ");
      {
	char buff[65];
	_uint_to_string(Callee.FIdx, buff, 10);

	_strcat(s, buff);
      }
      _strcat(s, ">(0x");
      {
	char buff[65];
	_uint_to_string(RealEntry, buff, 0x10);

	_strcat(s, buff);
      }
      _strcat(s, ")\n");

      _DUMP(s);
    }

    if (unlikely(in_ifunc)) {
      //
      // when might __jove_env_clunk be NULL? in an ifunc resolver, that's when
      //
      uintptr_t dummy_stack = _jove_alloc_stack();

      struct CPUArchState dummy_env = {0};

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
      target_ulong *const emusp_ptr =
          emulated_stack_pointer_of_cpu_state(JOVE_RT_THREAD_GLOBALP(env));

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

      if (unlikely(__jove_opts.Debug.Calls)) {
        char s[512];
        s[0] = '\0';

        _strcat(s, "\t=0x");
        {
          char buff[65];
          _uint_to_string(res & (((jove_thunk_return_t)1ULL) << (sizeof(uintptr_t)*8)-1), buff, 0x10);

          _strcat(s, buff);
        }

        if (unlikely(__jove_opts.Debug.Stack)) {
          const uintptr_t emusp = *emusp_ptr;

          _strcat(s, " <0x");
          {
            char buff[65];
            _uint_to_string(emusp, buff, 0x10);

            _strcat(s, buff);
          }
          _strcat(s, ">");
        }

        _strcat(s, "\n");

        _DUMP(s);
      }

      return res;
    }

    if (_jove_callstack_enabled()) {
      uint64_t *callstack = JOVE_RT_THREAD_GLOBAL(callstack);

      *callstack-- = 0; /* clear */
      *callstack = 0; /* clear */

      JOVE_RT_THREAD_GLOBAL(callstack) = callstack;
    }
  } else {
    if (unlikely(__jove_opts.Debug.Calls))
    {
      char s[512];
      s[0] = '\0';

      _strcat(s, " R(0x");
      {
	char buff[65];
	_uint_to_string(Callee.RecompiledFunc, buff, 0x10);

	_strcat(s, buff);
      }
      _strcat(s, ")\n");

      _DUMP(s);
    }

    return ((JOVE_THUNK_EXTRA_ATTR jove_thunk_return_t (*)(
                         #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) uintptr_t

                         BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                         #undef __REG_ARG
                         ))Callee.RecompiledFunc)(
                                                 #define __REG_ARG(n, i, data) BOOST_PP_COMMA_IF(i) reg##i

                                                 BOOST_PP_REPEAT(TARGET_NUM_REG_ARGS, __REG_ARG, void)

                                                 #undef __REG_ARG
                                                 );
  }
}

#undef JOVE_THUNK_EXTRA_ATTR

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

#if BITS_PER_LONG == 32
//
// 32-bit DFSan
//
extern struct shadow_t __df32_shadow_mem[1u << 16];

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

static void AssertNonZeroU32(uint32_t x) { _ASSERT(x); }
static void AssertNonZeroU64(uint64_t x) { _ASSERT(x); }

__attribute__((__noreturn__)) void _jove_assert_fail(const char *file,
                                                     unsigned line,
                                                     void *retaddr) {
  char *s;
  JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
  s[0] = '\0';

  _ASSERT(file);

  _strcat(s, "_jove_assert_fail: \"");
  _strcat(s, file);
  _strcat(s, "\":");

  {
    char buff[65];
    _uint_to_string(line, buff, 10);

    _strcat(s, buff);
  }

  _strcat(s, " from=0x");

  {
    char buff[65];
    _uint_to_string((uintptr_t)retaddr, buff, 0x10);

    _strcat(s, buff);
  }

  _strcat(s, "\n");

  _DUMP(s);
  _UNREACHABLE();
}

#if 0 /* FIXME the problem is that this can be called into by recompiled code, \
         but it has no function table entry, so we think it's "new" code when  \
         it's not. */
void *memset(void *dst, int c, size_t n) {
  return __builtin_memset(dst, c, n);
}

void *memcpy(void *dst, const void *src, size_t n) {
  return __builtin_memcpy(dst, src, n);
}
#endif

void __nodce(void **p) {
#ifdef JOVE_COFF
  *p++ = &_jove_recover_anonymous_foreign_function;
#endif
  *p++ = &_jove_assert_fail;
  *p++ = AssertNonZeroU32;
  *p++ = AssertNonZeroU64;
  *p++ = JOVE_RT_THREAD_GLOBALP(trace);
  *p++ = JOVE_RT_THREAD_GLOBALP(trace_begin);
  *p++ = JOVE_RT_THREAD_GLOBALP(callstack);
  *p++ = JOVE_RT_THREAD_GLOBALP(callstack_begin);
  *p++ = &_jove_callstack_enabled;
  *p++ = &_jove_dfsan_enabled;
  *p++ = &_jove_get_init_fn_sect_ptr;
  *p++ = &_jove_get_libc_early_init_fn;
  *p++ = &_jove_get_libc_early_init_fn_sect_ptr;
  *p++ = &_jove_rt_init_clunk;
  *p++ = &_jove_needs_runtime;
  *p++ = &_jove_make_sections_executable;
  *p++ = &_jove_make_sections_not_executable;
#ifdef JOVE_CLUNK
  *p++ = &__jove_env_clunk;
#endif
  *p++ = &_jove_alloc_stack;
  *p++ = &_jove_free_stack;
#if 0
  *p++ = &_jove_alloc_callstack;
  *p++ = &_jove_free_callstack;
#endif
  *p++ = &_jove_call;
#ifdef JOVE_MT
  *p++ = &__jove_local_env;
#endif
#if defined(JOVE_DFSAN)
  *p++ = &_jove_check_return_address;
#if BITS_PER_LONG == 32
  *p++ = &__df32_shadow_for;
#endif
#endif
}

#include "jove.recover.c.inc"
#include "jove.start.c.inc"

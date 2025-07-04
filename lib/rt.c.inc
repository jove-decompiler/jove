#include "rt.util.c.inc"
#include "rt.alloc.c.inc"
#include "rt.recover.h"

#include <signal.h>
#include <ucontext.h>

#ifdef JOVE_COFF
#include "Win.copy.h"
#endif

DEFINE_JOVE_RT_THREAD_GLOBAL(struct CPUArchState, env, {0})

DEFINE_JOVE_RT_THREAD_GLOBAL(uint64_t *, trace, NULL)
DEFINE_JOVE_RT_THREAD_GLOBAL(uint64_t *, trace_begin, NULL)

DEFINE_JOVE_RT_THREAD_GLOBAL(uint64_t *, callstack, NULL)
DEFINE_JOVE_RT_THREAD_GLOBAL(uint64_t *, callstack_begin, NULL)

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

uintptr_t *__jove_sections_tables[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

DEFINE_HASHTABLE(__jove_function_map, JOVE_FUNCTION_MAP_HASH_BITS);

static mutex_t to_free_lock = JOVE_MUTEX_INIT;
static uintptr_t to_free[16];

static void _jove_free_stack_later(uintptr_t stack) {
  _mutex_lock(&to_free_lock);

  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] != 0)
      continue;

    to_free[i] = stack;

    _mutex_unlock(&to_free_lock);
    return;
  }

  _UNREACHABLE();
}

#if defined(JOVE_DFSAN)
#if BITS_PER_LONG == 32
struct shadow_t __df32_shadow_mem[65536];
#endif

void (*__jove_dfsan_flush)(void) = NULL; /* XXX */
unsigned __jove_dfsan_sig_handle = 0;
#endif

#include "kernel_sigaction.h"

static void _jove_rt_signal_handler(int, siginfo_t *, ucontext_t *);

static void _jove_init_cpu_state(void);
static void _jove_callstack_init(void);
static void _jove_trace_init(void);
void _jove_flush_trace(void);

#ifdef JOVE_MT
int _jove_needs_multi_threaded_runtime(void) { return 1; }
#else
int _jove_needs_single_threaded_runtime(void) { return 1; }
#endif

static void _jove_parse_opts(void);

void _jove_rt_init(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  _jove_parse_opts();

  if (unlikely(__jove_opts.Debug.Inits)) _DUMP_FUNC();

  struct kernel_sigaction sa;
  _memset(&sa, 0, sizeof(sa));

  sa.k_sa_handler = (void *)_jove_rt_signal_handler;
  sa.k_sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;

#if defined(__x86_64__)
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif
  sa.k_sa_flags |= SA_RESTORER;
  sa.k_sa_restorer =
#ifdef JOVE_COFF
      _jove_do_rt_sigreturn
#else
      restore_rt
#endif
      ;
#elif defined(__i386__)
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif
  sa.k_sa_flags |= SA_RESTORER;
  sa.k_sa_restorer = _jove_do_rt_sigreturn;
#endif

  if (_jove_sys_rt_sigaction(SIGSEGV, (void *)&sa, NULL, sizeof(kernel_sigset_t)) < 0)
    _UNREACHABLE("failed to install SIGSEGV handler");

  if (_jove_sys_rt_sigaction(SIGBUS, (void *)&sa, NULL, sizeof(kernel_sigset_t)) < 0)
    _UNREACHABLE("failed to install SIGBUS handler");

#if 0
  if (_jove_sys_rt_sigaction(SIGABRT, (void *)&sa, NULL, sizeof(kernel_sigset_t)) < 0)
    _UNREACHABLE("failed to install SIGABRT handler");
#endif

  if (_jove_sys_rt_sigaction(SIGILL, (void *)&sa, NULL, sizeof(kernel_sigset_t)) < 0)
    _UNREACHABLE("failed to install SIGILL handler");

  {
    uintptr_t newstack = _jove_alloc_stack();

    stack_t uss = {.ss_sp = (void *)(newstack + JOVE_PAGE_SIZE),
                   .ss_flags = 0,
                   .ss_size = JOVE_STACK_SIZE - 2 * JOVE_PAGE_SIZE};

    if (_jove_sys_sigaltstack(&uss, NULL) < 0)
      _UNREACHABLE("failed to set alternate signal stack");
  }

  _jove_init_cpu_state();
  _jove_callstack_init();
  _jove_trace_init();
}

static void _jove_dump_opts(void);
static void _jove_parse_debug_string(char *const);
static void _jove_parse_pause_string(char *const);
static void _jove_parse_trace_string(char *const);
static void _jove_parse_crash_string(char *const);
static void _jove_parse_callstack_string(char *const s);
static void _jove_parse_hoard_string(char *const);
static void _jove_parse_sects_string(char *const);

//
// options
//
void _jove_parse_opts(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  __jove_opts.Trace = NULL;

  char *envs;
  unsigned n;
  envs = _get_environ(&n);

  char *env;
  for_each_in_environ(env, envs, n) {
    if (!_strcmp(env, "JOVE_DUMP_OPTS=1"))
      __jove_opts.DumpOpts = true;

#define STRING_OPT(NAME, F)                                                    \
  do {                                                                         \
    if (!_strncmp(env, NAME "=", sizeof(NAME "=") - 1)) {                      \
      F(env + sizeof(NAME "=") - 1);                                           \
      continue;                                                                \
    }                                                                          \
  } while (false)

    STRING_OPT("JOVESECTS", _jove_parse_sects_string);
    STRING_OPT("JOVEHOARD", _jove_parse_hoard_string);
    STRING_OPT("JOVECALLS", _jove_parse_callstack_string);
    STRING_OPT("JOVETRACE", _jove_parse_trace_string);
    STRING_OPT("JOVECRASH", _jove_parse_crash_string);
    STRING_OPT("JOVEDEBUG", _jove_parse_debug_string);
    STRING_OPT("JOVEPAUSE", _jove_parse_pause_string);

#undef STRING_OPT
  }

  if (__jove_opts.DumpOpts)
    _jove_dump_opts();
}

struct debug_option_pair {
  const char *name;
  bool *opt_ptr;
};

static const struct debug_option_pair debug_opt_tbl[] = {
  {"signals", &__jove_opts.Debug.Signals},
  {"thunks",  &__jove_opts.Debug.Thunks},
  {"tramps",  &__jove_opts.Debug.Tramps},
  {"calls",   &__jove_opts.Debug.Calls},
  {"stack",   &__jove_opts.Debug.Stack},
  {"inits",   &__jove_opts.Debug.Inits},
  {"verbose", &__jove_opts.Debug.Verbose},
  {"insn",    &__jove_opts.Debug.Insn},
  {"interactive", &__jove_opts.Debug.Interactive},
  {"detailed", &__jove_opts.Debug.Detailed},
};

void _jove_parse_debug_string(char *const s) {
  const unsigned n = _strlen(s)+1;

  set_restore_char_safe(&s[n - 1], ',', '\0'); /* comma-terminate */

  char *opt;
  for_each_str_delim_know_end(opt, ',', s, n) {
    /* null-terminate */
    set_restore_char_safe(_memchr(opt, ',', n), '\0', ',');

    bool found_opt = false;

    struct debug_option_pair *pairp;
    array_for_each_p(pairp, debug_opt_tbl) {
      if (!_strcmp(pairp->name, opt)) {
        found_opt = true;
        *pairp->opt_ptr = true;
        break;
      }
    }

    _ASSERT(found_opt);
  }
}

static const struct debug_option_pair pause_opt_tbl[] = {
  {"Begin", &__jove_opts.Pause.Begin},
  {"Call", &__jove_opts.Pause.Call},
  {"UnknownCallee", &__jove_opts.Pause.UnknownCallee}
};

void _jove_parse_pause_string(char *const s) {
  const unsigned n = _strlen(s)+1;

  set_restore_char_safe(&s[n - 1], ',', '\0'); /* comma-terminate */

  char *opt;
  for_each_str_delim_know_end(opt, ',', s, n) {
    /* null-terminate */
    set_restore_char_safe(_memchr(opt, ',', n), '\0', ',');

    bool found_opt = false;

    struct debug_option_pair *pairp;
    array_for_each_p(pairp, pause_opt_tbl) {
      if (!_strcmp(pairp->name, opt)) {
        found_opt = true;
        *pairp->opt_ptr = true;
        break;
      }
    }

    if (!found_opt) {
      char *s;
      JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
      s[0] = '\0';

      _strcat(s, "invalid JOVEPAUSE environment variable: \"");
      _strcat(s, opt);
      _strcat(s, "\"\n");

      _DUMP(s);
      _jove_sys_exit_group(1);
      __UNREACHABLE();
    }
  }
}

void _jove_parse_trace_string(char *const s) {
  jove_buffer_t str = _jove_alloc_buffer(PATH_MAX);
  char *p = (char *)str.ptr;

  _strcpy(p, s);

  __jove_opts.Trace = p;
}

void _jove_parse_callstack_string(char *const s) {
  jove_buffer_t str = _jove_alloc_buffer(PATH_MAX);
  char *p = (char *)str.ptr;

  _strcpy(p, s);

  __jove_opts.CallS = p;
}

void _jove_parse_crash_string(char *const s) {
  char ch = s[0];

  switch (ch) {
  case 'a':
  case 's':
  case 'x':
    break;

  default:
    _UNREACHABLE("invalid JOVECRASH environment variable");
  }

  __jove_opts.OnCrash = ch;
}

void _jove_parse_hoard_string(char *const s) {
  __jove_opts.Hoard = s[0] == '1';
}

void _jove_parse_sects_string(char *const s) {
  if (!_strcmp(s, "exe")) {
    __jove_opts.SectsExe = true;
    return;
  }

  _UNREACHABLE("invalid JOVESECTS environment variable");
}

void _jove_dump_opts(void) {
  char s[1024];
  s[0] = '\0';

  struct debug_option_pair *pairp;
  array_for_each_p(pairp, debug_opt_tbl) {
    const unsigned val = (unsigned)*pairp->opt_ptr;

    _strcat(s, pairp->name);
    _strcat(s, "=");
    {
      char buff[64];
      _uint_to_string(val, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "\n");
  }

  if (__jove_opts.OnCrash != '\0') {
    _strcat(s, "OnCrash=");

    {
      char buff[2];
      buff[0] = __jove_opts.OnCrash;
      buff[1] = '\0';

      _strcat(s, buff);
    }
    _strcat(s, "\n");
  }

  _DUMP(s);
}

#ifdef JOVE_COFF
_SECTION(".tls") static char _tls_start;
_SECTION(".tls$ZZZ") static char _tls_end;

ULONG _tls_index = 0;

static void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
  switch (Reason) {
  case DLL_PROCESS_ATTACH:
    _jove_parse_opts();

    _VERBOSE_DUMP("TlsCallback [DLL_PROCESS_ATTACH]\n");
    break;
  case DLL_THREAD_ATTACH:
    _VERBOSE_DUMP("TlsCallback [DLL_THREAD_ATTACH]\n");
    break;
  case DLL_THREAD_DETACH:
    _VERBOSE_DUMP("TlsCallback [DLL_THREAD_DETACH]\n");
    break;
  case DLL_PROCESS_DETACH:
    _VERBOSE_DUMP("TlsCallback [DLL_PROCESS_DETACH]\n");
    break;
  }
}

static PIMAGE_TLS_CALLBACK tls_callbacks[] = {TlsCallback, NULL};

_SECTION(".rdata$T")
const IMAGE_TLS_DIRECTORY _tls_used = {
    (uintptr_t)&_tls_start,
    (uintptr_t)&_tls_end,
    (uintptr_t)&_tls_index,
    (uintptr_t)&tls_callbacks,
    0,
    0
};

BOOL DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    _jove_parse_opts();
    _VERBOSE_DUMP("DllMain [DLL_PROCESS_ATTACH]\n");
    _jove_rt_init();
    break;
  case DLL_THREAD_ATTACH:
    _VERBOSE_DUMP("DllMain [DLL_THREAD_ATTACH]\n");
    _jove_trace_init();
    _jove_callstack_init();
    break;
  case DLL_THREAD_DETACH:
    _VERBOSE_DUMP("DllMain [DLL_THREAD_DETACH]\n");
    _jove_flush_trace();
    break;
  case DLL_PROCESS_DETACH:
    _VERBOSE_DUMP("DllMain [DLL_PROCESS_DETACH]\n");
    _jove_flush_trace();
    break;
  }
  return TRUE;
}

BOOL WINAPI _DllMainCRTStartup(HMODULE hModule, DWORD ul_reason_for_call,
                               LPVOID lpReserved) {
  return DllMain(hModule, ul_reason_for_call, lpReserved);
}

#endif

static _JTHREAD bool __jove_initialized_env = false;

void _jove_init_cpu_state(void) {
  if (__jove_initialized_env)
    return;
  __jove_initialized_env = true;

  struct CPUArchState *const env = &__jove_env;

  if (unlikely(__jove_opts.Debug.Verbose)) {
    char s[128];
    s[0] = '\0';

    _strcat(s, "_jove_init_cpu_state [0x");
    {
      char buff[65];
      _uint_to_string((uintptr_t)env, buff, 0x10);

      _strcat(s, buff);
    }
    _strcat(s, "]\n");

    _DUMP(s);
  }

  static const uint8_t env_init_bytes[] = {
#ifdef JOVE_COFF
#include "env_init.win.inc"
#else
#include "env_init.linux.inc"
#endif
  };

  static_assert(sizeof(env_init_bytes) == sizeof(struct CPUArchState));
  __builtin_memcpy_inline(env, env_init_bytes, sizeof(env_init_bytes));

#if defined(TARGET_X86_64) || defined(TARGET_I386)
  _ASSERT(env->df == 1 || env->df == -1);
#endif
}

static uintptr_t _jove_alloc_callstack(const char *callstack_path) {
  char *path;
  JOVE_SCOPED_BUFF(path, PATH_MAX);

  _ASSERT(callstack_path);

  _strcpy(path, callstack_path);
  _strcat(path, ".");

  {
    char buff[65];
    _uint_to_string(_jove_sys_gettid(), buff, 10);

    _strcat(path, buff);
  }

  long tid = _jove_sys_gettid();

  int fd = _jove_open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  if (_jove_sys_ftruncate(fd, JOVE_CALLSTACK_SIZE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  uintptr_t ret = _mmap_rw_shared_file(fd, JOVE_CALLSTACK_SIZE);
  if (IS_ERR_VALUE(ret))
    _UNREACHABLE("failed to allocate callstack");

  if (_jove_sys_close(fd) < 0)
    _UNREACHABLE("failed to close callstack fd");

  //
  // create guard pages on both sides
  //
  uintptr_t beg = ret;
  uintptr_t end = beg + JOVE_CALLSTACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #1");

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #2");

  JOVE_TRACK_ALLOCATION(beg, JOVE_PAGE_SIZE, "beg-callstack");
  JOVE_TRACK_ALLOCATION(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, "end-callstack");
  JOVE_TRACK_ALLOCATION(beg + JOVE_PAGE_SIZE, JOVE_STACK_SIZE - 2 * JOVE_PAGE_SIZE, "callstack");

  return beg;
}

static void _jove_free_callstack(uintptr_t start) {
  if (_jove_sys_munmap(start - JOVE_PAGE_SIZE, JOVE_CALLSTACK_SIZE) < 0)
    _UNREACHABLE("failed to deallocate callstack");

  JOVE_UNTRACK_ALLOCATION(start, JOVE_CALLSTACK_SIZE);
}

void _jove_callstack_init(void) {
  static _JTHREAD bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  char *const callstack_path = __jove_opts.CallS;
  if (!callstack_path)
    return;

  _VERBOSE_DUMP_FUNC();

  __jove_callstack_begin = __jove_callstack =
      (uint64_t *)(_jove_alloc_callstack(callstack_path) + JOVE_PAGE_SIZE);
}

void _jove_trace_init(void) {
  static _JTHREAD bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  if (!__jove_opts.Trace)
    return;

  _VERBOSE_DUMP_FUNC();

  unsigned long ret = _mmap_rw_anonymous_private_memory(JOVE_TRACE_BUFF_SIZE);
  if (IS_ERR_VALUE(ret))
    _UNREACHABLE("failed to allocate trace buffer");

  unsigned long beg = (unsigned long)ret;
  unsigned long end = beg + JOVE_TRACE_BUFF_SIZE;

  //
  // create guard page
  //
  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page for trace");

  JOVE_TRACK_ALLOCATION(beg, JOVE_TRACE_BUFF_SIZE - JOVE_PAGE_SIZE, "trace");
  JOVE_TRACK_ALLOCATION(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, "end-trace");

  //
  // install
  //
  __jove_trace_begin = __jove_trace = (void *)ret;
}

void _jove_flush_trace(void) {
  _VERBOSE_DUMP_FUNC();

  uint64_t *const TracePtr   = __jove_trace;
  uint64_t *const TraceBegin = __jove_trace_begin;

  if (unlikely(TraceBegin == TracePtr))
    return;

  char *path;
  JOVE_SCOPED_BUFF(path, PATH_MAX);

  char *const trace_path = __jove_opts.Trace;
  _ASSERT(trace_path);

  _strcpy(path, trace_path);
  _strcat(path, ".");

  {
    char buff[65];
    _uint_to_string(_jove_sys_gettid(), buff, 10);

    _strcat(path, buff);
  }

  int fd = _jove_open(path, O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
  if (fd < 0)
    _UNREACHABLE("_jove_flush_trace: failed to open trace file");

  unsigned n = (TracePtr - TraceBegin) * sizeof(uint64_t);

  ssize_t ret = _jove_robust_write(fd, TraceBegin, n);

  if (ret != n)
    _UNREACHABLE("_jove_flush_trace: could not flush trace file");

  if (_jove_sys_close(fd) < 0)
    _UNREACHABLE("_jove_flush_trace: failed to close trace file");

  if (unlikely(__jove_opts.Debug.Verbose)) {
    char *s;
    JOVE_SCOPED_BUFF(s, PATH_MAX);
    _strcpy(s, "flushed ");

    {
      char buff[65];
      _uint_to_string(n, buff, 10);

      _strcat(s, buff);
    }

    _strcat(s, " bytes to ");
    _strcat(s, path);
    _strcat(s, "\n");

    _DUMP(s);
  }

  //
  // reset
  //
  __jove_trace = TraceBegin;
}

static int insn_length(const uint8_t *insnp);
static bool is_sigreturn_insn_sequence(const void *insn_bytes);

_REGPARM
_HIDDEN uintptr_t _jove_handle_signal_delivery(uintptr_t SignalDelivery,
                                               void *SavedState);

_NAKED _HIDDEN void _jove_inverse_thunk(void);

static __thread bool _sighandler_reentered = false;

struct _entered_t { bool *enteredp; };

static struct _entered_t _jove_entered(bool *p) {
  struct _entered_t res = {*p ? NULL : p};
  *p = true;
  return res;
}

static void _jove_clear_entered(const struct _entered_t *entered) {
  _ASSERT(entered->enteredp);

  *entered->enteredp = false;
}

static void dump_detailed_ucontext(ucontext_t *, siginfo_t *);

void _jove_rt_signal_handler(int sig, siginfo_t *si, ucontext_t *uctx) {
  const struct _entered_t entered _CLEANUP(_jove_clear_entered) =
      _jove_entered(&_sighandler_reentered);

  if (sig != SIGSEGV &&
      sig != SIGBUS &&
      sig != SIGABRT &&
      sig != SIGILL)
    _UNREACHABLE("BUG");

#if 0
  if (unlikely(__jove_opts.Debug.Verbose)) {
    char s[128];
    s[0] = '\0';

    _strcat(s, "_jove_rt_sig [");
    {
      char buff[65];
      _uint_to_string(sig, buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "]\n");

    _DUMP(s);
  }
#endif

  _ASSERT(entered.enteredp && "haven't reentered");

  uint64_t **const callstack_ptr = &__jove_callstack;
  uint64_t **const callstack_begin_ptr = &__jove_callstack_begin;

  greg_t *const pc_ptr =
#if defined(__mips64) || defined(__mips__) || defined(__aarch64__)
    &uctx->uc_mcontext.pc
#elif defined(__x86_64__)
    &uctx->uc_mcontext.gregs[REG_RIP]
#elif defined(__i386__)
    &uctx->uc_mcontext.gregs[REG_EIP]
#else
#error
#endif
    ;

  greg_t *const sp_ptr =
#if defined(__mips64) || defined(__mips__)
      &uctx->uc_mcontext.gregs[29]
#elif defined(__x86_64__)
      &uctx->uc_mcontext.gregs[REG_RSP]
#elif defined(__i386__)
      &uctx->uc_mcontext.gregs[REG_ESP]
#elif defined(__aarch64__)
      &uctx->uc_mcontext.sp
#else
#error
#endif
      ;

  greg_t *const ra_ptr =
#if defined(__mips64) || defined(__mips__)
      &uctx->uc_mcontext.gregs[31]
#elif defined(__aarch64__)
      &uctx->uc_mcontext.regs[30]
#else
      NULL
#endif
      ;

  greg_t *const t9_ptr =
#if defined(__mips64) || defined(__mips__)
      &uctx->uc_mcontext.gregs[25]
#else
      NULL
#endif
      ;

  target_ulong *const emusp_ptr =
      emulated_stack_pointer_of_cpu_state(&__jove_env);

  target_ulong *const emut9_ptr =
#if defined(__mips64) || defined(__mips__)
      &__jove_env.active_tc.gpr[25]
#else
      NULL
#endif
      ;

  //
  // if we are in trace mode, we may have hit a guard page. check for this
  // possbility first.
  //
  void *TraceBegin = __jove_trace_begin;

  if (si && TraceBegin) {
    uintptr_t FaultAddr = (uintptr_t)si->si_addr;

    if (FaultAddr) {
      uintptr_t TraceGuardPageBeg = (uintptr_t)TraceBegin + JOVE_TRACE_BUFF_SIZE - JOVE_PAGE_SIZE;
      uintptr_t TraceGuardPageEnd = TraceGuardPageBeg + JOVE_PAGE_SIZE;

      if (FaultAddr >= TraceGuardPageBeg &&
          FaultAddr <= TraceGuardPageEnd) {
        _jove_flush_trace();

        //
        // skip faulting instruction by determining length.
        //
        const uint8_t *const insnp = (const uint8_t *)(*pc_ptr);
        const int len = insn_length(insnp);

        if (unlikely(__jove_opts.Debug.Insn)) {
          char s[1024];

          _strcpy(s, "insn is ");
          {
            char buff[65];
            _int_to_string(len, buff, 10);

            _strcat(s, buff);
          }
          _strcat(s, " bytes (");

          const unsigned n = len > 0 ? len : 10;
          for (unsigned i = 0; i < n; ++i) {
            _strcat(s, "0x");

            char buff[65];
            _uint_to_string(insnp[i], buff, 0x10);

            _strcat(s, buff);

            if (i+1 < n)
              _strcat(s, " ");
          }
          if (!(len > 0))
            _strcat(s, " ...");

          _strcat(s, ")\n");

          _DUMP(s);
        }

        _ASSERT(len > 0);

        *pc_ptr += len;
        return;
      }
    }
  }

  //
  // no time like the present
  //
  {
    _mutex_lock(&to_free_lock);

    for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
      if (to_free[i] == 0)
        continue;

      _jove_free_stack(to_free[i]);
      to_free[i] = 0;
    }

    _mutex_unlock(&to_free_lock);
  }

  const uintptr_t saved_pc = *pc_ptr;

  struct jove_function_info_t Callee;

  //
  // lookup in __jove_function_map
  //
  {
    struct jove_function_info_t *finfo;

    hash_for_each_possible(__jove_function_map, finfo, hlist, saved_pc) {
      if (finfo->pc == saved_pc) {
        Callee = *finfo;
        goto found;
      }
    }
  }

  //
  // lookup in __jove_function_map failed, now try brute force search
  //
  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES; ++BIdx) {
    if (BIdx == 1 ||
        BIdx == 2)
      continue; /* rtld or vdso */

    uintptr_t *fns = __jove_function_tables[BIdx];

    if (!fns)
      continue;

    for (unsigned FIdx = 0; fns[3 * FIdx]; ++FIdx) {
      if (likely(saved_pc != fns[3 * FIdx + 0]))
        continue;

      Callee.IsForeign = 0;

      Callee.BIdx = BIdx;
      Callee.FIdx = FIdx;

      Callee.Recompiled.SectPtr = fns[3 * FIdx + 0];
      Callee.RecompiledFunc     = fns[3 * FIdx + 2];

      goto found;
    }
  }

  //
  // we found new code?
  //
  _jove_recover_function(saved_pc);

  goto not_found;

found:
  //
  // native -> recompiled call
  //
  {
    if (unlikely(Callee.IsForeign)) {
      dump_detailed_ucontext(uctx, si);
      _UNREACHABLE("unexpected callee");
    }

    _jove_init_cpu_state(); /* could be thread start */

    const uintptr_t FuncSectPtr = Callee.Recompiled.SectPtr;
    const uintptr_t FuncPtr     = Callee.RecompiledFunc;

    uint64_t *const saved_callstack       = *callstack_ptr;
    uint64_t *const saved_callstack_begin = *callstack_begin_ptr;

    if (unlikely(saved_callstack_begin)) {
      uint64_t *callstack = saved_callstack;
      *callstack++ = JOVE_COMBINE_B_AND_BB(JOVE_INVALID_BINARY_INDEX,
                                           JOVE_INVALID_BASIC_BLOCK_INDEX);
      *callstack = 0; /* clear */

      __jove_callstack = callstack;
    }

    const uintptr_t saved_sp = *sp_ptr;
    const uintptr_t saved_emusp = *emusp_ptr;
    const uintptr_t saved_retaddr = ra_ptr ? *ra_ptr : *((uintptr_t *)saved_sp);

    //
    // inspect the instruction bytes that the return address points to, to
    // determine whether the kernel has just delivered a signal XXX
    //
    bool SignalDelivery = is_sigreturn_insn_sequence((void *)saved_retaddr);
    if (SignalDelivery) {
#if defined(JOVE_DFSAN)
      ++__jove_dfsan_sig_handle;
#endif

      if (unlikely(__jove_opts.Debug.Signals)) {
        //
        // print number of signal and description of program counter
        //

        char s[512];
        s[0] = '\0';

        _strcat(s, __ANSI_BOLD_BLUE "[signal ");

        int signo =
#if defined(__mips64) || defined(__mips__)
            uctx->uc_mcontext.gregs[4]
#else
            0
#endif
            ;

        {
          char buff[65];
          _uint_to_string(signo, buff, 10);

          _strcat(s, buff);
        }

        _strcat(s, "] @ 0x");

        {
          char buff[65];
          _uint_to_string(saved_pc, buff, 0x10);

          _strcat(s, buff);
        }

#if 0
        {
	  char *maps;
          JOVE_SCOPED_BUFF(maps, JOVE_MAX_PROC_MAPS);
          unsigned n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

          char buff[256];
          _description_of_address_for_maps(buff, saved_pc, maps, n);
          if (_strlen(buff) != 0) {
            _strcat(s, " <");
            _strcat(s, buff);
            _strcat(s, ">");
          }
        }
#endif

        _strcat(s, "\n" __ANSI_NORMAL_COLOR);

        _DUMP(s);
      }
    }

    if (unlikely(__jove_opts.Debug.Thunks)) {
      //
      // print information about call taking place
      //
      char s[512];
      s[0] = '\0';

      _strcat(s, "_jove_rt_sig: -> 0x");
      {
        char buff[65];
        _uint_to_string(FuncPtr, buff, 0x10);

        _strcat(s, buff);
      }

      _strcat(s, " ->_ 0x");
      {
        char buff[65];
        _uint_to_string(saved_retaddr, buff, 0x10);

        _strcat(s, buff);
      }

      if (__jove_opts.Debug.Stack) {
        _strcat(s, " <0x");
        {
          char buff[65];
          _uint_to_string(saved_sp, buff, 0x10);

          _strcat(s, buff);
        }

        _strcat(s, ">");
      }

      _strcat(s, " [");
      {
        char buff[65];
        _uint_to_string(sig, buff, 10);

        _strcat(s, buff);
      }

      _strcat(s, "]\n");

      _DUMP(s);
    }

    if (unlikely(__jove_opts.Debug.Interactive)) {
      char buff;
      while (_jove_sys_read(STDIN_FILENO, &buff, 1) > 0 && buff != '\n');
    }

    //
    // setup emulated stack
    //
    {
      static uint64_t __dummy_trace_point;

      const uintptr_t newstack = _jove_alloc_stack();

      /* TODO make tight */
      uintptr_t newsp =
          newstack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE - 60 * sizeof(uintptr_t);

      if (SignalDelivery)
        newsp -= sizeof(__jove_env);

      //
      // align the stack
      //
      newsp &= ~31UL;

#if defined(__x86_64__) || defined(__i386__)
      newsp -= sizeof(uintptr_t); /* account for return address on the stack */
#endif

      {
        uintptr_t *p = (uintptr_t *)newsp;

#if defined(__x86_64__) || defined(__i386__)
        *p++ = (uintptr_t)_jove_inverse_thunk; /* return address */
        *p++ = saved_retaddr;
        *p++ = saved_sp;
        *p++ = saved_emusp;
        *p++ = saved_callstack ? (uintptr_t)saved_callstack : (uintptr_t)&__dummy_trace_point;
        *p++ = (uintptr_t)saved_callstack_begin;
        *p++ = newstack;
        *p++ = SignalDelivery;

#if defined(__x86_64__)

#ifdef JOVE_COFF /* CSR_Win64 */
        *p++ = uctx->uc_mcontext.gregs[REG_RDI]; /* saved rdi */
        *p++ = uctx->uc_mcontext.gregs[REG_RSI]; /* saved rsi */

        static_assert(sizeof(uctx->uc_mcontext.fpregs->_xmm[6]) == 16);

        __builtin_memcpy_inline( /* saved xmm[6]...xmm[15] */
            (uint8_t *)p,
            (const uint8_t *)&uctx->uc_mcontext.fpregs->_xmm[6], 160);
#else
        ++p;
        ++p;
#endif
        p += (160 / sizeof(uintptr_t));
#endif

#elif defined(__mips__) || defined(__mips64)
        *p++ = 0xdeadbeef;
        *p++ = saved_retaddr;
        *p++ = saved_sp;
        *p++ = saved_emusp;
        *p++ = saved_callstack ? (uintptr_t)saved_callstack : (uintptr_t)&__dummy_trace_point;
        *p++ = (uintptr_t)saved_callstack_begin;
        *p++ = newstack;
        *p++ = (uintptr_t)emusp_ptr;
        *p++ = (uintptr_t)callstack_begin_ptr;
        *p++ = saved_callstack ? (uintptr_t)saved_callstack : (uintptr_t)&__dummy_trace_point;
        *p++ = (uintptr_t)_jove_free_stack_later;
        *p++ = (uintptr_t)_jove_free_callstack;
        *p++ = 0; /* saved v0 */
        *p++ = 0; /* saved v1 */
        *p++ = (uintptr_t)callstack_begin_ptr;
        *p++ = (uintptr_t)callstack_ptr;
        *p++ = SignalDelivery;
        *p++ = (uintptr_t)_jove_handle_signal_delivery;
#elif defined(__aarch64__)
        *p++ = 0xdeadbeeffeedface;
        *p++ = saved_retaddr;
        *p++ = saved_sp;
        *p++ = saved_emusp;
        *p++ = saved_callstack ? (uintptr_t)saved_callstack : (uintptr_t)&__dummy_trace_point;
        *p++ = (uintptr_t)saved_callstack_begin;
        *p++ = newstack;
#else
#error
#endif

        *p = (uintptr_t)(p + 1);
        ++p;

        if (SignalDelivery)
          __builtin_memcpy_inline(p, &__jove_env, sizeof(__jove_env));
      }

      if (unlikely(__jove_opts.Debug.Stack)) {
#if defined(__x86_64__) || defined(__i386__)
        _ASSERT(((newsp + sizeof(uintptr_t)) % 32) == 0);
#endif
      }

      *sp_ptr = newsp;
    }

    if (ra_ptr)
      *ra_ptr = (uintptr_t)_jove_inverse_thunk;
    if (t9_ptr)
      *t9_ptr = FuncPtr;
    if (emut9_ptr)
      *emut9_ptr = FuncSectPtr;

#if 0
    *callstack_begin_ptr = *callstack_ptr =
        (uint64_t *)(_jove_alloc_callstack() + JOVE_PAGE_SIZE);
#endif

    *emusp_ptr = saved_sp; /* native stack becomes emulated stack */

    *pc_ptr = FuncPtr;

    return;
  }

not_found:
on_crash:
  //
  // if we get here we'll assume it's a crash.
  //
  dump_detailed_ucontext(uctx, si);

  //
  // flush trace
  //
  _jove_flush_trace();

  //
  // flush dfsan_log.pb
  //
#if defined(JOVE_DFSAN)
  void (*dfsan_flush_ptr)(void) = __jove_dfsan_flush;
  if (dfsan_flush_ptr) {
    _DUMP(__ANSI_BOLD_BLUE "calling __jove_dfsan_flush\n" __ANSI_NORMAL_COLOR);
    dfsan_flush_ptr();
  }
#endif

  _jove_on_crash(__jove_opts.OnCrash);
  __UNREACHABLE();
}

void dump_detailed_ucontext(ucontext_t *uctx, siginfo_t *si) {
  char *maps;
  unsigned maps_n;
  LOAD_PROC_SELF_MAPS(maps, maps_n);

  char *s;
  JOVE_SCOPED_BUFF(s, JOVE_LARGE_BUFF_SIZE);
  s[0] = '\0';

  _strcat(s, "*** crash? *** [");
  {
    char buff[65];
    _uint_to_string(_jove_sys_gettid(), buff, 10);

    _strcat(s, buff);
  }
  _strcat(s, "]\n");

  char *buff;
  JOVE_SCOPED_BUFF(buff, 2*PATH_MAX);
  buff[0] = '\0';

#define _FIELD(name, init)                                                     \
  do {                                                                       \
    _strcat(s, name " 0x");                                                  \
    {                                                                        \
      char _buff[65];                                                        \
      _uint_to_string((uintptr_t)init, _buff, 0x10);                         \
                                                                             \
      _strcat(s, _buff);                                                     \
    }                                                                        \
    if (_description_of_address_for_maps(buff, (uintptr_t)(init), maps, maps_n)) {\
      _strcat(s, " <");                                                      \
      _strcat(s, buff);                                                      \
      _strcat(s, ">");                                                       \
    }                                                                        \
    _strcat(s, "\n");                                                        \
  } while (false)

  if (si)
    _FIELD("si_addr", si->si_addr);

#if defined(__x86_64__)

  _FIELD("pc", uctx->uc_mcontext.gregs[REG_RIP]);
  _FIELD("rax", uctx->uc_mcontext.gregs[REG_RAX]);
  _FIELD("rcx", uctx->uc_mcontext.gregs[REG_RCX]);
  _FIELD("rdx", uctx->uc_mcontext.gregs[REG_RDX]);
  _FIELD("rbx", uctx->uc_mcontext.gregs[REG_RBX]);
  _FIELD("rsp", uctx->uc_mcontext.gregs[REG_RSP]);
  _FIELD("rbp", uctx->uc_mcontext.gregs[REG_RBP]);
  _FIELD("rsi", uctx->uc_mcontext.gregs[REG_RSI]);
  _FIELD("rdi", uctx->uc_mcontext.gregs[REG_RDI]);
  _FIELD("r8 ", uctx->uc_mcontext.gregs[REG_R8]);
  _FIELD("r9 ", uctx->uc_mcontext.gregs[REG_R9]);
  _FIELD("r10", uctx->uc_mcontext.gregs[REG_R10]);
  _FIELD("r11", uctx->uc_mcontext.gregs[REG_R11]);
  _FIELD("r12", uctx->uc_mcontext.gregs[REG_R12]);
  _FIELD("r13", uctx->uc_mcontext.gregs[REG_R13]);
  _FIELD("r14", uctx->uc_mcontext.gregs[REG_R14]);
  _FIELD("r15", uctx->uc_mcontext.gregs[REG_R15]);

#elif defined(__i386__)

  _FIELD("pc", uctx->uc_mcontext.gregs[REG_EIP]);
  _FIELD("GS ", uctx->uc_mcontext.gregs[REG_GS]);
  _FIELD("FS ", uctx->uc_mcontext.gregs[REG_FS]);
  _FIELD("ES ", uctx->uc_mcontext.gregs[REG_ES]);
  _FIELD("DS ", uctx->uc_mcontext.gregs[REG_DS]);
  _FIELD("EDI", uctx->uc_mcontext.gregs[REG_EDI]);
  _FIELD("ESI", uctx->uc_mcontext.gregs[REG_ESI]);
  _FIELD("EBP", uctx->uc_mcontext.gregs[REG_EBP]);
  _FIELD("ESP", uctx->uc_mcontext.gregs[REG_ESP]);
  _FIELD("EBX", uctx->uc_mcontext.gregs[REG_EBX]);
  _FIELD("EDX", uctx->uc_mcontext.gregs[REG_EDX]);
  _FIELD("ECX", uctx->uc_mcontext.gregs[REG_ECX]);
  _FIELD("EAX", uctx->uc_mcontext.gregs[REG_EAX]);
  _FIELD("TRAPNO", uctx->uc_mcontext.gregs[REG_TRAPNO]);
  _FIELD("ERR", uctx->uc_mcontext.gregs[REG_ERR]);
  _FIELD("EIP", uctx->uc_mcontext.gregs[REG_EIP]);
  _FIELD("CS", uctx->uc_mcontext.gregs[REG_CS]);
  _FIELD("EFL", uctx->uc_mcontext.gregs[REG_EFL]);
  _FIELD("UESP", uctx->uc_mcontext.gregs[REG_UESP]);
  _FIELD("SS", uctx->uc_mcontext.gregs[REG_SS]);

#elif defined(__mips64) || defined(__mips__)

  _FIELD("pc", uctx->uc_mcontext.pc);
  _FIELD("r0", uctx->uc_mcontext.gregs[0]);
  _FIELD("at", uctx->uc_mcontext.gregs[1]);
  _FIELD("v0", uctx->uc_mcontext.gregs[2]);
  _FIELD("v1", uctx->uc_mcontext.gregs[3]);
  _FIELD("a0", uctx->uc_mcontext.gregs[4]);
  _FIELD("a1", uctx->uc_mcontext.gregs[5]);
  _FIELD("a2", uctx->uc_mcontext.gregs[6]);
  _FIELD("a3", uctx->uc_mcontext.gregs[7]);
  _FIELD("t0", uctx->uc_mcontext.gregs[8]);
  _FIELD("t1", uctx->uc_mcontext.gregs[9]);
  _FIELD("t2", uctx->uc_mcontext.gregs[10]);
  _FIELD("t3", uctx->uc_mcontext.gregs[11]);
  _FIELD("t4", uctx->uc_mcontext.gregs[12]);
  _FIELD("t5", uctx->uc_mcontext.gregs[13]);
  _FIELD("t6", uctx->uc_mcontext.gregs[14]);
  _FIELD("t7", uctx->uc_mcontext.gregs[15]);
  _FIELD("s0", uctx->uc_mcontext.gregs[16]);
  _FIELD("s1", uctx->uc_mcontext.gregs[17]);
  _FIELD("s2", uctx->uc_mcontext.gregs[18]);
  _FIELD("s3", uctx->uc_mcontext.gregs[19]);
  _FIELD("s4", uctx->uc_mcontext.gregs[20]);
  _FIELD("s5", uctx->uc_mcontext.gregs[21]);
  _FIELD("s6", uctx->uc_mcontext.gregs[22]);
  _FIELD("s7", uctx->uc_mcontext.gregs[23]);
  _FIELD("t8", uctx->uc_mcontext.gregs[24]);
  _FIELD("t9", uctx->uc_mcontext.gregs[25]);
  _FIELD("k0", uctx->uc_mcontext.gregs[26]);
  _FIELD("k1", uctx->uc_mcontext.gregs[27]);
  _FIELD("gp", uctx->uc_mcontext.gregs[28]);
  _FIELD("sp", uctx->uc_mcontext.gregs[29]);
  _FIELD("s8", uctx->uc_mcontext.gregs[30]);
  _FIELD("ra", uctx->uc_mcontext.gregs[31]);

#elif defined(__aarch64__)

  _FIELD("fault_address ", uctx->uc_mcontext.fault_address);
  _FIELD("sp ", uctx->uc_mcontext.sp);
  _FIELD("pc ", uctx->uc_mcontext.pc);

  // TODO

#else
#error
#endif

#undef _FIELD

  _strcat(s, "\n");
  _strcat(s, maps);

  _DUMP(s);
}

uintptr_t _jove_handle_signal_delivery(uintptr_t SignalDelivery,
                                       void *SavedState) {
  //
  // save the emusp *before* we restore env
  //
  const uintptr_t res =
#if defined(__x86_64__) || defined(__i386__)
      __jove_env.regs[R_ESP]
#elif defined(__mips64) || defined(__mips__)
      __jove_env.active_tc.gpr[29]
#elif defined(__aarch64__)
      __jove_env.xregs[31]
#else
#error
#endif
      ;

  if (SignalDelivery) {
    __builtin_memcpy_inline(&__jove_env, SavedState, sizeof(__jove_env));

#if defined(JOVE_DFSAN)
    __jove_dfsan_sig_handle = 0;
#endif
  }

  return res;
}

void __nodce(void **p) {
  *p++ = &__jove_trace;
  *p++ = &__jove_trace_begin;
  *p++ = &__jove_callstack;
  *p++ = &__jove_callstack_begin;
  *p++ = &__jove_function_tables;
  *p++ = &__jove_sections_tables;
  *p++ = &__jove_function_map;
#if defined(JOVE_DFSAN)
  *p++ = &__jove_dfsan_flush;
  *p++ = &__jove_dfsan_sig_handle;
#endif
  *p++ = &_jove_rt_init;
}

#include "rt.recover.c.inc"

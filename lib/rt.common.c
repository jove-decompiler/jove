#include "rt.util.c"

#include <signal.h>
#include <ucontext.h>

__JTHREAD struct CPUArchState __jove_env __attribute__((aligned(64)));

static __JTHREAD bool __jove_initialized_env = false;

__JTHREAD uint64_t *__jove_trace       = NULL;
__JTHREAD uint64_t *__jove_trace_begin = NULL;

__JTHREAD uint64_t *__jove_callstack       = NULL;
__JTHREAD uint64_t *__jove_callstack_begin = NULL;

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

uintptr_t *__jove_sections_tables[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

DEFINE_HASHTABLE(__jove_function_map, JOVE_FUNCTION_MAP_HASH_BITS);

static uintptr_t to_free[16];

static void _jove_free_stack_later(uintptr_t stack) {
  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] != 0)
      continue;

    to_free[i] = stack;
    return;
  }

  _UNREACHABLE();
}

//
// for DFSan
//
struct shadow_t __df32_shadow_mem[65536];

void (*__jove_dfsan_flush)(void) = NULL; /* XXX */
unsigned __jove_dfsan_sig_handle = 0;

#include "kernel_sigaction.h"

static void _jove_rt_signal_handler(int, siginfo_t *, ucontext_t *);

static void _jove_init_cpu_state(void);
static void _jove_callstack_init(void);
static void _jove_trace_init(void);

#ifdef JOVE_MT
int _jove_needs_multi_threaded_runtime(void) { return 1; }
#else
int _jove_needs_single_threaded_runtime(void) { return 1; }
#endif

#if defined(__x86_64__)
#if 0
extern void restore_rt (void) asm ("__restore_rt") __attribute__ ((visibility ("hidden")));
#endif
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
  sa.k_sa_restorer = _jove_do_rt_sigreturn; // restore_rt
#elif defined(__i386__)
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
static void _jove_parse_crash_string(char *const);

//
// options
//
void _jove_parse_opts(void) {
  JOVE_BUFF(envs, ARG_MAX);
  const unsigned n =
      _jove_read_pseudo_file("/proc/self/environ", _envs.ptr, _envs.len);

  char *env;
  for_each_in_environ(env, envs, n) {
    if (!_strcmp(env, "JOVE_DUMP_OPTS=1"))
      __jove_opts.DumpOpts = true;

    if (!_strncmp(env, "JOVECRASH=", sizeof("JOVECRASH=")-1))
      _jove_parse_crash_string(env + sizeof("JOVECRASH=")-1);

    if (!_strncmp(env, "JOVEDEBUG=", sizeof("JOVEDEBUG=")-1))
      _jove_parse_debug_string(env + sizeof("JOVEDEBUG=")-1);
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
};

void _jove_parse_debug_string(char *const s) {
  const unsigned n = _strlen(s)+1;

  save_and_swap_back_char_safe(&s[n - 1], ',', '\0'); /* comma-terminate */

  char *opt;
  for_each_str_delim_know_end(opt, ',', s, n) {
    /* null-terminate */
    save_and_swap_back_char_safe(_memchr(opt, ',', n), '\0', ',');

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

void _jove_parse_crash_string(char *const s) {
  char ch = s[0];

  switch (ch) {
  case 'a':
  case 's':
    break;

  default:
    _UNREACHABLE("invalid JOVECRASH environment variable");
  }

  __jove_opts.OnCrash = ch;
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

BOOL DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{

    switch (ul_reason_for_call)
    {
    case 1: // DLL_PROCESS_ATTACH
        // Code to run when the DLL is loaded
        _jove_rt_init();
        break;
    case 2: // DLL_THREAD_ATTACH
        // Code to run when a thread is created within the DLL
        break;
    case 3: // DLL_THREAD_DETACH
        // Code to run when a thread within the DLL terminates
        break;
    case 0: // DLL_PROCESS_DETACH
        // Code to run when the DLL is unloaded
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH
}

BOOL WINAPI _DllMainCRTStartup(HMODULE hModule,
                               DWORD ul_reason_for_call,
                               LPVOID lpReserved)
{
    return DllMain(hModule, ul_reason_for_call, lpReserved);
}

void ___chkstk_ms() {}
void __chkstk() {}

void _jove_init_cpu_state(void) {
  if (__jove_initialized_env)
    return;
  __jove_initialized_env = true;

#if defined(__mips64) || defined(__mips__)
  __jove_env.hflags = 226;
#elif defined(__x86_64__) || defined(__i386__)
  __jove_env.df = 1;

  __jove_env.fpuc = 0x37f;
  __jove_env.fptags[0] = 1;
  __jove_env.fptags[1] = 1;
  __jove_env.fptags[2] = 1;
  __jove_env.fptags[3] = 1;
  __jove_env.fptags[4] = 1;
  __jove_env.fptags[5] = 1;
  __jove_env.fptags[6] = 1;
  __jove_env.fptags[7] = 1;
#endif

#if defined(__x86_64__) || defined(__i386__)
#define CPUID_XSAVE_XGETBV1    (1U << 2)

  __jove_env.features[FEAT_XSAVE] |= CPUID_XSAVE_XGETBV1;

#define CR4_OSXSAVE_MASK (1U << 18)

  __jove_env.cr[4] |= CR4_OSXSAVE_MASK;
#endif
}

void _jove_callstack_init(void) {
  __jove_callstack_begin = __jove_callstack =
      (uint64_t *)(_jove_alloc_callstack() + JOVE_PAGE_SIZE);
}

void _jove_trace_init(void) {
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

  //
  // install
  //
  __jove_trace_begin = __jove_trace = (void *)ret;
}

void _jove_flush_trace(void) {
  uint64_t *TracePtr = __jove_trace;
  uint64_t *const TraceBegin = __jove_trace_begin;

  if (unlikely(TraceBegin == TracePtr))
    return;

  int fd;
  {
    char path[4096];
    path[0] = '\0';

    _strcat(path, "/mnt/jove.");
    {
      char buff[65];
      _uint_to_string(_jove_sys_gettid(), buff, 10);

      _strcat(path, buff);
    }
    _strcat(path, ".trace.bin");

#ifdef __aarch64__
    fd = _jove_sys_openat(-1, path, O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
#else
    fd = _jove_sys_open(path, O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
#endif

    if (fd < 0)
      _UNREACHABLE("_jove_flush_trace: failed to open trace file");
  }

  --TracePtr;
  unsigned n = (TracePtr - TraceBegin) * sizeof(uint64_t);

  ssize_t ret = _jove_robust_write(fd, TraceBegin, n);

  if (ret != n)
    _UNREACHABLE("_jove_flush_trace: could not flush trace file");

  if (_jove_sys_close(fd) < 0)
    _UNREACHABLE("_jove_flush_trace: failed to close trace file");

  //
  // reset
  //
  __jove_trace = TraceBegin;
}

static bool is_sigreturn_insn_sequence(const void *insn_bytes);

_REGPARM
_HIDDEN uintptr_t _jove_handle_signal_delivery(uintptr_t SignalDelivery,
                                               void *SavedState);

_NAKED _HIDDEN void _jove_inverse_thunk(void);

void _jove_rt_signal_handler(int sig, siginfo_t *si, ucontext_t *uctx) {
  if (sig != SIGSEGV &&
      sig != SIGBUS &&
      sig != SIGABRT &&
      sig != SIGILL)
    _UNREACHABLE("BUG");

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
        void *Trace = __jove_trace;

        if (Trace != TraceBegin)
          _jove_flush_trace();

        //
        // skip faulting instruction. to do so, we need to determine its length
        //
        unsigned insn_len;

#if defined(__mips64) || defined(__mips__) || defined(__aarch64__)
        insn_len = 4;
#elif defined(__x86_64) || defined(__i386__)
        insn_len = 0; /* XXX TODO */
#else
#error
#endif
        *pc_ptr += insn_len;
        return;
      }
    }
  }

  //
  // no time like the present
  //
  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] == 0)
      continue;

    _jove_free_stack(to_free[i]);
    to_free[i] = 0;
  }

  const uintptr_t saved_pc = *pc_ptr;

  struct jove_function_info_t Callee;

  //
  // lookup in __jove_function_map
  //
  {
    struct jove_function_info_t *finfo;

    hash_for_each_possible(__jove_function_map, finfo, hlist, saved_pc) {
      if (finfo->pc != saved_pc) {
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

  goto not_found;

found:
  //
  // native -> recompiled call
  //
  {
    if (unlikely(Callee.IsForeign))
      _UNREACHABLE("unexpected callee");

    const uintptr_t FuncSectPtr = Callee.Recompiled.SectPtr;
    const uintptr_t FuncPtr     = Callee.RecompiledFunc;

    uint64_t *const saved_callstack       = *callstack_ptr;
    uint64_t *const saved_callstack_begin = *callstack_begin_ptr;

    const uintptr_t saved_sp = *sp_ptr;
    const uintptr_t saved_emusp = *emusp_ptr;
    const uintptr_t saved_retaddr = ra_ptr ? *ra_ptr : *((uintptr_t *)saved_sp);

    //
    // inspect the instruction bytes that the return address points to, to
    // determine whether the kernel has just delivered a signal XXX
    //
    bool SignalDelivery = is_sigreturn_insn_sequence((void *)saved_retaddr);
    if (SignalDelivery) {
      ++__jove_dfsan_sig_handle;

      if (unlikely(__jove_opts.Debug.Signals)) {
        //
        // print number of signal and description of program counter
        //

        char s[4096 * 16];
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

        {
          JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);
          unsigned n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

          char buff[256];
          _description_of_address_for_maps(buff, saved_pc, maps, n);
          if (_strlen(buff) != 0) {
            _strcat(s, " <");
            _strcat(s, buff);
            _strcat(s, ">");
          }
        }

        _strcat(s, "\n" __ANSI_NORMAL_COLOR);

        _DUMP(s);
      }
    }

    if (unlikely(__jove_opts.Debug.Thunks)) {
      //
      // print information about call taking place
      //
      char s[2048];
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

    //
    // setup emulated stack
    //
    {
      const uintptr_t newstack = _jove_alloc_stack();

      uintptr_t newsp =
          newstack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE - 19 * sizeof(uintptr_t);

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
        *p++ = (uintptr_t)saved_callstack;
        *p++ = (uintptr_t)saved_callstack_begin;
        *p++ = newstack;
        *p++ = SignalDelivery;
#elif defined(__mips__) || defined(__mips64)
        *p++ = 0xdeadbeef;
        *p++ = saved_retaddr;
        *p++ = saved_sp;
        *p++ = saved_emusp;
        *p++ = (uintptr_t)saved_callstack;
        *p++ = (uintptr_t)saved_callstack_begin;
        *p++ = newstack;
        *p++ = (uintptr_t)emusp_ptr;
        *p++ = (uintptr_t)callstack_begin_ptr;
        *p++ = (uintptr_t)saved_callstack;
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
        *p++ = (uintptr_t)saved_callstack;
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

    *callstack_begin_ptr = *callstack_ptr =
        (uint64_t *)(_jove_alloc_callstack() + JOVE_PAGE_SIZE);

    *emusp_ptr = saved_sp; /* native stack becomes emulated stack */

    *pc_ptr = FuncPtr;

    _jove_init_cpu_state();
    return;
  }

not_found:
  {
    //
    // if we get here we'll assume it's a crash.
    //
    JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);
    unsigned maps_n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

    JOVE_BUFF(s, JOVE_LARGE_BUFF_SIZE);
    s[0] = '\0';

    _strcat(s, "*** crash (jove) *** [");
    {
      char buff[65];
      _uint_to_string(_jove_sys_gettid(), buff, 10);

      _strcat(s, buff);
    }
    _strcat(s, "]\n");

#define _FIELD(name, init)                                                     \
    do {                                                                       \
      _strcat(s, name " 0x");                                                  \
                                                                               \
      {                                                                        \
        char _buff[65];                                                        \
        _uint_to_string((uintptr_t)init, _buff, 0x10);                         \
                                                                               \
        _strcat(s, _buff);                                                     \
      }                                                                        \
      {                                                                        \
        char _buff[PATH_MAX];                                                  \
        _description_of_address_for_maps(_buff, (uintptr_t)(init), maps, maps_n);\
        if (_strlen(_buff) != 0) {                                             \
          _strcat(s, " <");                                                    \
          _strcat(s, _buff);                                                   \
          _strcat(s, ">");                                                     \
        }                                                                      \
      }                                                                        \
                                                                               \
      _strcat(s, "\n");                                                        \
    } while (false)

    if (si)
      _FIELD("si_addr", si->si_addr);

    _FIELD("pc", saved_pc);

#if defined(__x86_64__)

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

#if 0
    {
      int fd = _jove_sys_open("/tmp/hack.tmp", O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
      _jove_sys_write(fd, buff, _strlen(buff));
      _jove_sys_close(fd);
    }
#endif

    //
    // flush trace
    //
    _jove_flush_trace();

    //
    // flush dfsan_log.pb
    //
    void (*dfsan_flush_ptr)(void) = __jove_dfsan_flush;
    if (dfsan_flush_ptr) {
      {
        char buff[256];
        buff[0] = '\0';

        _strcat(buff, __ANSI_BOLD_BLUE "calling __jove_dfsan_flush\n" __ANSI_NORMAL_COLOR);

        _jove_sys_write(2 /* stderr */, buff, _strlen(buff));
      }

      dfsan_flush_ptr();
    }
  }

  _jove_on_crash(__jove_opts.OnCrash);
  __UNREACHABLE();
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

    __jove_dfsan_sig_handle = 0;
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
  *p++ = &__jove_dfsan_flush;
  *p++ = &__jove_dfsan_sig_handle;
}

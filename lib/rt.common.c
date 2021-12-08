/* __thread */ uint64_t *__jove_trace       = NULL;
/* __thread */ uint64_t *__jove_trace_begin = NULL;

/* __thread */ uint64_t *__jove_callstack       = NULL;
/* __thread */ uint64_t *__jove_callstack_begin = NULL;

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

uintptr_t *__jove_sections_table[_JOVE_MAX_BINARIES] = {
  [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

struct shadow_t __df32_shadow_mem[65536];

void (*__jove_dfsan_flush)(void) = NULL; /* XXX */

static uintptr_t to_free[16];

void _jove_free_stack_later(uintptr_t stack) {
  for (unsigned i = 0; i < ARRAY_SIZE(to_free); ++i) {
    if (to_free[i] != 0)
      continue;

    to_free[i] = stack;
    return;
  }

  _UNREACHABLE();
}

//
// declare sigaction struct from the kernel
//
#undef sa_handler
#undef sa_restorer
#undef sa_flags
#undef _NSIG
#undef _NSIG_BPW
#undef _NSIG_WORDS

#if defined(__mips64)

// FIXME copied from mips32
# define _NSIG		128
# define _NSIG_BPW	32
# define __ARCH_HAS_IRIX_SIGACTION

#elif defined(__mips__)

# define _NSIG		128
# define _NSIG_BPW	32
# define __ARCH_HAS_IRIX_SIGACTION

#elif defined(__x86_64__)

# define _NSIG		64
# define _NSIG_BPW	64
# define __ARCH_HAS_SA_RESTORER

#elif defined(__i386__)

# define _NSIG		64
# define _NSIG_BPW	32
# define __ARCH_HAS_SA_RESTORER

#elif defined(__aarch64__)

#define _NSIG		64
#define _NSIG_BPW	64
#define __ARCH_HAS_SA_RESTORER

#else
#error
#endif

#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} kernel_sigset_t;

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t(void);

typedef __restorefn_t *__sigrestore_t;

struct kernel_sigaction {
#ifndef __ARCH_HAS_IRIX_SIGACTION
	__sighandler_t	sa_handler;
	unsigned long	sa_flags;
#else
	unsigned int	sa_flags;
	__sighandler_t	sa_handler;
#endif
#ifdef __ARCH_HAS_SA_RESTORER
	__sigrestore_t sa_restorer;
#endif
	kernel_sigset_t	sa_mask;	/* mask last for extensibility */
};

static void _jove_rt_signal_handler(int, siginfo_t *, ucontext_t *);

static void _jove_init_cpu_state(void);
static void _jove_callstack_init(void);
static void _jove_trace_init(void);

#if defined(__x86_64__)
extern void restore_rt (void) asm ("__restore_rt") __attribute__ ((visibility ("hidden")));
#endif

void _jove_rt_init(void) {
  static bool _Done = false;
  if (_Done)
    return;
  _Done = true;

  struct kernel_sigaction sa;
  _memset(&sa, 0, sizeof(sa));

  sa.sa_handler = _jove_rt_signal_handler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;

#if defined(__x86_64__)
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif
  sa.sa_flags |= SA_RESTORER;
  sa.sa_restorer = restore_rt; // _jove_do_rt_sigreturn
#elif defined(__i386__)
  sa.sa_restorer = _jove_do_rt_sigreturn;
#endif

  if (_jove_sys_rt_sigaction(SIGSEGV, &sa, NULL, sizeof(kernel_sigset_t)) < 0)
    _UNREACHABLE("failed to install SIGSEGV handler");

  if (_jove_sys_rt_sigaction(SIGBUS, &sa, NULL, sizeof(kernel_sigset_t)) < 0)
    _UNREACHABLE("failed to install SIGBUS handler");

  if (_jove_sys_rt_sigaction(SIGABRT, &sa, NULL, sizeof(kernel_sigset_t)) < 0)
    _UNREACHABLE("failed to install SIGABRT handler");

  {
    uintptr_t newstack = _jove_alloc_stack();

    stack_t uss = {.ss_sp = newstack + JOVE_PAGE_SIZE,
                   .ss_flags = 0,
                   .ss_size = JOVE_STACK_SIZE - 2 * JOVE_PAGE_SIZE};

    if (_jove_sys_sigaltstack(&uss, NULL) < 0)
      _UNREACHABLE("failed to set alternate signal stack");
  }

  _jove_init_cpu_state();
  _jove_callstack_init();
  _jove_trace_init();
}

void _jove_init_cpu_state(void) {
#if defined(__mips64) || defined(__mips__)
  __jove_env.hflags = 226;
#elif defined(__x86_64__) || defined(__i386__)
  __jove_env.df = 1;
#endif

#if !defined(__x86_64__) && defined(__i386__)
#define CPUID_XSAVE_XGETBV1    (1U << 2)

  __jove_env.features[FEAT_XSAVE] |= CPUID_XSAVE_XGETBV1;
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

  ssize_t ret = _robust_write(fd, TraceBegin, n);

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

#if !defined(__x86_64__) && defined(__i386__)
_REGPARM
#endif
_HIDDEN uintptr_t _jove_handle_signal_delivery(uintptr_t SignalDelivery,
                                               void *SavedState);

_NAKED _HIDDEN void _jove_inverse_thunk(void);

void _jove_rt_signal_handler(int sig, siginfo_t *si, ucontext_t *uctx) {
  if (sig != SIGSEGV &&
      sig != SIGBUS &&
      sig != SIGABRT)
    _UNREACHABLE("BUG");

  uint64_t **const callstack_ptr = &__jove_callstack;
  uint64_t **const callstack_begin_ptr = &__jove_callstack_begin;

  uintptr_t *const pc_ptr =
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

  uintptr_t *const sp_ptr =
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

  uintptr_t *const ra_ptr =
#if defined(__mips64) || defined(__mips__)
      &uctx->uc_mcontext.gregs[31]
#elif defined(__aarch64__)
      &uctx->uc_mcontext.regs[30]
#else
      NULL
#endif
      ;

  uintptr_t *const emusp_ptr =
#if defined(__mips64) || defined(__mips__)
      &__jove_env.active_tc.gpr[29]
#elif defined(__x86_64__) || defined(__i386__)
      &__jove_env.regs[R_ESP]
#elif defined(__aarch64__)
      &__jove_env.xregs[31]
#else
#error
#endif
      ;

  uintptr_t *const t9_ptr =
#if defined(__mips64) || defined(__mips__)
      &uctx->uc_mcontext.gregs[25]
#else
      NULL
#endif
      ;

  uintptr_t *const emut9_ptr =
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

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES; ++BIdx) {
    if (BIdx == 1 ||
        BIdx == 2)
      continue; /* rtld or vdso */

    uintptr_t *fns = __jove_function_tables[BIdx];

    if (!fns)
      continue;

    for (unsigned FIdx = 0; fns[2 * FIdx]; ++FIdx) {
      const uintptr_t FuncSectPtr = fns[2 * FIdx + 0];
      const uintptr_t FuncPtr     = fns[2 * FIdx + 1];

      if (likely(saved_pc != FuncSectPtr))
        continue;

      if (unlikely(!FuncPtr))
        _UNREACHABLE("called recompiled function is not ABI");

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

#if 0
      if (SignalDelivery) {
        //
        // print number of signal and description of program counter
        //

        char s[4096 * 16];
        s[0] = '\0';

        _strcat(s, __LOG_BOLD_BLUE "[signal ");

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
          char maps[4096 * 8];
          const unsigned maps_n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
          maps[maps_n] = '\0';

          char buff[256];
          _description_of_address_for_maps(buff, saved_pc, maps, maps_n);
          if (_strlen(buff) != 0) {
            _strcat(s, " <");
            _strcat(s, buff);
            _strcat(s, ">");
          }
        }

        _strcat(s, "\n" __LOG_NORMAL_COLOR);

        _jove_sys_write(2 /* stderr */, s, _strlen(s));
      }
#endif

      //
      // setup emulated stack
      //
      {
        const uintptr_t newstack = _jove_alloc_stack();

        uintptr_t newsp =
            newstack + JOVE_STACK_SIZE - JOVE_PAGE_SIZE - 19 * sizeof(uintptr_t);

        if (SignalDelivery)
          newsp -= sizeof(__jove_env);

        {
          //
          // align the stack
          //
          const uintptr_t align_val = 15;
          const uintptr_t align_mask = ~align_val;

          newsp &= align_mask;
        }

#if defined(__x86_64__) || defined(__i386__)
        newsp -= sizeof(uintptr_t); /* account for return address on the stack */
#endif

        {
          uintptr_t *p = (uintptr_t *)newsp;

#if defined(__x86_64__) || defined(__i386__)
          *p++ = (uintptr_t)_jove_inverse_thunk;
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
            _memcpy(p, &__jove_env, sizeof(__jove_env));
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
      return;
    }
  }

  //
  // if we get here, it's a crash.
  //
  char maps[4096 * 8];
  const unsigned maps_n = _read_pseudo_file("/proc/self/maps", maps, sizeof(maps));
  maps[maps_n] = '\0';

  char s[4096 * 16];
  s[0] = '\0';

  _strcat(s, "*** crash (jove) *** [");
  {
    char buff[65];
    _uint_to_string(_jove_sys_gettid(), buff, 10);

    _strcat(s, buff);
  }
  _strcat(s, "]\n");

#define _FIELD(name, init)                                                     \
  do {                                                                         \
    _strcat(s, name " 0x");                                                    \
                                                                               \
    {                                                                          \
      char _buff[65];                                                          \
      _uint_to_string((uintptr_t)init, _buff, 0x10);                           \
                                                                               \
      _strcat(s, _buff);                                                       \
    }                                                                          \
    {                                                                          \
      char _buff[256];                                                         \
      _description_of_address_for_maps(_buff, (uintptr_t)(init), maps, maps_n);\
      if (_strlen(_buff) != 0) {                                               \
        _strcat(s, " <");                                                      \
        _strcat(s, _buff);                                                     \
        _strcat(s, ">");                                                       \
      }                                                                        \
    }                                                                          \
                                                                               \
    _strcat(s, "\n");                                                          \
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

  //
  // dump message for user
  //
  _robust_write(2 /* stderr */, s, _strlen(s));

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

      _strcat(buff, __LOG_BOLD_BLUE "calling __jove_dfsan_flush\n" __LOG_NORMAL_COLOR);

      _jove_sys_write(2 /* stderr */, buff, _strlen(buff));
    }

    dfsan_flush_ptr();
  }

  {
    char envs[4096 * 8];
    const unsigned envs_n = _read_pseudo_file("/proc/self/environ", envs, sizeof(envs));
    envs[envs_n] = '\0';

    if (_should_sleep_on_crash(envs, envs_n)) {
      {
        char buff[256];
        buff[0] = '\0';

        _strcat(buff, __LOG_BOLD_BLUE "sleeping...\n" __LOG_NORMAL_COLOR);

        _jove_sys_write(2 /* stderr */, buff, _strlen(buff));
      }

      for (;;) _jove_sleep();
    } else {
      _jove_sys_exit_group(0x77);
      __builtin_trap();
    }
  }

  __builtin_unreachable();
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

  if (SignalDelivery)
    _memcpy(&__jove_env, SavedState, sizeof(__jove_env));

  return res;
}

void __nodce(void **p) {
  *p++ = __jove_trace;
  *p++ = __jove_trace_begin;
  *p++ = __jove_callstack;
  *p++ = __jove_callstack_begin;
}

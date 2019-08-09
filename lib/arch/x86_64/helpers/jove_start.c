#define TARGET_X86_64 1

#include <stdbool.h>

#include <stdint.h>

#define Q_TAILQ_ENTRY(type, qual)                                       \
struct {                                                                \
        qual type *tqe_next;            /* next element */              \
        qual type *qual *tqe_prev;      /* address of previous next element */\
}

#define QTAILQ_ENTRY(type)       Q_TAILQ_ENTRY(struct type,)

typedef uint8_t flag;

typedef uint32_t float32;

typedef uint64_t float64;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

typedef struct float_status {
    signed char float_detect_tininess;
    signed char float_rounding_mode;
    uint8_t     float_exception_flags;
    signed char floatx80_rounding_precision;
    /* should denormalised results go to zero and set the inexact flag? */
    flag flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    flag flush_inputs_to_zero;
    flag default_nan_mode;
    flag snan_bit_is_one;
} float_status;

typedef struct MemTxAttrs {
    /* Bus masters which don't specify any attributes will get this
     * (via the MEMTXATTRS_UNSPECIFIED constant), so that we can
     * distinguish "all attributes deliberately clear" from
     * "didn't specify" if necessary.
     */
    unsigned int unspecified:1;
    /* ARM/AMBA: TrustZone Secure access
     * x86: System Management Mode access
     */
    unsigned int secure:1;
    /* Memory access is usermode (unprivileged) */
    unsigned int user:1;
    /* Requester ID (for MSI for example) */
    unsigned int requester_id:16;
} MemTxAttrs;

typedef uint64_t vaddr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr _vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_SINT_COUNT                         16

#define HV_STIMER_COUNT                       4

#define CPU_COMMON_TLB

#define CPU_COMMON                                                      \
    /* soft mmu support */                                              \
    CPU_COMMON_TLB

typedef uint64_t target_ulong;

enum {
    R_EAX = 0,
    R_ECX = 1,
    R_EDX = 2,
    R_EBX = 3,
    R_ESP = 4,
    R_EBP = 5,
    R_ESI = 6,
    R_EDI = 7,
    R_R8 = 8,
    R_R9 = 9,
    R_R10 = 10,
    R_R11 = 11,
    R_R12 = 12,
    R_R13 = 13,
    R_R14 = 14,
    R_R15 = 15,

    R_AL = 0,
    R_CL = 1,
    R_DL = 2,
    R_BL = 3,
    R_AH = 4,
    R_CH = 5,
    R_DH = 6,
    R_BH = 7,
};

#define MCE_BANKS_DEF   10

#define MSR_MTRRcap_VCNT                8

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MAX_RTIT_ADDRS                  8

typedef enum FeatureWord {
    FEAT_1_EDX,         /* CPUID[1].EDX */
    FEAT_1_ECX,         /* CPUID[1].ECX */
    FEAT_7_0_EBX,       /* CPUID[EAX=7,ECX=0].EBX */
    FEAT_7_0_ECX,       /* CPUID[EAX=7,ECX=0].ECX */
    FEAT_7_0_EDX,       /* CPUID[EAX=7,ECX=0].EDX */
    FEAT_8000_0001_EDX, /* CPUID[8000_0001].EDX */
    FEAT_8000_0001_ECX, /* CPUID[8000_0001].ECX */
    FEAT_8000_0007_EDX, /* CPUID[8000_0007].EDX */
    FEAT_8000_0008_EBX, /* CPUID[8000_0008].EBX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_KVM_HINTS,     /* CPUID[4000_0001].EDX */
    FEAT_HYPERV_EAX,    /* CPUID[4000_0003].EAX */
    FEAT_HYPERV_EBX,    /* CPUID[4000_0003].EBX */
    FEAT_HYPERV_EDX,    /* CPUID[4000_0003].EDX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_COMP_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_COMP_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEATURE_WORDS,
} FeatureWord;

typedef uint32_t FeatureWordArray[FEATURE_WORDS];

#define MMREG_UNION(n, bits)        \
    union n {                       \
        uint8_t  _b_##n[(bits)/8];  \
        uint16_t _w_##n[(bits)/16]; \
        uint32_t _l_##n[(bits)/32]; \
        uint64_t _q_##n[(bits)/64]; \
        float32  _s_##n[(bits)/32]; \
        float64  _d_##n[(bits)/64]; \
    }

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
} XMMReg;

typedef union {
    uint8_t _b[32];
    uint16_t _w[16];
    uint32_t _l[8];
    uint64_t _q[4];
} YMMReg;

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;

typedef MMREG_UNION(MMXReg, 64)  MMXReg;

typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

typedef struct BNDCSReg {
    uint64_t cfgu;
    uint64_t sts;
} BNDCSReg;

typedef union {
    floatx80 d __attribute__((aligned(16)));
    MMXReg mmx;
} FPReg;

#define CPU_NB_REGS64 16

#define CPU_NB_REGS CPU_NB_REGS64

#define MAX_FIXED_COUNTERS 3

#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)

#define NB_OPMASK_REGS 8

typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

typedef enum TPRAccess {
    TPR_ACCESS_READ,
    TPR_ACCESS_WRITE,
} TPRAccess;

typedef struct CPUX86State {
    /* standard registers */
    target_ulong regs[CPU_NB_REGS];
    target_ulong eip;
    target_ulong eflags; /* eflags register. During CPU emulation, CC
                        flags and DF are set to zero because they are
                        stored elsewhere */

    /* emulator internal eflags handling */
    target_ulong cc_dst;
    target_ulong cc_src;
    target_ulong cc_src2;
    uint32_t cc_op;
    int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
    uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
                        are known at translation time. */
    uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

    /* segments */
    SegmentCache segs[6]; /* selector values */
    SegmentCache ldt;
    SegmentCache tr;
    SegmentCache gdt; /* only base and limit are used */
    SegmentCache idt; /* only base and limit are used */

    target_ulong cr[5]; /* NOTE: cr1 is unused */
    int32_t a20_mask;

    BNDReg bnd_regs[4];
    BNDCSReg bndcs_regs;
    uint64_t msr_bndcfgs;
    uint64_t efer;

    /* Beginning of state preserved by INIT (dummy marker).  */
    struct {} start_init_save;

    /* FPU state */
    unsigned int fpstt; /* top of stack index */
    uint16_t fpus;
    uint16_t fpuc;
    uint8_t fptags[8];   /* 0 = valid, 1 = empty */
    FPReg fpregs[8];
    /* KVM-only so far */
    uint16_t fpop;
    uint64_t fpip;
    uint64_t fpdp;

    /* emulator internal variables */
    float_status fp_status;
    floatx80 ft0;

    float_status mmx_status; /* for 3DNow! float ops */
    float_status sse_status;
    uint32_t mxcsr;
    ZMMReg xmm_regs[CPU_NB_REGS == 8 ? 8 : 32];
    ZMMReg xmm_t0;
    MMXReg mmx_t0;

    XMMReg ymmh_regs[CPU_NB_REGS];

    uint64_t opmask_regs[NB_OPMASK_REGS];
    YMMReg zmmh_regs[CPU_NB_REGS];
    ZMMReg hi16_zmm_regs[CPU_NB_REGS];

    /* sysenter registers */
    uint32_t sysenter_cs;
    target_ulong sysenter_esp;
    target_ulong sysenter_eip;
    uint64_t star;

    uint64_t vm_hsave;

#ifdef TARGET_X86_64
    target_ulong lstar;
    target_ulong cstar;
    target_ulong fmask;
    target_ulong kernelgsbase;
#endif

    uint64_t tsc;
    uint64_t tsc_adjust;
    uint64_t tsc_deadline;
    uint64_t tsc_aux;

    uint64_t xcr0;

    uint64_t mcg_status;
    uint64_t msr_ia32_misc_enable;
    uint64_t msr_ia32_feature_control;

    uint64_t msr_fixed_ctr_ctrl;
    uint64_t msr_global_ctrl;
    uint64_t msr_global_status;
    uint64_t msr_global_ovf_ctrl;
    uint64_t msr_fixed_counters[MAX_FIXED_COUNTERS];
    uint64_t msr_gp_counters[MAX_GP_COUNTERS];
    uint64_t msr_gp_evtsel[MAX_GP_COUNTERS];

    uint64_t pat;
    uint32_t smbase;
    uint64_t msr_smi_count;

    uint32_t pkru;

    uint64_t spec_ctrl;

    /* End of state preserved by INIT (dummy marker).  */
    struct {} end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;

    /* Partition-wide HV MSRs, will be updated only on the first vcpu */
    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_tsc;

    /* Per-VCPU HV MSRs */
    uint64_t msr_hv_vapic;
    uint64_t msr_hv_crash_params[HV_CRASH_PARAMS];
    uint64_t msr_hv_runtime;
    uint64_t msr_hv_synic_control;
    uint64_t msr_hv_synic_evt_page;
    uint64_t msr_hv_synic_msg_page;
    uint64_t msr_hv_synic_sint[HV_SINT_COUNT];
    uint64_t msr_hv_stimer_config[HV_STIMER_COUNT];
    uint64_t msr_hv_stimer_count[HV_STIMER_COUNT];

    uint64_t msr_rtit_ctrl;
    uint64_t msr_rtit_status;
    uint64_t msr_rtit_output_base;
    uint64_t msr_rtit_output_mask;
    uint64_t msr_rtit_cr3_match;
    uint64_t msr_rtit_addrs[MAX_RTIT_ADDRS];

    /* exception/interrupt handling */
    int error_code;
    int exception_is_int;
    target_ulong exception_next_eip;
    target_ulong dr[8]; /* debug registers; note dr4 and dr5 are unused */
    union {
        struct CPUBreakpoint *cpu_breakpoint[4];
        struct CPUWatchpoint *cpu_watchpoint[4];
    }; /* break/watchpoints for dr[0..3] */
    int old_exception;  /* exception in flight */

    uint64_t vm_vmcb;
    uint64_t tsc_offset;
    uint64_t intercept;
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exceptions;
    uint8_t v_tpr;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    CPU_COMMON

    /* Fields after CPU_COMMON are preserved across CPU reset. */

    /* processor features (e.g. for CPUID insn) */
    /* Minimum level/xlevel/xlevel2, based on CPU model + features */
    uint32_t cpuid_min_level, cpuid_min_xlevel, cpuid_min_xlevel2;
    /* Maximum level/xlevel/xlevel2 value for auto-assignment: */
    uint32_t cpuid_max_level, cpuid_max_xlevel, cpuid_max_xlevel2;
    /* Actual level/xlevel/xlevel2 value: */
    uint32_t cpuid_level, cpuid_xlevel, cpuid_xlevel2;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
    FeatureWordArray features;
    /* Features that were explicitly enabled/disabled */
    FeatureWordArray user_features;
    uint32_t cpuid_model[12];

    /* MTRRs */
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[MSR_MTRRcap_VCNT];

    /* For KVM */
    uint32_t mp_state;
    int32_t exception_injected;
    int32_t interrupt_injected;
    uint8_t soft_interrupt;
    uint8_t has_error_code;
    uint32_t ins_len;
    uint32_t sipi_vector;
    bool tsc_valid;
    int64_t tsc_khz;
    int64_t user_tsc_khz; /* for sanity check only */
    void *kvm_xsave_buf;
#if defined(CONFIG_HVF)
    HVFX86EmulatorState *hvf_emul;
#endif

    uint64_t mcg_cap;
    uint64_t mcg_ctl;
    uint64_t mcg_ext_ctl;
    uint64_t mce_banks[MCE_BANKS_DEF*4];
    uint64_t xstate_bv;

    /* vmstate */
    uint16_t fpus_vmstate;
    uint16_t fptag_vmstate;
    uint16_t fpregs_format_vmstate;

    uint64_t xss;

    TPRAccess tpr_access_type;
} CPUX86State;

#include <stddef.h>

/* __thread */ struct CPUX86State __jove_env;
/* __thread */ char __jove_stack[0x100000];
/* __thread */ uint64_t *__jove_trace;

#define _JOVE_MAX_BINARIES 512

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
    [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

/* static */ uintptr_t *___jove_function_tables[3] = {NULL, NULL, NULL};

struct CPUX86State *jove_state(void) { return &__jove_env; }
char               *jove_stack(void) { return &__jove_stack[0]; }
uint64_t           *jove_trace(void) { return __jove_trace; }

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>

#define _CTOR  __attribute__((constructor))
#define _INL   __attribute__((always_inline))
#define _NAKED __attribute__((naked))
#define _NOINL __attribute__((noinline))
#define _NORET __attribute__((noreturn))

extern bool _jove_trace_enabled(void);
extern void _jove_call_entry(void);
extern uintptr_t *_jove_get_dynl_function_table(void);
extern uintptr_t *_jove_get_vdso_function_table(void);
extern _CTOR void _jove_install_function_table(void);

_NAKED void __jove_start(void);
void _jove_start(target_ulong, target_ulong, target_ulong, target_ulong,
                 target_ulong, target_ulong);

static _INL int _open(const char *, int, mode_t);
static _INL ssize_t _read(int, void *, size_t);
static _INL int _close(int);
static _INL ssize_t _write(int, const void *, size_t);
static _INL void _exit_group(int status);
static _INL int _ftruncate(int fd, off_t length);
static _INL void *_mmap(void *addr, size_t length, int prot, int flags, int fd,
                        off_t offset);
static _INL int _execve(char *pathname, char **argv, char **envp);

static _INL unsigned _read_pseudo_file(const char *path, char *out, size_t len);
static _INL uintptr_t _parse_stack_end_of_maps(char *maps, const unsigned n);
static _INL uintptr_t _parse_dynl_load_bias(char *maps, const unsigned n);
static _INL uintptr_t _parse_vdso_load_bias(char *maps, const unsigned n);
static _INL void *_memchr(const void *s, int c, size_t n);
static _INL void *_memcpy(void *dest, const void *src, size_t n);
static _INL char *__findenv(const char *name, int len, int *offset);
static _INL char *_getenv(const char *name);
static _INL uint64_t _u64ofhexstr(char *str_begin, char *str_end);
static _INL unsigned _getHexDigit(char cdigit);
static _INL uintptr_t _get_stack_end(void);

static _CTOR _NOINL void _jove_install_vdso_and_dynl_function_tables(void);

void _jove_trace_init(void);

_NAKED _NOINL unsigned long _jove_thunk(unsigned long,
                                        unsigned long *,
                                        unsigned long *);

_NAKED _NOINL _NORET void _jove_fail1(unsigned long);

_NOINL void _jove_recover_dyn_target(uint32_t CallerBIdx,
                                     uint32_t CallerBBIdx,
                                     uintptr_t CalleeAddr);

_NOINL void _jove_recover_basic_block(uint32_t IndBrBIdx,
                                      uint32_t IndBrBBIdx,
                                      uintptr_t SectsStartAddr,
                                      uintptr_t SectionsBeg,
                                      uintptr_t SectionsEnd,
                                      uintptr_t BBAddr);

void __jove_start(void) {
  asm volatile("movq %rsp, %r9\n"
               "jmp _jove_start\n");
}

static struct {
  int argc;
  char **argv;
  char **environ;
} _jove_startup_info;

void _jove_start(target_ulong rdi, target_ulong rsi, target_ulong rdx,
                 target_ulong rcx, target_ulong r8,
                 target_ulong sp_addr /* formerly r9 */) {
  __jove_env.regs[R_EDI] = rdi;
  __jove_env.regs[R_ESI] = rsi;
  __jove_env.regs[R_EDX] = rdx;
  __jove_env.regs[R_ECX] = rcx;
  __jove_env.regs[R_R8] = r8;
  __jove_env.df = 1;

  //
  // _jove_startup_info
  //
  {
    uintptr_t addr = sp_addr;

    _jove_startup_info.argc = *((long *)addr);

    addr += sizeof(long);

    _jove_startup_info.argv = (char **)addr;

    addr += _jove_startup_info.argc * sizeof(char *);
    addr += sizeof(char *);

    _jove_startup_info.environ = (char **)addr;
  }

  //
  // setup the stack
  //
  {
    unsigned len = _get_stack_end() - sp_addr;

    char *const env_stack_end_addr = &__jove_stack[sizeof(__jove_stack)];
    char *env_sp_addr = env_stack_end_addr - len;

    _memcpy(env_sp_addr, (void *)sp_addr, len);

    __jove_env.regs[R_ESP] = (target_ulong)env_sp_addr;
  }

  // trace init (if -trace was passed)
  if (_jove_trace_enabled())
    _jove_trace_init();

  _jove_install_function_table();
  _jove_install_vdso_and_dynl_function_tables();

  return _jove_call_entry();
}

char *__findenv(const char *name, int len, int *offset) {
  int i;
  const char *np;
  char **p, *cp;

  if (name == NULL || _jove_startup_info.environ == NULL)
    return (NULL);
  for (p = _jove_startup_info.environ + *offset; (cp = *p) != NULL; ++p) {
    for (np = name, i = len; i && *cp; i--)
      if (*cp++ != *np++)
        break;
    if (i == 0 && *cp++ == '=') {
      *offset = p - _jove_startup_info.environ;
      return (cp);
    }
  }
  return (NULL);
}

char *_getenv(const char *name) {
  int offset = 0;
  const char *np;

  for (np = name; *np && *np != '='; ++np)
    ;
  return (__findenv(name, (int)(np - name), &offset));
}

uintptr_t _get_stack_end(void) {
  char buff[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
  buff[n] = '\0';

  uintptr_t res = _parse_stack_end_of_maps(buff, n);
  return res;
}

void *_memchr(const void *s, int c, size_t n) {
  if (n != 0) {
    const unsigned char *p = s;

    do {
      if (*p++ == (unsigned char)c)
        return ((void *)(p - 1));
    } while (--n != 0);
  }
  return (NULL);
}

/// A utility function that converts a character to a digit.
unsigned _getHexDigit(char cdigit) {
  unsigned radix = 0x10;

  unsigned r;

  if (radix == 16 || radix == 36) {
    r = cdigit - '0';
    if (r <= 9)
      return r;

    r = cdigit - 'A';
    if (r <= radix - 11U)
      return r + 10;

    r = cdigit - 'a';
    if (r <= radix - 11U)
      return r + 10;

    radix = 10;
  }

  r = cdigit - '0';
  if (r < radix)
    return r;

  return -1U;
}

uint64_t _u64ofhexstr(char *str_begin, char *str_end) {
  const unsigned radix = 0x10;

  uint64_t res = 0;

  char *p = str_begin;
  size_t slen = str_end - str_begin;

  // Figure out if we can shift instead of multiply
  unsigned shift = (radix == 16 ? 4 : radix == 8 ? 3 : radix == 2 ? 1 : 0);

  // Enter digit traversal loop
  for (char *e = str_end; p != e; ++p) {
    unsigned digit = _getHexDigit(*p);

    if (!(digit < radix))
      return 0;

    // Shift or multiply the value by the radix
    if (slen > 1) {
      if (shift)
        res <<= shift;
      else
        res *= radix;
    }

    // Add in the digit we just interpreted
    res += digit;
  }

  return res;
}

uintptr_t _parse_stack_end_of_maps(char *maps, const unsigned n) {
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
        eol[-2] == 'k' &&
        eol[-3] == 'c' &&
        eol[-4] == 'a' &&
        eol[-5] == 't' &&
        eol[-6] == 's' &&
        eol[-7] == '[') {
      char *dash = _memchr(line, '-', left);

      char *space = _memchr(line, ' ', left);
      uint64_t max = _u64ofhexstr(dash + 1, space);
      return max;
    }
  }

  __builtin_trap();
  __builtin_unreachable();
}

int _open(const char *filename, int flags, mode_t mode) {
  long resultvar;

  mode_t       __arg3 = mode;
  int          __arg2 = flags;
  const char * __arg1 = filename;

  register mode_t       _a3 asm("rdx") = __arg3;
  register int          _a2 asm("rsi") = __arg2;
  register const char * _a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_open), "r"(_a1), "r"(_a2), "r"(_a3)
               : "memory", "cc", "r11", "cx");

  return resultvar;
}

ssize_t _read(int fd, void *buf, size_t count) {
  long resultvar;

  size_t __arg3 = count;
  void * __arg2 = buf;
  int    __arg1 = fd;

  register size_t _a3 asm("rdx") = __arg3;
  register void * _a2 asm("rsi") = __arg2;
  register int    _a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_read), "r"(_a1), "r"(_a2), "r"(_a3)
               : "memory", "cc", "r11", "cx");

  return resultvar;
}

int _close(int fd) {
  long resultvar;

  int __arg1 = fd;

  register int _a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_close), "r"(_a1)
               : "memory", "cc", "r11", "cx");

  return resultvar;
}

ssize_t _write(int fd, const void *buf, size_t count) {
  long resultvar;

  size_t       __arg3 = count;
  const void * __arg2 = buf;
  int          __arg1 = fd;

  register size_t       _a3 asm("rdx") = __arg3;
  register const void * _a2 asm("rsi") = __arg2;
  register int          _a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_write), "r"(_a1), "r"(_a2), "r"(_a3)
               : "memory", "cc", "r11", "cx");

  return resultvar;
}

void _exit_group(int status) {
  long resultvar;

  int __arg1 = status;

  register int _a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_exit_group), "r"(_a1)
               : "memory", "cc", "r11", "cx");

  __builtin_trap();
  __builtin_unreachable();
}

unsigned _read_pseudo_file(const char *path, char *out, size_t len) {
  unsigned n;

  {
    int fd = _open(path, O_RDONLY, S_IRWXU);
    if (fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    // let n denote the number of characters read
    n = 0;

    for (;;) {
      ssize_t ret = _read(fd, &out[n], len - n);

      if (ret == 0)
        break;

      if (ret < 0) {
        if (ret == -EINTR)
          continue;

        __builtin_trap();
        __builtin_unreachable();
      }

      n += ret;
    }

    if (_close(fd) < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }

  return n;
}

void *_memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = dest;
  const unsigned char *s = src;

  for (; n; n--)
    *d++ = *s++;

  return dest;
}

int _ftruncate(int fd, off_t length) {
  long resultvar;

  off_t __arg2 = length;
  int   __arg1 = fd;

  register off_t _a2 asm("rsi") = __arg2;
  register int   _a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_ftruncate), "r"(_a1), "r"(_a2)
               : "memory", "cc", "r11", "cx");

  return resultvar;
}

void *_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  long resultvar;

  off_t  __arg6 = offset;
  int    __arg5 = fd;
  int    __arg4 = flags;
  int    __arg3 = prot;
  size_t __arg2 = length;
  void * __arg1 = addr;

  register off_t  _a6 asm("r9")  = __arg6;
  register int    _a5 asm("r8")  = __arg5;
  register int    _a4 asm("r10") = __arg4;
  register int    _a3 asm("rdx") = __arg3;
  register size_t _a2 asm("rsi") = __arg2;
  register void * _a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_mmap), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4),
                 "r"(_a5), "r"(_a6)
               : "memory", "cc", "r11", "cx");

  return (void *)resultvar;
}

void _jove_trace_init(void) {
  if (__jove_trace)
    return;

  int fd = _open("trace.bin", O_RDWR | O_CREAT | O_TRUNC | O_SYNC, 0666);
  if (fd < 0) {
    __builtin_trap();

    return;
  }

  off_t size = 1UL << 31; /* 2 GiB */
  if (_ftruncate(fd, size) < 0) {
    __builtin_trap();

    _close(fd);
    return;
  }

  void *p = _mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (p == MAP_FAILED) {
    __builtin_trap();

    _close(fd);
    return;
  }

  __jove_trace = p;
}

int _execve(char *pathname, char **argv, char **envp) {
  long resultvar;

  char **__arg3 = envp;
  char **__arg2 = argv;
  char  *__arg1 = pathname;

  register char **_a3 asm("rdx") = __arg3;
  register char **_a2 asm("rsi") = __arg2;
  register char  *_a1 asm("rdi") = __arg1;

  asm volatile("syscall\n\t"
               : "=a"(resultvar)
               : "0"(__NR_execve), "r"(_a1), "r"(_a2), "r"(_a3)
               : "memory", "cc", "r11", "cx");

  return resultvar;
}

static char *ulongtostr(char *dst, unsigned long N) {
  char *Str = dst;

  const unsigned Radix = 10;

  // First, check for a zero value and just short circuit the logic below.
  if (N == 0) {
    *Str++ = '0';
    goto out;
  }

  static const char Digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

  char Buffer[65];
  char *const BufEnd = &Buffer[sizeof(Buffer)];

  char *BufPtr = BufEnd;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *Ptr = BufPtr; Ptr != BufEnd; ++Ptr)
    *Str++ = *Ptr;

out:
  *Str = '\0';
  return Str;
}

void _jove_recover_dyn_target(uint32_t CallerBIdx,
                              uint32_t CallerBBIdx,
                              uintptr_t CalleeAddr) {
  if (!_jove_startup_info.environ)
    return;

  char *jove_recover_path = _getenv("JOVE_RECOVER_PATH");
  if (!jove_recover_path)
    return;

  char *jv_path = _getenv("JOVE_DECOMPILATION_PATH");
  if (!jv_path)
    return;

  struct {
    uint32_t BIdx;
    uint32_t FIdx;
  } Callee;

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES ; ++BIdx) {
    uintptr_t *fns = __jove_function_tables[BIdx];
    if (!fns)
      continue;

    for (unsigned FIdx = 0; fns[FIdx]; ++FIdx) {
      if (CalleeAddr == fns[FIdx]) {
        Callee.BIdx = BIdx;
        Callee.FIdx = FIdx;

        goto found;
      }
    }
  }

  return; /* not found */

found:
  {
    char *argv0 = jove_recover_path;
    char  argv1[] = "-d";
    char *argv2 = jv_path;
    char  argv3[256];

    {
      char *p = &argv3[0];

      *p++ = '-';
      *p++ = 'd';
      *p++ = 'y';
      *p++ = 'n';
      *p++ = '-';
      *p++ = 't';
      *p++ = 'a';
      *p++ = 'r';
      *p++ = 'g';
      *p++ = 'e';
      *p++ = 't';
      *p++ = '=';

      p = ulongtostr(p, CallerBIdx);
      *p++ = ',';
      p = ulongtostr(p, CallerBBIdx);
      *p++ = ',';
      p = ulongtostr(p, Callee.BIdx);
      *p++ = ',';
      p = ulongtostr(p, Callee.FIdx);
    }

    char *argv[] = {argv0, argv1, argv2, argv3, NULL};

    _execve(argv0, argv, _jove_startup_info.environ);
  }
}

void _jove_recover_basic_block(uint32_t IndBrBIdx,
                               uint32_t IndBrBBIdx,
                               uintptr_t SectsStartAddr,
                               uintptr_t SectionsBeg,
                               uintptr_t SectionsEnd,
                               uintptr_t BBAddr) {
  if (!_jove_startup_info.environ)
    return;

  char *jove_recover_path = _getenv("JOVE_RECOVER_PATH");
  if (!jove_recover_path)
    return;

  char *jv_path = _getenv("JOVE_DECOMPILATION_PATH");
  if (!jv_path)
    return;

  if (!(BBAddr >= SectionsBeg && BBAddr < SectionsEnd))
    return;

  uintptr_t FileAddr = (BBAddr - SectionsBeg) + SectsStartAddr;

  {
    char *argv0 = jove_recover_path;
    char  argv1[] = "-d";
    char *argv2 = jv_path;
    char  argv3[256];

    {
      char *p = &argv3[0];

      *p++ = '-';
      *p++ = 'b';
      *p++ = 'a';
      *p++ = 's';
      *p++ = 'i';
      *p++ = 'c';
      *p++ = '-';
      *p++ = 'b';
      *p++ = 'l';
      *p++ = 'o';
      *p++ = 'c';
      *p++ = 'k';
      *p++ = '=';

      p = ulongtostr(p, IndBrBIdx);
      *p++ = ',';
      p = ulongtostr(p, IndBrBBIdx);
      *p++ = ',';
      p = ulongtostr(p, FileAddr);
    }

    char *argv[] = {argv0, argv1, argv2, argv3, NULL};

    _execve(argv0, argv, _jove_startup_info.environ);
  }
}

void _jove_fail1(unsigned long x) {
  asm volatile("int3\n"
               "hlt");
}

unsigned long _jove_thunk(unsigned long dstpc   /* rdi */,
                          unsigned long *args   /* rsi */,
                          unsigned long *emuspp /* rdx */) {
  asm volatile("pushq %r15\n" /* callee-saved registers */
               "pushq %r14\n"

               "movq %rdx, %r14\n" /* emuspp in r14 */
               "movq %rsp, %r15\n" /* put old sp in r15 */

               "movq (%rdx), %rsp\n" /* make emusp be the sp */

               "movq %rdi, %r10\n" /* put dstpc in temporary register */

               /* unpack args */
               "movq 40(%rsi), %r9\n"
               "movq 32(%rsi), %r8\n"
               "movq 24(%rsi), %rcx\n"
               "movq 16(%rsi), %rdx\n"
               "movq  0(%rsi), %rdi\n"
               "movq  8(%rsi), %rsi\n"

               "addq $8, %rsp\n" /* replace return address on the stack */
               "callq *%r10\n" /* call dstpc */

               "movq %rsp, (%r14)\n" /* store modified emusp */
               "movq %r15, %rsp\n" /* restore stack pointer */

               "popq %r14\n"
               "popq %r15\n" /* callee-saved registers */
               "ret");
}

uintptr_t _parse_dynl_load_bias(char *maps, const unsigned n) {
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
    if (eol[-1]  == 'o' &&
        eol[-2]  == 's' &&
        eol[-3]  == '.' &&
        eol[-4]  == '9' &&
        eol[-5]  == '2' &&
        eol[-6]  == '.' &&
        eol[-7]  == '2' &&
        eol[-8]  == '-' &&
        eol[-9]  == 'd' &&
        eol[-10] == 'l' &&
        eol[-11] == '/' &&
        eol[-12] == 'b' &&
        eol[-13] == 'i' &&
        eol[-14] == 'l' &&
        eol[-15] == '/' &&
        eol[-16] == 'r' &&
        eol[-17] == 's' &&
        eol[-18] == 'u' &&
        eol[-19] == '/') {
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

  __builtin_trap();
  __builtin_unreachable();
}

uintptr_t _parse_vdso_load_bias(char *maps, const unsigned n) {
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

  __builtin_trap();
  __builtin_unreachable();
}

void _jove_install_vdso_and_dynl_function_tables(void) {
  static bool _installed = false;
  if (_installed)
    return;
  _installed = true;

  /* we need to get the load addresses for the dynamic linker and VDSO by
   * parsing /proc/self/maps */
  uintptr_t dynl_load_bias;
  uintptr_t vdso_load_bias;
  {
    char buff[4096 * 16];
    unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
    buff[n] = '\0';

    dynl_load_bias = _parse_dynl_load_bias(buff, n);
    vdso_load_bias = _parse_vdso_load_bias(buff, n);
  }

  uintptr_t *dynl_fn_tbl = _jove_get_dynl_function_table();
  uintptr_t *vdso_fn_tbl = _jove_get_vdso_function_table();

  for (uintptr_t *p = dynl_fn_tbl; *p; ++p)
    *p += dynl_load_bias;
  for (uintptr_t *p = vdso_fn_tbl; *p; ++p)
    *p += vdso_load_bias;

  /* __jove_function_tables[1] is the dynamic linker. */
  ___jove_function_tables[1] = dynl_fn_tbl;
  /* __jove_function_tables[2] is the VDSO. */
  ___jove_function_tables[2] = vdso_fn_tbl;
}

#define TARGET_AARCH64 1

#define CONFIG_USER_ONLY 1

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

typedef uint8_t flag;

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
    /* not always used -- see snan_bit_is_one() in softfloat-specialize.h */
    flag snan_bit_is_one;
} float_status;

#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

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
    /* Invert endianness for this page */
    unsigned int byte_swap:1;
    /*
     * The following are target-specific page-table bits.  These are not
     * related to actual memory transactions at all.  However, this structure
     * is part of the tlb_fill interface, cached in the cputlb structure,
     * and has unused bits.  These fields will be read by target-specific
     * helpers using env->iotlb[mmu_idx][tlb_index()].attrs.target_tlb_bitN.
     */
    unsigned int target_tlb_bit0 : 1;
    unsigned int target_tlb_bit1 : 1;
    unsigned int target_tlb_bit2 : 1;
} MemTxAttrs;

typedef uint64_t vaddr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

struct arm_boot_info;

enum {
    M_REG_NS = 0,
    M_REG_S = 1,
    M_REG_NUM_BANKS = 2,
};

#define NUM_GTIMERS 4

typedef struct ARMGenericTimer {
    uint64_t cval; /* Timer CompareValue register */
    uint64_t ctl; /* Timer Control register */
} ARMGenericTimer;

# define ARM_MAX_VQ    16

typedef struct {
    uint64_t raw_tcr;
    uint32_t mask;
    uint32_t base_mask;
} TCR;

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

typedef struct ARMPACKey {
    uint64_t lo, hi;
} ARMPACKey;

typedef struct CPUARMState {
    /* Regs for current mode.  */
    uint32_t regs[16];

    /* 32/64 switch only happens when taking and returning from
     * exceptions so the overlap semantics are taken care of then
     * instead of having a complicated union.
     */
    /* Regs for A64 mode.  */
    uint64_t xregs[32];
    uint64_t pc;
    /* PSTATE isn't an architectural register for ARMv8. However, it is
     * convenient for us to assemble the underlying state into a 32 bit format
     * identical to the architectural format used for the SPSR. (This is also
     * what the Linux kernel's 'pstate' field in signal handlers and KVM's
     * 'pstate' register are.) Of the PSTATE bits:
     *  NZCV are kept in the split out env->CF/VF/NF/ZF, (which have the same
     *    semantics as for AArch32, as described in the comments on each field)
     *  nRW (also known as M[4]) is kept, inverted, in env->aarch64
     *  DAIF (exception masks) are kept in env->daif
     *  BTYPE is kept in env->btype
     *  all other bits are stored in their correct places in env->pstate
     */
    uint32_t pstate;
    uint32_t aarch64; /* 1 if CPU is in aarch64 state; inverse of PSTATE.nRW */

    /* Cached TBFLAGS state.  See below for which bits are included.  */
    uint32_t hflags;

    /* Frequently accessed CPSR bits are stored separately for efficiency.
       This contains all the other bits.  Use cpsr_{read,write} to access
       the whole CPSR.  */
    uint32_t uncached_cpsr;
    uint32_t spsr;

    /* Banked registers.  */
    uint64_t banked_spsr[8];
    uint32_t banked_r13[8];
    uint32_t banked_r14[8];

    /* These hold r8-r12.  */
    uint32_t usr_regs[5];
    uint32_t fiq_regs[5];

    /* cpsr flag cache for faster execution */
    uint32_t CF; /* 0 or 1 */
    uint32_t VF; /* V is the bit 31. All other bits are undefined */
    uint32_t NF; /* N is bit 31. All other bits are undefined.  */
    uint32_t ZF; /* Z set if zero.  */
    uint32_t QF; /* 0 or 1 */
    uint32_t GE; /* cpsr[19:16] */
    uint32_t thumb; /* cpsr[5]. 0 = arm mode, 1 = thumb mode. */
    uint32_t condexec_bits; /* IT bits.  cpsr[15:10,26:25].  */
    uint32_t btype;  /* BTI branch type.  spsr[11:10].  */
    uint64_t daif; /* exception masks, in the bits they are in PSTATE */

    uint64_t elr_el[4]; /* AArch64 exception link regs  */
    uint64_t sp_el[4]; /* AArch64 banked stack pointers */

    /* System control coprocessor (cp15) */
    struct {
        uint32_t c0_cpuid;
        union { /* Cache size selection */
            struct {
                uint64_t _unused_csselr0;
                uint64_t csselr_ns;
                uint64_t _unused_csselr1;
                uint64_t csselr_s;
            };
            uint64_t csselr_el[4];
        };
        union { /* System control register. */
            struct {
                uint64_t _unused_sctlr;
                uint64_t sctlr_ns;
                uint64_t hsctlr;
                uint64_t sctlr_s;
            };
            uint64_t sctlr_el[4];
        };
        uint64_t cpacr_el1; /* Architectural feature access control register */
        uint64_t cptr_el[4];  /* ARMv8 feature trap registers */
        uint32_t c1_xscaleauxcr; /* XScale auxiliary control register.  */
        uint64_t sder; /* Secure debug enable register. */
        uint32_t nsacr; /* Non-secure access control register. */
        union { /* MMU translation table base 0. */
            struct {
                uint64_t _unused_ttbr0_0;
                uint64_t ttbr0_ns;
                uint64_t _unused_ttbr0_1;
                uint64_t ttbr0_s;
            };
            uint64_t ttbr0_el[4];
        };
        union { /* MMU translation table base 1. */
            struct {
                uint64_t _unused_ttbr1_0;
                uint64_t ttbr1_ns;
                uint64_t _unused_ttbr1_1;
                uint64_t ttbr1_s;
            };
            uint64_t ttbr1_el[4];
        };
        uint64_t vttbr_el2; /* Virtualization Translation Table Base.  */
        /* MMU translation table base control. */
        TCR tcr_el[4];
        TCR vtcr_el2; /* Virtualization Translation Control.  */
        uint32_t c2_data; /* MPU data cacheable bits.  */
        uint32_t c2_insn; /* MPU instruction cacheable bits.  */
        union { /* MMU domain access control register
                 * MPU write buffer control.
                 */
            struct {
                uint64_t dacr_ns;
                uint64_t dacr_s;
            };
            struct {
                uint64_t dacr32_el2;
            };
        };
        uint32_t pmsav5_data_ap; /* PMSAv5 MPU data access permissions */
        uint32_t pmsav5_insn_ap; /* PMSAv5 MPU insn access permissions */
        uint64_t hcr_el2; /* Hypervisor configuration register */
        uint64_t scr_el3; /* Secure configuration register.  */
        union { /* Fault status registers.  */
            struct {
                uint64_t ifsr_ns;
                uint64_t ifsr_s;
            };
            struct {
                uint64_t ifsr32_el2;
            };
        };
        union {
            struct {
                uint64_t _unused_dfsr;
                uint64_t dfsr_ns;
                uint64_t hsr;
                uint64_t dfsr_s;
            };
            uint64_t esr_el[4];
        };
        uint32_t c6_region[8]; /* MPU base/size registers.  */
        union { /* Fault address registers. */
            struct {
                uint64_t _unused_far0;
#ifdef HOST_WORDS_BIGENDIAN
                uint32_t ifar_ns;
                uint32_t dfar_ns;
                uint32_t ifar_s;
                uint32_t dfar_s;
#else
                uint32_t dfar_ns;
                uint32_t ifar_ns;
                uint32_t dfar_s;
                uint32_t ifar_s;
#endif
                uint64_t _unused_far3;
            };
            uint64_t far_el[4];
        };
        uint64_t hpfar_el2;
        uint64_t hstr_el2;
        union { /* Translation result. */
            struct {
                uint64_t _unused_par_0;
                uint64_t par_ns;
                uint64_t _unused_par_1;
                uint64_t par_s;
            };
            uint64_t par_el[4];
        };

        uint32_t c9_insn; /* Cache lockdown registers.  */
        uint32_t c9_data;
        uint64_t c9_pmcr; /* performance monitor control register */
        uint64_t c9_pmcnten; /* perf monitor counter enables */
        uint64_t c9_pmovsr; /* perf monitor overflow status */
        uint64_t c9_pmuserenr; /* perf monitor user enable */
        uint64_t c9_pmselr; /* perf monitor counter selection register */
        uint64_t c9_pminten; /* perf monitor interrupt enables */
        union { /* Memory attribute redirection */
            struct {
#ifdef HOST_WORDS_BIGENDIAN
                uint64_t _unused_mair_0;
                uint32_t mair1_ns;
                uint32_t mair0_ns;
                uint64_t _unused_mair_1;
                uint32_t mair1_s;
                uint32_t mair0_s;
#else
                uint64_t _unused_mair_0;
                uint32_t mair0_ns;
                uint32_t mair1_ns;
                uint64_t _unused_mair_1;
                uint32_t mair0_s;
                uint32_t mair1_s;
#endif
            };
            uint64_t mair_el[4];
        };
        union { /* vector base address register */
            struct {
                uint64_t _unused_vbar;
                uint64_t vbar_ns;
                uint64_t hvbar;
                uint64_t vbar_s;
            };
            uint64_t vbar_el[4];
        };
        uint32_t mvbar; /* (monitor) vector base address register */
        struct { /* FCSE PID. */
            uint32_t fcseidr_ns;
            uint32_t fcseidr_s;
        };
        union { /* Context ID. */
            struct {
                uint64_t _unused_contextidr_0;
                uint64_t contextidr_ns;
                uint64_t _unused_contextidr_1;
                uint64_t contextidr_s;
            };
            uint64_t contextidr_el[4];
        };
        union { /* User RW Thread register. */
            struct {
                uint64_t tpidrurw_ns;
                uint64_t tpidrprw_ns;
                uint64_t htpidr;
                uint64_t _tpidr_el3;
            };
            uint64_t tpidr_el[4];
        };
        /* The secure banks of these registers don't map anywhere */
        uint64_t tpidrurw_s;
        uint64_t tpidrprw_s;
        uint64_t tpidruro_s;

        union { /* User RO Thread register. */
            uint64_t tpidruro_ns;
            uint64_t tpidrro_el[1];
        };
        uint64_t c14_cntfrq; /* Counter Frequency register */
        uint64_t c14_cntkctl; /* Timer Control register */
        uint32_t cnthctl_el2; /* Counter/Timer Hyp Control register */
        uint64_t cntvoff_el2; /* Counter Virtual Offset register */
        ARMGenericTimer c14_timer[NUM_GTIMERS];
        uint32_t c15_cpar; /* XScale Coprocessor Access Register */
        uint32_t c15_ticonfig; /* TI925T configuration byte.  */
        uint32_t c15_i_max; /* Maximum D-cache dirty line index.  */
        uint32_t c15_i_min; /* Minimum D-cache dirty line index.  */
        uint32_t c15_threadid; /* TI debugger thread-ID.  */
        uint32_t c15_config_base_address; /* SCU base address.  */
        uint32_t c15_diagnostic; /* diagnostic register */
        uint32_t c15_power_diagnostic;
        uint32_t c15_power_control; /* power control */
        uint64_t dbgbvr[16]; /* breakpoint value registers */
        uint64_t dbgbcr[16]; /* breakpoint control registers */
        uint64_t dbgwvr[16]; /* watchpoint value registers */
        uint64_t dbgwcr[16]; /* watchpoint control registers */
        uint64_t mdscr_el1;
        uint64_t oslsr_el1; /* OS Lock Status */
        uint64_t mdcr_el2;
        uint64_t mdcr_el3;
        /* Stores the architectural value of the counter *the last time it was
         * updated* by pmccntr_op_start. Accesses should always be surrounded
         * by pmccntr_op_start/pmccntr_op_finish to guarantee the latest
         * architecturally-correct value is being read/set.
         */
        uint64_t c15_ccnt;
        /* Stores the delta between the architectural value and the underlying
         * cycle count during normal operation. It is used to update c15_ccnt
         * to be the correct architectural value before accesses. During
         * accesses, c15_ccnt_delta contains the underlying count being used
         * for the access, after which it reverts to the delta value in
         * pmccntr_op_finish.
         */
        uint64_t c15_ccnt_delta;
        uint64_t c14_pmevcntr[31];
        uint64_t c14_pmevcntr_delta[31];
        uint64_t c14_pmevtyper[31];
        uint64_t pmccfiltr_el0; /* Performance Monitor Filter Register */
        uint64_t vpidr_el2; /* Virtualization Processor ID Register */
        uint64_t vmpidr_el2; /* Virtualization Multiprocessor ID Register */
    } cp15;

    struct {
        /* M profile has up to 4 stack pointers:
         * a Main Stack Pointer and a Process Stack Pointer for each
         * of the Secure and Non-Secure states. (If the CPU doesn't support
         * the security extension then it has only two SPs.)
         * In QEMU we always store the currently active SP in regs[13],
         * and the non-active SP for the current security state in
         * v7m.other_sp. The stack pointers for the inactive security state
         * are stored in other_ss_msp and other_ss_psp.
         * switch_v7m_security_state() is responsible for rearranging them
         * when we change security state.
         */
        uint32_t other_sp;
        uint32_t other_ss_msp;
        uint32_t other_ss_psp;
        uint32_t vecbase[M_REG_NUM_BANKS];
        uint32_t basepri[M_REG_NUM_BANKS];
        uint32_t control[M_REG_NUM_BANKS];
        uint32_t ccr[M_REG_NUM_BANKS]; /* Configuration and Control */
        uint32_t cfsr[M_REG_NUM_BANKS]; /* Configurable Fault Status */
        uint32_t hfsr; /* HardFault Status */
        uint32_t dfsr; /* Debug Fault Status Register */
        uint32_t sfsr; /* Secure Fault Status Register */
        uint32_t mmfar[M_REG_NUM_BANKS]; /* MemManage Fault Address */
        uint32_t bfar; /* BusFault Address */
        uint32_t sfar; /* Secure Fault Address Register */
        unsigned mpu_ctrl[M_REG_NUM_BANKS]; /* MPU_CTRL */
        int exception;
        uint32_t primask[M_REG_NUM_BANKS];
        uint32_t faultmask[M_REG_NUM_BANKS];
        uint32_t aircr; /* only holds r/w state if security extn implemented */
        uint32_t secure; /* Is CPU in Secure state? (not guest visible) */
        uint32_t csselr[M_REG_NUM_BANKS];
        uint32_t scr[M_REG_NUM_BANKS];
        uint32_t msplim[M_REG_NUM_BANKS];
        uint32_t psplim[M_REG_NUM_BANKS];
        uint32_t fpcar[M_REG_NUM_BANKS];
        uint32_t fpccr[M_REG_NUM_BANKS];
        uint32_t fpdscr[M_REG_NUM_BANKS];
        uint32_t cpacr[M_REG_NUM_BANKS];
        uint32_t nsacr;
    } v7m;

    /* Information associated with an exception about to be taken:
     * code which raises an exception must set cs->exception_index and
     * the relevant parts of this structure; the cpu_do_interrupt function
     * will then set the guest-visible registers as part of the exception
     * entry process.
     */
    struct {
        uint32_t syndrome; /* AArch64 format syndrome register */
        uint32_t fsr; /* AArch32 format fault status register info */
        uint64_t vaddress; /* virtual addr associated with exception, if any */
        uint32_t target_el; /* EL the exception should be targeted for */
        /* If we implement EL2 we will also need to store information
         * about the intermediate physical address for stage 2 faults.
         */
    } exception;

    /* Information associated with an SError */
    struct {
        uint8_t pending;
        uint8_t has_esr;
        uint64_t esr;
    } serror;

    /* State of our input IRQ/FIQ/VIRQ/VFIQ lines */
    uint32_t irq_line_state;

    /* Thumb-2 EE state.  */
    uint32_t teecr;
    uint32_t teehbr;

    /* VFP coprocessor state.  */
    struct {
        ARMVectorReg zregs[32];

#ifdef TARGET_AARCH64
        /* Store FFR as pregs[16] to make it easier to treat as any other.  */
#define FFR_PRED_NUM 16
        ARMPredicateReg pregs[17];
        /* Scratch space for aa64 sve predicate temporary.  */
        ARMPredicateReg preg_tmp;
#endif

        /* We store these fpcsr fields separately for convenience.  */
        uint32_t qc[4] QEMU_ALIGNED(16);
        int vec_len;
        int vec_stride;

        uint32_t xregs[16];

        /* Scratch space for aa32 neon expansion.  */
        uint32_t scratch[8];

        /* There are a number of distinct float control structures:
         *
         *  fp_status: is the "normal" fp status.
         *  fp_status_fp16: used for half-precision calculations
         *  standard_fp_status : the ARM "Standard FPSCR Value"
         *
         * Half-precision operations are governed by a separate
         * flush-to-zero control bit in FPSCR:FZ16. We pass a separate
         * status structure to control this.
         *
         * The "Standard FPSCR", ie default-NaN, flush-to-zero,
         * round-to-nearest and is used by any operations (generally
         * Neon) which the architecture defines as controlled by the
         * standard FPSCR value rather than the FPSCR.
         *
         * To avoid having to transfer exception bits around, we simply
         * say that the FPSCR cumulative exception flags are the logical
         * OR of the flags in the three fp statuses. This relies on the
         * only thing which needs to read the exception flags being
         * an explicit FPSCR read.
         */
        float_status fp_status;
        float_status fp_status_f16;
        float_status standard_fp_status;

        /* ZCR_EL[1-3] */
        uint64_t zcr_el[4];
    } vfp;
    uint64_t exclusive_addr;
    uint64_t exclusive_val;
    uint64_t exclusive_high;

    /* iwMMXt coprocessor state.  */
    struct {
        uint64_t regs[16];
        uint64_t val;

        uint32_t cregs[16];
    } iwmmxt;

#ifdef TARGET_AARCH64
    struct {
        ARMPACKey apia;
        ARMPACKey apib;
        ARMPACKey apda;
        ARMPACKey apdb;
        ARMPACKey apga;
    } keys;
#endif

#if defined(CONFIG_USER_ONLY)
    /* For usermode syscall translation.  */
    int eabi;
#endif

    struct CPUBreakpoint *cpu_breakpoint[16];
    struct CPUWatchpoint *cpu_watchpoint[16];

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    /* Fields after this point are preserved across CPU reset. */

    /* Internal CPU feature flags.  */
    uint64_t features;

    /* PMSAv7 MPU */
    struct {
        uint32_t *drbar;
        uint32_t *drsr;
        uint32_t *dracr;
        uint32_t rnr[M_REG_NUM_BANKS];
    } pmsav7;

    /* PMSAv8 MPU */
    struct {
        /* The PMSAv8 implementation also shares some PMSAv7 config
         * and state:
         *  pmsav7.rnr (region number register)
         *  pmsav7_dregion (number of configured regions)
         */
        uint32_t *rbar[M_REG_NUM_BANKS];
        uint32_t *rlar[M_REG_NUM_BANKS];
        uint32_t mair0[M_REG_NUM_BANKS];
        uint32_t mair1[M_REG_NUM_BANKS];
    } pmsav8;

    /* v8M SAU */
    struct {
        uint32_t *rbar;
        uint32_t *rlar;
        uint32_t rnr;
        uint32_t ctrl;
    } sau;

    void *nvic;
    const struct arm_boot_info *boot_info;
    /* Store GICv3CPUState to access from this struct */
    void *gicv3state;
} CPUARMState;

typedef uint64_t target_ulong;

#include <stddef.h>

extern /* __thread */ struct CPUARMState __jove_env;

extern /* __thread */ uint64_t *__jove_trace;
extern /* __thread */ uint64_t *__jove_trace_begin;

extern int    __jove_startup_info_argc;
extern char **__jove_startup_info_argv;
extern char **__jove_startup_info_environ;

#define _JOVE_MAX_BINARIES 512
extern uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES];

/* -> static */ uintptr_t *__jove_foreign_function_tables[3] = {NULL, NULL, NULL};

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <signal.h>

typedef unsigned long kernel_sigset_t;

struct kernel_sigaction {
  void *          _sa_handler;
  unsigned long   _sa_flags;
  void *          _sa_restorer;
  kernel_sigset_t _sa_mask;
};

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define _IOV_ENTRY(var) {.iov_base = &var, .iov_len = sizeof(var)}

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define _CTOR   __attribute__((constructor))
#define _INL    __attribute__((always_inline))
#define _NAKED  __attribute__((naked))
#define _NOINL  __attribute__((noinline))
#define _NORET  __attribute__((noreturn))
#define _UNUSED __attribute__((unused))
#define _HIDDEN __attribute__((visibility("hidden")))

#define JOVE_SYS_ATTR _INL _UNUSED
#include "jove_sys.h"

extern /* -> static */ uintptr_t _jove_sections_start_file_addr(void);
extern /* -> static */ uintptr_t _jove_sections_global_beg_addr(void);
extern /* -> static */ uintptr_t _jove_sections_global_end_addr(void);
extern /* -> static */ uint32_t _jove_binary_index(void);
extern /* -> static */ bool _jove_trace_enabled(void);
extern /* -> static */ void _jove_call_entry(void);
extern /* -> static */ uintptr_t *_jove_get_function_table(void);
extern /* -> static */ uintptr_t *_jove_get_dynl_function_table(void);
extern /* -> static */ uintptr_t *_jove_get_vdso_function_table(void);

_CTOR static void _jove_install_function_table(void) {
  __jove_function_tables[_jove_binary_index()] = _jove_get_function_table();
}

_CTOR static void _jove_install_foreign_function_tables(void);

_HIDDEN
_NAKED void _jove_start(void);
_HIDDEN void _jove_begin(target_ulong x0,
                         target_ulong x1,
                         target_ulong x2,
                         target_ulong x3,
                         target_ulong x4,
                         target_ulong x5,
                         target_ulong x6,
                         target_ulong sp_addr /* formerly x7 */);

_NAKED _NOINL target_ulong _jove_thunk(target_ulong dstpc,
                                       target_ulong *args,
                                       target_ulong *emuspp);

_NOINL void _jove_recover_dyn_target(uint32_t CallerBBIdx,
                                     target_ulong CalleeAddr);

_NOINL void _jove_recover_basic_block(uint32_t IndBrBBIdx,
                                      target_ulong BBAddr);

_HIDDEN _NOINL _NORET void _jove_fail1(target_ulong);
_HIDDEN _NOINL _NORET void _jove_fail2(target_ulong, target_ulong);

_NOINL void _jove_check_return_address(target_ulong RetAddr,
                                       target_ulong NativeRetAddr);

#define JOVE_PAGE_SIZE 4096
#define JOVE_STACK_SIZE (256 * JOVE_PAGE_SIZE)

_HIDDEN target_ulong _jove_alloc_stack(void);
_HIDDEN void _jove_free_stack(target_ulong);

//
// utility functions
//
static _INL unsigned _read_pseudo_file(const char *path, char *out, size_t len);
static _INL uintptr_t _parse_stack_end_of_maps(char *maps, const unsigned n);
static _INL uintptr_t _parse_dynl_load_bias(char *maps, const unsigned n);
static _INL uintptr_t _parse_vdso_load_bias(char *maps, const unsigned n);
static _INL size_t _sum_iovec_lengths(const struct iovec *, unsigned n);
static _INL bool _isDigit(char);
static _INL int _atoi(const char *s);
static _INL size_t _strlen(const char *s);
static _INL unsigned _getDigit(char cdigit, uint8_t radix);
static _INL void *_memchr(const void *s, int c, size_t n);
static _INL void *_memcpy(void *dest, const void *src, size_t n);
static _INL void *_memset(void *dst, int c, size_t n);
static _INL char *_findenv(const char *name, int len, int *offset);
static _INL char *_getenv(const char *name);
static _INL uint64_t _u64ofhexstr(char *str_begin, char *str_end);
static _INL unsigned _getHexDigit(char cdigit);
static _INL uintptr_t _get_stack_end(void);

//
// definitions
//

void _jove_start(void) {
  asm volatile(/* Create an initial frame with 0 LR and FP */
               "mov x29, #0\n"
               "mov x30, #0\n"

               "mov x7, sp\n"
               "b _jove_begin\n");
}

static void _jove_trace_init(void);

void _jove_begin(target_ulong x0,
                 target_ulong x1,
                 target_ulong x2,
                 target_ulong x3,
                 target_ulong x4,
                 target_ulong x5,
                 target_ulong x6,
                 target_ulong sp_addr /* formerly x7 */) {
  __jove_env.xregs[0] = x0;
  __jove_env.xregs[1] = x1;
  __jove_env.xregs[2] = x2;
  __jove_env.xregs[3] = x3;
  __jove_env.xregs[4] = x4;
  __jove_env.xregs[5] = x5;
  __jove_env.xregs[6] = x6;

  //
  // _jove_startup_info
  //
  {
    uintptr_t addr = sp_addr;

    __jove_startup_info_argc = *((long *)addr);

    addr += sizeof(long);

    __jove_startup_info_argv = (char **)addr;

    addr += __jove_startup_info_argc * sizeof(char *);
    addr += sizeof(char *);

    __jove_startup_info_environ = (char **)addr;
  }

  //
  // setup the stack
  //
  {
    unsigned len = _get_stack_end() - sp_addr;

    unsigned long env_stack_beg = _jove_alloc_stack();
    unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

    char *env_sp = (char *)(env_stack_end - JOVE_PAGE_SIZE - len);

    _memcpy(env_sp, (void *)sp_addr, len);

    __jove_env.xregs[31] = (target_ulong)env_sp;
  }

  // trace init (if -trace was passed)
  if (_jove_trace_enabled())
    _jove_trace_init();

  _jove_install_function_table();
  _jove_install_foreign_function_tables();

  return _jove_call_entry();
}

char *_findenv(const char *name, int len, int *offset) {
  int i;
  const char *np;
  char **p, *cp;

  if (name == NULL || __jove_startup_info_environ == NULL)
    return (NULL);
  for (p = __jove_startup_info_environ + *offset; (cp = *p) != NULL; ++p) {
    for (np = name, i = len; i && *cp; i--)
      if (*cp++ != *np++)
        break;
    if (i == 0 && *cp++ == '=') {
      *offset = p - __jove_startup_info_environ;
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
  return (_findenv(name, (int)(np - name), &offset));
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

unsigned _read_pseudo_file(const char *path, char *out, size_t len) {
  unsigned n;

  {
    int fd = _jove_sys_openat(AT_FDCWD, path, O_RDONLY, S_IRWXU);
    if (fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    // let n denote the number of characters read
    n = 0;

    for (;;) {
      ssize_t ret = _jove_sys_read(fd, &out[n], len - n);

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

    if (_jove_sys_close(fd) < 0) {
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

void *_memset(void *dst, int c, size_t n) {
  if (n != 0) {
    unsigned char *d = dst;

    do
      *d++ = (unsigned char)c;
    while (--n != 0);
  }
  return (dst);
}

static void _jove_sigsegv_handler(void);

void _jove_trace_init(void) {
  if (__jove_trace)
    return;

  int fd =
      _jove_sys_openat(AT_FDCWD, "trace.bin", O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  off_t size = 1UL << 31; /* 2 GiB */
  if (_jove_sys_ftruncate(fd, size) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  {
    long ret =
        _jove_sys_mmap(0x0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (ret < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    void *ptr = (void *)ret;

    __jove_trace_begin = __jove_trace = ptr;
  }

  if (_jove_sys_close(fd) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  //
  // install SIGSEGV handler
  //
  struct kernel_sigaction sa;
  _memset(&sa, 0, sizeof(sa));
  sa._sa_handler = (void *)_jove_sigsegv_handler;

  {
    long ret =
        _jove_sys_rt_sigaction(SIGSEGV, &sa, NULL, sizeof(kernel_sigset_t));
    if (ret < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }
}

static void _jove_flush_trace(void);

void _jove_sigsegv_handler(void) {
  _jove_flush_trace();

  _jove_sys_exit_group(22);
  __builtin_trap();
  __builtin_unreachable();
}

void _jove_flush_trace(void) {
  if (!__jove_trace || !__jove_trace_begin)
    return;

  size_t len = __jove_trace - __jove_trace_begin;
  len *= sizeof(uint64_t);

  long ret = _jove_sys_msync((unsigned long)__jove_trace_begin, len, MS_SYNC);
  if (ret < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }
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

/// A utility function that converts a character to a digit.
unsigned _getDigit(char cdigit, uint8_t radix) {
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

size_t _strlen(const char *str) {
  const char *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

int _atoi(const char *s) {
  unsigned res = 0;
  const uint8_t radix = 10;
  // Figure out if we can shift instead of multiply
  unsigned shift = (radix == 16 ? 4 : radix == 8 ? 3 : radix == 2 ? 1 : 0);
  size_t slen = _strlen(s);

  const char *p = s;
  for (const char *e = s + slen; p != e; ++p) {
    unsigned digit = _getDigit(*p, radix);

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

size_t _sum_iovec_lengths(const struct iovec *iov, unsigned n) {
  size_t expected = 0;
  for (unsigned i = 0; i < n; ++i)
    expected += iov[i].iov_len;
  return expected;
}

void _jove_recover_dyn_target(uint32_t CallerBBIdx,
                              target_ulong CalleeAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");
  if (!recover_fifo_path)
    return;

  uint32_t CallerBIdx = _jove_binary_index();

  struct {
    uint32_t BIdx;
    uint32_t FIdx;
  } Callee;

  for (unsigned BIdx = 0; BIdx < _JOVE_MAX_BINARIES ; ++BIdx) {
    uintptr_t *fns = __jove_function_tables[BIdx];
    if (!fns) {
      /* XXX */
      if (BIdx == 1 || BIdx == 2) {
        fns = __jove_foreign_function_tables[BIdx];
        if (!fns)
          continue;
      } else {
        continue;
      }
    }

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
    int recover_fd = _jove_sys_openat(AT_FDCWD, recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    {
      char ch = 'f';

      struct iovec iov_arr[] = {
          _IOV_ENTRY(ch),
          _IOV_ENTRY(CallerBIdx),
          _IOV_ENTRY(CallerBBIdx),
          _IOV_ENTRY(Callee.BIdx),
          _IOV_ENTRY(Callee.FIdx)
      };

      size_t expected = _sum_iovec_lengths(iov_arr, ARRAY_SIZE(iov_arr));
      if (_jove_sys_writev(recover_fd, iov_arr, ARRAY_SIZE(iov_arr)) != expected) {
        __builtin_trap();
        __builtin_unreachable();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_recover_basic_block(uint32_t IndBrBBIdx,
                               target_ulong BBAddr) {
  char *recover_fifo_path = _getenv("JOVE_RECOVER_FIFO");
  if (!recover_fifo_path)
    return;

  struct {
    uint32_t BIdx;
    uint32_t BBIdx;
  } IndBr;

  struct {
    uintptr_t Beg;
    uintptr_t End;
  } SectionsGlobal;

  uintptr_t SectsStartFileAddr;

  IndBr.BIdx = _jove_binary_index();
  IndBr.BBIdx = IndBrBBIdx;

  SectionsGlobal.Beg = _jove_sections_global_beg_addr();
  SectionsGlobal.End = _jove_sections_global_end_addr();
  SectsStartFileAddr = _jove_sections_start_file_addr();

  if (!(BBAddr >= SectionsGlobal.Beg && BBAddr < SectionsGlobal.End))
    return; /* not found */

  uintptr_t FileAddr = (BBAddr - SectionsGlobal.Beg) + SectsStartFileAddr;

found:
  {
    int recover_fd = _jove_sys_openat(AT_FDCWD, recover_fifo_path, O_WRONLY, 0666);
    if (recover_fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    {
      char ch = 'b';

      struct iovec iov_arr[] = {
          _IOV_ENTRY(ch),
          _IOV_ENTRY(IndBr.BIdx),
          _IOV_ENTRY(IndBr.BBIdx),
          _IOV_ENTRY(FileAddr)
      };

      size_t expected = _sum_iovec_lengths(iov_arr, ARRAY_SIZE(iov_arr));
      if (_jove_sys_writev(recover_fd, iov_arr, ARRAY_SIZE(iov_arr)) != expected) {
        __builtin_trap();
        __builtin_unreachable();
      }

      _jove_sys_close(recover_fd);
      _jove_sys_exit_group(ch);
    }
  }
}

void _jove_fail1(target_ulong rdi) {
  __builtin_trap();
  __builtin_unreachable();
}

void _jove_fail2(target_ulong rdi,
                 target_ulong rsi) {
  __builtin_trap();
  __builtin_unreachable();
}

target_ulong _jove_thunk(target_ulong dstpc   /* x0 */,
                         target_ulong *args   /* x1 */,
                         target_ulong *emuspp /* x2 */) {
  asm volatile("stp x29, x30, [sp, #-48]!\n" /* push frame */

               "stp x19, x20, [sp, #16]\n" /* callee-saved registers */
               "stp x21, x22, [sp, #32]\n"

               "mov x19, x0\n" /* dstpc in x19 */
               "mov x20, x1\n" /* args in x20 */
               "mov x21, x2\n" /* emuspp in x21 */
               "mov x22, sp\n" /* save sp in x22 */

               "bl _jove_alloc_stack\n"
               "mov x10, x19\n" /* put dstpc in temporary register */
               "mov x19, x0\n"  /* allocated stack in callee-saved register */
               "add x0, x0, #0x80000\n"

               "ldr x9, [x21]\n" /* sp=*emusp */
               "mov sp, x9\n"

               "str x0, [x21]\n" /* *emusp=stack storage */

               /* unpack args */
               "ldr x7, [x20, #56]\n"
               "ldr x6, [x20, #48]\n"
               "ldr x5, [x20, #40]\n"
               "ldr x4, [x20, #32]\n"
               "ldr x3, [x20, #24]\n"
               "ldr x2, [x20, #16]\n"
               "ldr x1, [x20, #8]\n"
               "ldr x0, [x20, #0]\n"

               "blr x10\n" /* call dstpc */

               "mov x9, sp\n" /* store modified emusp */
               "str x9, [x21]\n"

               "mov sp, x22\n"   /* restore stack pointer */

               "mov x22, x0\n"  /* save return value */

               "mov x0, x19\n" /* pass allocated stack */
               "bl _jove_free_stack\n"

               "mov x0, x22\n" /* restore return value */

               "ldp x19, x20, [sp, #16]\n"
               "ldp x21, x22, [sp, #32]\n" /* callee-saved registers */

               "ldp x29, x30, [sp], #48\n" /* restore frame */

               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

bool _isDigit(char C) { return C >= '0' && C <= '9'; }

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
    if (eol[-1]  == 'o'
     && eol[-2]  == 's'
     && eol[-3]  == '.'
     && _isDigit(eol[-4])
     && _isDigit(eol[-5])
     && eol[-6]  == '.'
     && _isDigit(eol[-7])
     && eol[-8]  == '-'
     && eol[-9]  == 'd'
     && eol[-10] == 'l'
     && eol[-11] == '/'
     && eol[-12] == 'b'
     && eol[-13] == 'i'
     && eol[-14] == 'l'
     && eol[-15] == '/'
     && eol[-16] == 'r'
     && eol[-17] == 's'
     && eol[-18] == 'u'
     && eol[-19] == '/') {
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

static bool __jove_installed_foreign_function_tables = false;

void _jove_install_foreign_function_tables(void) {
  if (__jove_installed_foreign_function_tables)
    return;
  __jove_installed_foreign_function_tables = true;

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

  __jove_foreign_function_tables[1] = dynl_fn_tbl;
  __jove_foreign_function_tables[2] = vdso_fn_tbl;
}

target_ulong _jove_alloc_stack(void) {
  long ret = _jove_sys_mmap(0x0, JOVE_STACK_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);
  if (ret < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  //
  // create guard pages on both sides
  //
  unsigned long beg = (unsigned long)ret;
  unsigned long end = beg + JOVE_STACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  return beg;
}

void _jove_free_stack(target_ulong beg) {
  if (_jove_sys_munmap(beg, JOVE_STACK_SIZE) < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }
}

static bool _jove_is_readable_mem(target_ulong Addr);
static bool _jove_is_foreign_code(target_ulong Addr);

void _jove_check_return_address(target_ulong RetAddr,
                                target_ulong NativeRetAddr) {
  static const target_ulong Cookie = 0xbd47c92caa6cbcb4;
  if (likely(RetAddr == Cookie))
    return;

  if (_jove_is_readable_mem(NativeRetAddr) &&
      _jove_is_foreign_code(NativeRetAddr))
    return; /* the return address is bogus because foreign code is calling into
               recompiled code */

  __builtin_trap();
  __builtin_unreachable();
}

bool _jove_is_readable_mem(target_ulong Addr) {
  pid_t pid;
  {
    long ret = _jove_sys_getpid();
    if (unlikely(ret < 0)) {
      __builtin_trap();
      __builtin_unreachable();
    }
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

static bool _is_foreign_code_of_maps(char *maps, const unsigned n,
                                     target_ulong Addr);

bool _jove_is_foreign_code(target_ulong Addr) {
  char buff[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
  buff[n] = '\0';

  uintptr_t res = _is_foreign_code_of_maps(buff, n, Addr);
  return res;
}

// precondition: Addr must point to valid virtual memory area
bool _is_foreign_code_of_maps(char *maps, const unsigned n, target_ulong Addr) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);
    }

    struct {
      uint64_t min, max;
    } vm;

    {
      unsigned left = eol - line;

      char *dash = _memchr(line, '-', left);
      vm.min = _u64ofhexstr(line, dash);

      char *space = _memchr(line, ' ', left);
      vm.max = _u64ofhexstr(dash + 1, space);
    }

    if (Addr >= vm.min && Addr < vm.max) {
      return (eol[-1] == ']'
           && eol[-2] == 'o'
           && eol[-3] == 's'
           && eol[-4] == 'd'
           && eol[-5] == 'v'
           && eol[-6] == '[')
        ||
             (eol[-1]  == 'o'
           && eol[-2]  == 's'
           && eol[-3]  == '.'
           && _isDigit(eol[-4])
           && _isDigit(eol[-5])
           && eol[-6]  == '.'
           && _isDigit(eol[-7])
           && eol[-8]  == '-'
           && eol[-9]  == 'd'
           && eol[-10] == 'l'
           && eol[-11] == '/'
           && eol[-12] == 'b'
           && eol[-13] == 'i'
           && eol[-14] == 'l'
           && eol[-15] == '/'
           && eol[-16] == 'r'
           && eol[-17] == 's'
           && eol[-18] == 'u'
           && eol[-19] == '/');
    }
  }

  __builtin_trap();
  __builtin_unreachable();
}

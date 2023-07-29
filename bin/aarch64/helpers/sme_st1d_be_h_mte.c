#define CONFIG_USER_ONLY 1

#define TARGET_AARCH64 1

#define TARGET_BIG_ENDIAN 0

#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#define QEMU_ALWAYS_INLINE  __attribute__((always_inline))

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

# define G_NORETURN __attribute__ ((__noreturn__))

#define _GLIB_EXTERN extern

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

#define G_LOG_DOMAIN    ((gchar*) 0)

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

GLIB_AVAILABLE_IN_ALL
G_NORETURN
void    g_assertion_message_expr        (const char     *domain,
                                         const char     *file,
                                         int             line,
                                         const char     *func,
                                         const char     *expr);

typedef struct CPUArchState CPUArchState;

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

typedef enum __attribute__((__packed__)) {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3,
    float_round_ties_away    = 4,
    /* Not an IEEE rounding mode: round to closest odd, overflow to max */
    float_round_to_odd       = 5,
    /* Not an IEEE rounding mode: round to closest odd, overflow to inf */
    float_round_to_odd_inf   = 6,
} FloatRoundMode;

typedef enum __attribute__((__packed__)) {
    floatx80_precision_x,
    floatx80_precision_d,
    floatx80_precision_s,
} FloatX80RoundPrec;

typedef struct float_status {
    uint16_t float_exception_flags;
    FloatRoundMode float_rounding_mode;
    FloatX80RoundPrec floatx80_rounding_precision;
    bool tininess_before_rounding;
    /* should denormalised results go to zero and set the inexact flag? */
    bool flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    bool flush_inputs_to_zero;
    bool default_nan_mode;
    /*
     * The flags below are not used on all specializations and may
     * constant fold away (see snan_bit_is_one()/no_signalling_nans() in
     * softfloat-specialize.inc.c)
     */
    bool snan_bit_is_one;
    bool use_first_nan;
    bool no_signaling_nans;
    /* should overflowed results subtract re_bias to its exponent? */
    bool rebias_overflow;
    /* should underflowed results add re_bias to its exponent? */
    bool rebias_underflow;
} float_status;

#define le_bswap(v, size) (v)

#define be_bswap(v, size) glue(__builtin_bswap, size)(v)

static inline void bswap64s(uint64_t *s)
{
    *s = __builtin_bswap64(*s);
}

static inline int lduw_he_p(const void *ptr)
{
    uint16_t r;
    __builtin_memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline void stq_he_p(void *ptr, uint64_t v)
{
    __builtin_memcpy(ptr, &v, sizeof(v));
}

static inline void stq_le_p(void *ptr, uint64_t v)
{
    stq_he_p(ptr, le_bswap(v, 64));
}

static inline void stq_be_p(void *ptr, uint64_t v)
{
    stq_he_p(ptr, be_bswap(v, 64));
}

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

static inline int64_t sextract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int64_t)(value << (64 - length - start))) >> (64 - length);
}

#define FIELD(reg, field, shift, length)                                  \
    enum { R_ ## reg ## _ ## field ## _SHIFT = (shift)};                  \
    enum { R_ ## reg ## _ ## field ## _LENGTH = (length)};                \
    enum { R_ ## reg ## _ ## field ## _MASK =                             \
                                        MAKE_64BIT_MASK(shift, length)};

#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

typedef uint64_t vaddr;

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
    /*
     * Bus interconnect and peripherals can access anything (memories,
     * devices) by default. By setting the 'memory' bit, bus transaction
     * are restricted to "normal" memories (per the AMBA documentation)
     * versus devices. Access to devices will be logged and rejected
     * (see MEMTX_ACCESS_ERROR).
     */
    unsigned int memory:1;
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

typedef enum MMUAccessType {
    MMU_DATA_LOAD  = 0,
    MMU_DATA_STORE = 1,
    MMU_INST_FETCH = 2
} MMUAccessType;

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

#define BP_MEM_WRITE          0x02

#  define TARGET_TAGGED_ADDRESSES

typedef uint64_t target_ulong;

enum {
    M_REG_NS = 0,
    M_REG_S = 1,
    M_REG_NUM_BANKS = 2,
};

#define NUM_GTIMERS     5

# define ARM_MAX_VQ    16

typedef struct ARMGenericTimer {
    uint64_t cval; /* Timer CompareValue register */
    uint64_t ctl; /* Timer Control register */
} ARMGenericTimer;

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

typedef struct ARMPACKey {
    uint64_t lo, hi;
} ARMPACKey;

typedef struct CPUARMTBFlags {
    uint32_t flags;
    target_ulong flags2;
} CPUARMTBFlags;

typedef struct ARMMMUFaultInfo ARMMMUFaultInfo;

typedef struct CPUArchState {
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
     *  SM and ZA are kept in env->svcr
     *  all other bits are stored in their correct places in env->pstate
     */
    uint32_t pstate;
    bool aarch64; /* True if CPU is in aarch64 state; inverse of PSTATE.nRW */
    bool thumb;   /* True if CPU is in thumb mode; cpsr[5] */

    /* Cached TBFLAGS state.  See below for which bits are included.  */
    CPUARMTBFlags hflags;

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
    uint32_t condexec_bits; /* IT bits.  cpsr[15:10,26:25].  */
    uint32_t btype;  /* BTI branch type.  spsr[11:10].  */
    uint64_t daif; /* exception masks, in the bits they are in PSTATE */
    uint64_t svcr; /* PSTATE.{SM,ZA} in the bits they are in SVCR */

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
        uint64_t vsctlr; /* Virtualization System control register. */
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
        uint64_t vsttbr_el2; /* Secure Virtualization Translation Table. */
        /* MMU translation table base control. */
        uint64_t tcr_el[4];
        uint64_t vtcr_el2; /* Virtualization Translation Control.  */
        uint64_t vstcr_el2; /* Secure Virtualization Translation Control. */
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
        uint64_t hcrx_el2; /* Extended Hypervisor configuration register */
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
#if HOST_BIG_ENDIAN
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
#if HOST_BIG_ENDIAN
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
        uint64_t rvbar; /* rvbar sampled from rvbar property at reset */
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
        uint64_t tpidr2_el0;
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
        uint64_t cnthctl_el2; /* Counter/Timer Hyp Control register */
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
        uint64_t dbgclaim;   /* DBGCLAIM bits */
        uint64_t mdscr_el1;
        uint64_t oslsr_el1; /* OS Lock Status */
        uint64_t osdlr_el1; /* OS DoubleLock status */
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
        uint64_t tfsr_el[4]; /* tfsre0_el1 is index 0.  */
        uint64_t gcr_el1;
        uint64_t rgsr_el1;

        /* Minimal RAS registers */
        uint64_t disr_el1;
        uint64_t vdisr_el2;
        uint64_t vsesr_el2;

        /*
         * Fine-Grained Trap registers. We store these as arrays so the
         * access checking code doesn't have to manually select
         * HFGRTR_EL2 vs HFDFGRTR_EL2 etc when looking up the bit to test.
         * FEAT_FGT2 will add more elements to these arrays.
         */
        uint64_t fgt_read[2]; /* HFGRTR, HDFGRTR */
        uint64_t fgt_write[2]; /* HFGWTR, HDFGWTR */
        uint64_t fgt_exec[1]; /* HFGITR */
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
        uint32_t ltpsize;
        uint32_t vpr;
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

    uint8_t ext_dabt_raised; /* Tracking/verifying injection of ext DABT */

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
         *  standard_fp_status_fp16 : used for half-precision
         *       calculations with the ARM "Standard FPSCR Value"
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
         * The "standard FPSCR but for fp16 ops" is needed because
         * the "standard FPSCR" tracks the FPSCR.FZ16 bit rather than
         * using a fixed value for it.
         *
         * To avoid having to transfer exception bits around, we simply
         * say that the FPSCR cumulative exception flags are the logical
         * OR of the flags in the four fp statuses. This relies on the
         * only thing which needs to read the exception flags being
         * an explicit FPSCR read.
         */
        float_status fp_status;
        float_status fp_status_f16;
        float_status standard_fp_status;
        float_status standard_fp_status_f16;

        uint64_t zcr_el[4];   /* ZCR_EL[1-3] */
        uint64_t smcr_el[4];  /* SMCR_EL[1-3] */
    } vfp;

    uint64_t exclusive_addr;
    uint64_t exclusive_val;
    /*
     * Contains the 'val' for the second 64-bit register of LDXP, which comes
     * from the higher address, not the high part of a complete 128-bit value.
     * In some ways it might be more convenient to record the exclusive value
     * as the low and high halves of a 128 bit data value, but the current
     * semantics of these fields are baked into the migration format.
     */
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

    uint64_t scxtnum_el[4];

    /*
     * SME ZA storage -- 256 x 256 byte array, with bytes in host word order,
     * as we do with vfp.zregs[].  This corresponds to the architectural ZA
     * array, where ZA[N] is in the least-significant bytes of env->zarray[N].
     * When SVL is less than the architectural maximum, the accessible
     * storage is restricted, such that if the SVL is X bytes the guest can
     * see only the bottom X elements of zarray[], and only the least
     * significant X bytes of each element of the array. (In other words,
     * the observable part is always square.)
     *
     * The ZA storage can also be considered as a set of square tiles of
     * elements of different sizes. The mapping from tiles to the ZA array
     * is architecturally defined, such that for tiles of elements of esz
     * bytes, the Nth row (or "horizontal slice") of tile T is in
     * ZA[T + N * esz]. Note that this means that each tile is not contiguous
     * in the ZA storage, because its rows are striped through the ZA array.
     *
     * Because this is so large, keep this toward the end of the reset area,
     * to keep the offsets into the rest of the structure smaller.
     */
    ARMVectorReg zarray[ARM_MAX_VQ * 16];
#endif

    struct CPUBreakpoint *cpu_breakpoint[16];
    struct CPUWatchpoint *cpu_watchpoint[16];

    /* Optional fault info across tlb lookup. */
    ARMMMUFaultInfo *tlb_fi;

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
        uint32_t *hprbar;
        uint32_t *hprlar;
        uint32_t mair0[M_REG_NUM_BANKS];
        uint32_t mair1[M_REG_NUM_BANKS];
        uint32_t hprselr;
    } pmsav8;

    /* v8M SAU */
    struct {
        uint32_t *rbar;
        uint32_t *rlar;
        uint32_t rnr;
        uint32_t ctrl;
    } sau;

#if !defined(CONFIG_USER_ONLY)
    NVICState *nvic;
    const struct arm_boot_info *boot_info;
    /* Store GICv3CPUState to access from this struct */
    void *gicv3state;
#else /* CONFIG_USER_ONLY */
    /* For usermode syscall translation.  */
    bool eabi;
#endif /* CONFIG_USER_ONLY */

#ifdef TARGET_TAGGED_ADDRESSES
    /* Linux syscall tagged address support */
    bool tagged_addr_enable;
#endif
} CPUARMState;

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) * 8 + 8;
}

static inline intptr_t simd_oprsz(uint32_t desc)
{
    uint32_t f = extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS);
    intptr_t o = f * 8 + 8;
    intptr_t m = simd_maxsz(desc);
    return f == 2 ? m : o;
}

#define SVE_MTEDESC_SHIFT 5

FIELD(MTEDESC, TBI,   4, 2)

FIELD(MTEDESC, TCMA,  6, 2)

static inline int allocation_tag_from_addr(uint64_t ptr)
{
    return extract64(ptr, 56, 4);
}

static inline bool tbi_check(uint32_t desc, int bit55)
{
    return (desc >> (R_MTEDESC_TBI_SHIFT + bit55)) & 1;
}

static inline bool tcma_check(uint32_t desc, int bit55, int ptr_tag)
{
    /*
     * We had extracted bit55 and ptr_tag for other reasons, so fold
     * (ptr<59:55> == 00000 || ptr<59:55> == 11111) into a single test.
     */
    bool match = ((ptr_tag + bit55) & 0xf) == 0;
    bool tcma = (desc >> (R_MTEDESC_TCMA_SHIFT + bit55)) & 1;
    return tcma && match;
}

static inline uint64_t useronly_clean_ptr(uint64_t ptr)
{
#ifdef CONFIG_USER_ONLY
    /* TBI0 is known to be enabled, while TBI1 is disabled. */
    ptr &= sextract64(ptr, 0, 56);
#endif
    return ptr;
}

#define HELPER(name) glue(helper_, name)

typedef enum MemOp {
    MO_8     = 0,
    MO_16    = 1,
    MO_32    = 2,
    MO_64    = 3,
    MO_128   = 4,
    MO_256   = 5,
    MO_512   = 6,
    MO_1024  = 7,
    MO_SIZE  = 0x07,   /* Mask for the above.  */

    MO_SIGN  = 0x08,   /* Sign-extended, otherwise zero-extended.  */

    MO_BSWAP = 0x10,   /* Host reverse endian.  */
#if HOST_BIG_ENDIAN
    MO_LE    = MO_BSWAP,
    MO_BE    = 0,
#else
    MO_LE    = 0,
    MO_BE    = MO_BSWAP,
#endif
#ifdef NEED_CPU_H
#if TARGET_BIG_ENDIAN
    MO_TE    = MO_BE,
#else
    MO_TE    = MO_LE,
#endif
#endif

    /*
     * MO_UNALN accesses are never checked for alignment.
     * MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
     *
     * Some architectures (e.g. ARMv8) need the address which is aligned
     * to a size more than the size of the memory access.
     * Some architectures (e.g. SPARCv9) need an address which is aligned,
     * but less strictly than the natural alignment.
     *
     * MO_ALIGN supposes the alignment size is the size of a memory access.
     *
     * There are three options:
     * - unaligned access permitted (MO_UNALN).
     * - an alignment to the size of an access (MO_ALIGN);
     * - an alignment to a specified size, which may be more or less than
     *   the access size (MO_ALIGN_x where 'x' is a size in bytes);
     */
    MO_ASHIFT = 5,
    MO_AMASK = 0x7 << MO_ASHIFT,
    MO_UNALN    = 0,
    MO_ALIGN_2  = 1 << MO_ASHIFT,
    MO_ALIGN_4  = 2 << MO_ASHIFT,
    MO_ALIGN_8  = 3 << MO_ASHIFT,
    MO_ALIGN_16 = 4 << MO_ASHIFT,
    MO_ALIGN_32 = 5 << MO_ASHIFT,
    MO_ALIGN_64 = 6 << MO_ASHIFT,
    MO_ALIGN    = MO_AMASK,

    /*
     * MO_ATOM_* describes the atomicity requirements of the operation:
     * MO_ATOM_IFALIGN: the operation must be single-copy atomic if it
     *    is aligned; if unaligned there is no atomicity.
     * MO_ATOM_IFALIGN_PAIR: the entire operation may be considered to
     *    be a pair of half-sized operations which are packed together
     *    for convenience, with single-copy atomicity on each half if
     *    the half is aligned.
     *    This is the atomicity e.g. of Arm pre-FEAT_LSE2 LDP.
     * MO_ATOM_WITHIN16: the operation is single-copy atomic, even if it
     *    is unaligned, so long as it does not cross a 16-byte boundary;
     *    if it crosses a 16-byte boundary there is no atomicity.
     *    This is the atomicity e.g. of Arm FEAT_LSE2 LDR.
     * MO_ATOM_WITHIN16_PAIR: the entire operation is single-copy atomic,
     *    if it happens to be within a 16-byte boundary, otherwise it
     *    devolves to a pair of half-sized MO_ATOM_WITHIN16 operations.
     *    Depending on alignment, one or both will be single-copy atomic.
     *    This is the atomicity e.g. of Arm FEAT_LSE2 LDP.
     * MO_ATOM_SUBALIGN: the operation is single-copy atomic by parts
     *    by the alignment.  E.g. if the address is 0 mod 4, then each
     *    4-byte subobject is single-copy atomic.
     *    This is the atomicity e.g. of IBM Power.
     * MO_ATOM_NONE: the operation has no atomicity requirements.
     *
     * Note the default (i.e. 0) value is single-copy atomic to the
     * size of the operation, if aligned.  This retains the behaviour
     * from before this field was introduced.
     */
    MO_ATOM_SHIFT         = 8,
    MO_ATOM_IFALIGN       = 0 << MO_ATOM_SHIFT,
    MO_ATOM_IFALIGN_PAIR  = 1 << MO_ATOM_SHIFT,
    MO_ATOM_WITHIN16      = 2 << MO_ATOM_SHIFT,
    MO_ATOM_WITHIN16_PAIR = 3 << MO_ATOM_SHIFT,
    MO_ATOM_SUBALIGN      = 4 << MO_ATOM_SHIFT,
    MO_ATOM_NONE          = 5 << MO_ATOM_SHIFT,
    MO_ATOM_MASK          = 7 << MO_ATOM_SHIFT,

    /* Combinations of the above, for ease of use.  */
    MO_UB    = MO_8,
    MO_UW    = MO_16,
    MO_UL    = MO_32,
    MO_UQ    = MO_64,
    MO_UO    = MO_128,
    MO_SB    = MO_SIGN | MO_8,
    MO_SW    = MO_SIGN | MO_16,
    MO_SL    = MO_SIGN | MO_32,
    MO_SQ    = MO_SIGN | MO_64,
    MO_SO    = MO_SIGN | MO_128,

    MO_LEUW  = MO_LE | MO_UW,
    MO_LEUL  = MO_LE | MO_UL,
    MO_LEUQ  = MO_LE | MO_UQ,
    MO_LESW  = MO_LE | MO_SW,
    MO_LESL  = MO_LE | MO_SL,
    MO_LESQ  = MO_LE | MO_SQ,

    MO_BEUW  = MO_BE | MO_UW,
    MO_BEUL  = MO_BE | MO_UL,
    MO_BEUQ  = MO_BE | MO_UQ,
    MO_BESW  = MO_BE | MO_SW,
    MO_BESL  = MO_BE | MO_SL,
    MO_BESQ  = MO_BE | MO_SQ,

#ifdef NEED_CPU_H
    MO_TEUW  = MO_TE | MO_UW,
    MO_TEUL  = MO_TE | MO_UL,
    MO_TEUQ  = MO_TE | MO_UQ,
    MO_TEUO  = MO_TE | MO_UO,
    MO_TESW  = MO_TE | MO_SW,
    MO_TESL  = MO_TE | MO_SL,
    MO_TESQ  = MO_TE | MO_SQ,
#endif

    MO_SSIZE = MO_SIZE | MO_SIGN,
} MemOp;

typedef uint64_t abi_ptr;

void cpu_stq_be_data_ra(CPUArchState *env, abi_ptr ptr,
                        uint64_t val, uintptr_t ra);

void cpu_stq_le_data_ra(CPUArchState *env, abi_ptr ptr,
                        uint64_t val, uintptr_t ra);

# define GETPC() 0

#define H1_8(x) (x)

typedef void sve_ldst1_host_fn(void *vd, intptr_t reg_off, void *host);

#define DO_ST_HOST(NAME, H, TYPEE, TYPEM, HOST)                              \
static inline void sve_##NAME##_host(void *vd, intptr_t reg_off, void *host) \
{ TYPEM val = *(TYPEE *)(vd + H(reg_off)); HOST(host, val); }

#define DO_ST_TLB(NAME, H, TYPEE, TYPEM, TLB)                              \
static inline void sve_##NAME##_tlb(CPUARMState *env, void *vd,            \
                        intptr_t reg_off, target_ulong addr, uintptr_t ra) \
{                                                                          \
    TYPEM val = *(TYPEE *)(vd + H(reg_off));                               \
    TLB(env, useronly_clean_ptr(addr), val, ra);                           \
}

typedef void sve_ldst1_tlb_fn(CPUARMState *env, void *vd, intptr_t reg_off,
                              target_ulong vaddr, uintptr_t retaddr);

#define DO_ST_PRIM_2(NAME, H, TE, TM, ST) \
    DO_ST_HOST(st1##NAME##_be, H, TE, TM, ST##_be_p)    \
    DO_ST_HOST(st1##NAME##_le, H, TE, TM, ST##_le_p)    \
    DO_ST_TLB(st1##NAME##_be, H, TE, TM, cpu_##ST##_be_data_ra) \
    DO_ST_TLB(st1##NAME##_le, H, TE, TM, cpu_##ST##_le_data_ra)

DO_ST_PRIM_2(dd, H1_8, uint64_t, uint64_t, stq)

typedef struct {
    void *host;
    int flags;
    MemTxAttrs attrs;
    bool tagged;
} SVEHostPage;

typedef enum {
    FAULT_NO,
    FAULT_FIRST,
    FAULT_ALL,
} SVEContFault;

typedef struct {
    /*
     * First and last element wholly contained within the two pages.
     * mem_off_first[0] and reg_off_first[0] are always set >= 0.
     * reg_off_last[0] may be < 0 if the first element crosses pages.
     * All of mem_off_first[1], reg_off_first[1] and reg_off_last[1]
     * are set >= 0 only if there are complete elements on a second page.
     *
     * The reg_off_* offsets are relative to the internal vector register.
     * The mem_off_first offset is relative to the memory address; the
     * two offsets are different when a load operation extends, a store
     * operation truncates, or for multi-register operations.
     */
    int16_t mem_off_first[2];
    int16_t reg_off_first[2];
    int16_t reg_off_last[2];

    /*
     * One element that is misaligned and spans both pages,
     * or -1 if there is no such active element.
     */
    int16_t mem_off_split;
    int16_t reg_off_split;

    /*
     * The byte offset at which the entire operation crosses a page boundary.
     * Set >= 0 if and only if the entire operation spans two pages.
     */
    int16_t page_split;

    /* TLB data for the two pages. */
    SVEHostPage page[2];
} SVEContLdSt;

bool sve_cont_ldst_elements(SVEContLdSt *info, target_ulong addr, uint64_t *vg,
                            intptr_t reg_max, int esz, int msize);

bool sve_cont_ldst_pages(SVEContLdSt *info, SVEContFault fault,
                         CPUARMState *env, target_ulong addr,
                         MMUAccessType access_type, uintptr_t retaddr);

static inline void
sve_cont_ldst_watchpoints(SVEContLdSt *info, CPUARMState *env, uint64_t *vg,
                          target_ulong addr, int esize, int msize,
                          int wp_access, uintptr_t retaddr)
{ }

void sve_cont_ldst_mte_check(SVEContLdSt *info, CPUARMState *env, uint64_t *vg,
                             target_ulong addr, int esize, int msize,
                             uint32_t mtedesc, uintptr_t ra);

#define tile_vslice_offset(byteoff) ((byteoff) * sizeof(ARMVectorReg))

#define DO_ST(NAME, TYPE, HOST, TLB)                                        \
static inline void sme_##NAME##_v_host(void *za, intptr_t off, void *host)  \
{                                                                           \
    TYPE val = *(TYPE *)(za + tile_vslice_offset(off));                     \
    HOST(host, val);                                                        \
}                                                                           \
static inline void sme_##NAME##_v_tlb(CPUARMState *env, void *za,           \
                        intptr_t off, target_ulong addr, uintptr_t ra)      \
{                                                                           \
    TYPE val = *(TYPE *)(za + tile_vslice_offset(off));                     \
    TLB(env, useronly_clean_ptr(addr), val, ra);                            \
}

DO_ST(st1d_be, uint64_t, stq_be_p, cpu_stq_be_data_ra)

static inline QEMU_ALWAYS_INLINE
void sme_st1(CPUARMState *env, void *za, uint64_t *vg,
             const target_ulong addr, uint32_t desc, const uintptr_t ra,
             const int esz, uint32_t mtedesc, bool vertical,
             sve_ldst1_host_fn *host_fn,
             sve_ldst1_tlb_fn *tlb_fn)
{
    const intptr_t reg_max = simd_oprsz(desc);
    const intptr_t esize = 1 << esz;
    intptr_t reg_off, reg_last;
    SVEContLdSt info;
    void *host;
    int flags;

    /* Find the active elements.  */
    if (!sve_cont_ldst_elements(&info, addr, vg, reg_max, esz, esize)) {
        /* The entire predicate was false; no store occurs.  */
        return;
    }

    /* Probe the page(s).  Exit with exception for any invalid page. */
    sve_cont_ldst_pages(&info, FAULT_ALL, env, addr, MMU_DATA_STORE, ra);

    /* Handle watchpoints for all active elements. */
    sve_cont_ldst_watchpoints(&info, env, vg, addr, esize, esize,
                              BP_MEM_WRITE, ra);

    /*
     * Handle mte checks for all active elements.
     * Since TBI must be set for MTE, !mtedesc => !mte_active.
     */
    if (mtedesc) {
        sve_cont_ldst_mte_check(&info, env, vg, addr, esize, esize,
                                mtedesc, ra);
    }

    flags = info.page[0].flags | info.page[1].flags;
    if (unlikely(flags != 0)) {
#ifdef CONFIG_USER_ONLY
        g_assert_not_reached();
#else
        /*
         * At least one page includes MMIO.
         * Any bus operation can fail with cpu_transaction_failed,
         * which for ARM will raise SyncExternal.  We cannot avoid
         * this fault and will leave with the store incomplete.
         */
        reg_off = info.reg_off_first[0];
        reg_last = info.reg_off_last[1];
        if (reg_last < 0) {
            reg_last = info.reg_off_split;
            if (reg_last < 0) {
                reg_last = info.reg_off_last[0];
            }
        }

        do {
            uint64_t pg = vg[reg_off >> 6];
            do {
                if ((pg >> (reg_off & 63)) & 1) {
                    tlb_fn(env, za, reg_off, addr + reg_off, ra);
                }
                reg_off += esize;
            } while (reg_off & 63);
        } while (reg_off <= reg_last);
        return;
#endif
    }

    reg_off = info.reg_off_first[0];
    reg_last = info.reg_off_last[0];
    host = info.page[0].host;

    while (reg_off <= reg_last) {
        uint64_t pg = vg[reg_off >> 6];
        do {
            if ((pg >> (reg_off & 63)) & 1) {
                host_fn(za, reg_off, host + reg_off);
            }
            reg_off += 1 << esz;
        } while (reg_off <= reg_last && (reg_off & 63));
    }

    /*
     * Use the slow path to manage the cross-page misalignment.
     * But we know this is RAM and cannot trap.
     */
    reg_off = info.reg_off_split;
    if (unlikely(reg_off >= 0)) {
        tlb_fn(env, za, reg_off, addr + reg_off, ra);
    }

    reg_off = info.reg_off_first[1];
    if (unlikely(reg_off >= 0)) {
        reg_last = info.reg_off_last[1];
        host = info.page[1].host;

        do {
            uint64_t pg = vg[reg_off >> 6];
            do {
                if ((pg >> (reg_off & 63)) & 1) {
                    host_fn(za, reg_off, host + reg_off);
                }
                reg_off += 1 << esz;
            } while (reg_off & 63);
        } while (reg_off <= reg_last);
    }
}

#define DO_ST(L, END, ESZ)                                                 \
void HELPER(sme_st1##L##END##_h)(CPUARMState *env, void *za, void *vg,     \
                                 target_ulong addr, uint32_t desc)         \
{                                                                          \
    sme_st1(env, za, vg, addr, desc, GETPC(), ESZ, 0, false,               \
            sve_st1##L##L##END##_host, sve_st1##L##L##END##_tlb);          \
}                                                                          \
void HELPER(sme_st1##L##END##_v)(CPUARMState *env, void *za, void *vg,     \
                                 target_ulong addr, uint32_t desc)         \
{                                                                          \
    sme_st1(env, za, vg, addr, desc, GETPC(), ESZ, 0, true,                \
            sme_st1##L##END##_v_host, sme_st1##L##END##_v_tlb);            \
}                                                                          \
void HELPER(sme_st1##L##END##_h_mte)(CPUARMState *env, void *za, void *vg, \
                                     target_ulong addr, uint32_t desc)     \
{                                                                          \
    sme_st1_mte(env, za, vg, addr, desc, GETPC(), ESZ, false,              \
                sve_st1##L##L##END##_host, sve_st1##L##L##END##_tlb);      \
}                                                                          \
void HELPER(sme_st1##L##END##_v_mte)(CPUARMState *env, void *za, void *vg, \
                                     target_ulong addr, uint32_t desc)     \
{                                                                          \
    sme_st1_mte(env, za, vg, addr, desc, GETPC(), ESZ, true,               \
                sme_st1##L##END##_v_host, sme_st1##L##END##_v_tlb);        \
}

static inline QEMU_ALWAYS_INLINE
void sme_st1_mte(CPUARMState *env, void *za, uint64_t *vg, target_ulong addr,
                 uint32_t desc, uintptr_t ra, int esz, bool vertical,
                 sve_ldst1_host_fn *host_fn,
                 sve_ldst1_tlb_fn *tlb_fn)
{
    uint32_t mtedesc = desc >> (SIMD_DATA_SHIFT + SVE_MTEDESC_SHIFT);
    int bit55 = extract64(addr, 55, 1);

    /* Remove mtedesc from the normal sve descriptor. */
    desc = extract32(desc, 0, SIMD_DATA_SHIFT + SVE_MTEDESC_SHIFT);

    /* Perform gross MTE suppression early. */
    if (!tbi_check(desc, bit55) ||
        tcma_check(desc, bit55, allocation_tag_from_addr(addr))) {
        mtedesc = 0;
    }

    sme_st1(env, za, vg, addr, desc, ra, esz, mtedesc,
            vertical, host_fn, tlb_fn);
}

DO_ST(d, _be, MO_64)


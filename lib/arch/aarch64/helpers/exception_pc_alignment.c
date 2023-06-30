#define CONFIG_USER_ONLY 1

#define TARGET_AARCH64 1

#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#include <stdbool.h>

#include <stdint.h>

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

#include <stddef.h>

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

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define FIELD(reg, field, shift, length)                                  \
    enum { R_ ## reg ## _ ## field ## _SHIFT = (shift)};                  \
    enum { R_ ## reg ## _ ## field ## _LENGTH = (length)};                \
    enum { R_ ## reg ## _ ## field ## _MASK =                             \
                                        MAKE_64BIT_MASK(shift, length)};

#define FIELD_EX32(storage, reg, field)                                   \
    extract32((storage), R_ ## reg ## _ ## field ## _SHIFT,               \
              R_ ## reg ## _ ## field ## _LENGTH)

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

#  define TARGET_TAGGED_ADDRESSES

typedef uint64_t target_ulong;

#define EXCP_PREFETCH_ABORT  3

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

#define TTBCR_EAE    (1U << 31)

FIELD(VTCR, IRGN0, 8, 2)

FIELD(VTCR, ORGN0, 10, 2)

FIELD(VTCR, SH0, 12, 2)

FIELD(VTCR, PS, 16, 3)

FIELD(VTCR, VS, 19, 1)

FIELD(VTCR, HA, 21, 1)

FIELD(VTCR, HD, 22, 1)

FIELD(VTCR, DS, 32, 1)

#define HCR_RW        (1ULL << 31)

#define SCR_NS                (1ULL << 0)

#define SCR_RW                (1ULL << 10)

#define SCR_EEL2              (1ULL << 18)

enum arm_features {
    ARM_FEATURE_AUXCR,  /* ARM1026 Auxiliary control register.  */
    ARM_FEATURE_XSCALE, /* Intel XScale extensions.  */
    ARM_FEATURE_IWMMXT, /* Intel iwMMXt extension.  */
    ARM_FEATURE_V6,
    ARM_FEATURE_V6K,
    ARM_FEATURE_V7,
    ARM_FEATURE_THUMB2,
    ARM_FEATURE_PMSA,   /* no MMU; may have Memory Protection Unit */
    ARM_FEATURE_NEON,
    ARM_FEATURE_M, /* Microcontroller profile.  */
    ARM_FEATURE_OMAPCP, /* OMAP specific CP15 ops handling.  */
    ARM_FEATURE_THUMB2EE,
    ARM_FEATURE_V7MP,    /* v7 Multiprocessing Extensions */
    ARM_FEATURE_V7VE, /* v7 Virtualization Extensions (non-EL2 parts) */
    ARM_FEATURE_V4T,
    ARM_FEATURE_V5,
    ARM_FEATURE_STRONGARM,
    ARM_FEATURE_VAPA, /* cp15 VA to PA lookups */
    ARM_FEATURE_GENERIC_TIMER,
    ARM_FEATURE_MVFR, /* Media and VFP Feature Registers 0 and 1 */
    ARM_FEATURE_DUMMY_C15_REGS, /* RAZ/WI all of cp15 crn=15 */
    ARM_FEATURE_CACHE_TEST_CLEAN, /* 926/1026 style test-and-clean ops */
    ARM_FEATURE_CACHE_DIRTY_REG, /* 1136/1176 cache dirty status register */
    ARM_FEATURE_CACHE_BLOCK_OPS, /* v6 optional cache block operations */
    ARM_FEATURE_MPIDR, /* has cp15 MPIDR */
    ARM_FEATURE_LPAE, /* has Large Physical Address Extension */
    ARM_FEATURE_V8,
    ARM_FEATURE_AARCH64, /* supports 64 bit mode */
    ARM_FEATURE_CBAR, /* has cp15 CBAR */
    ARM_FEATURE_CBAR_RO, /* has cp15 CBAR and it is read-only */
    ARM_FEATURE_EL2, /* has EL2 Virtualization support */
    ARM_FEATURE_EL3, /* has EL3 Secure monitor support */
    ARM_FEATURE_THUMB_DSP, /* DSP insns supported in the Thumb encodings */
    ARM_FEATURE_PMU, /* has PMU support */
    ARM_FEATURE_VBAR, /* has cp15 VBAR */
    ARM_FEATURE_M_SECURITY, /* M profile Security Extension */
    ARM_FEATURE_M_MAIN, /* M profile Main Extension */
    ARM_FEATURE_V8_1M, /* M profile extras only in v8.1M and later */
};

static inline int arm_feature(CPUARMState *env, int feature)
{
    return (env->features & (1ULL << feature)) != 0;
}

static inline bool arm_is_secure_below_el3(CPUARMState *env)
{
    return false;
}

static inline bool arm_is_el2_enabled(CPUARMState *env)
{
    return false;
}

static inline bool arm_el_is_aa64(CPUARMState *env, int el)
{
    /* This isn't valid for EL0 (if we're in EL0, is_a64() is what you want,
     * and if we're not in EL0 then the state of EL0 isn't well defined.)
     */
    assert(el >= 1 && el <= 3);
    bool aa64 = arm_feature(env, ARM_FEATURE_AARCH64);

    /* The highest exception level is always at the maximum supported
     * register width, and then lower levels have a register width controlled
     * by bits in the SCR or HCR registers.
     */
    if (el == 3) {
        return aa64;
    }

    if (arm_feature(env, ARM_FEATURE_EL3) &&
        ((env->cp15.scr_el3 & SCR_NS) || !(env->cp15.scr_el3 & SCR_EEL2))) {
        aa64 = aa64 && (env->cp15.scr_el3 & SCR_RW);
    }

    if (el == 2) {
        return aa64;
    }

    if (arm_is_el2_enabled(env)) {
        aa64 = aa64 && (env->cp15.hcr_el2 & HCR_RW);
    }

    return aa64;
}

#define ARM_MMU_IDX_A     0x10

#define ARM_MMU_IDX_NOTLB 0x20

#define ARM_MMU_IDX_M     0x40

#define ARM_MMU_IDX_M_PRIV   0x1

#define ARM_MMU_IDX_M_NEGPRI 0x2

#define ARM_MMU_IDX_M_S      0x4

typedef enum ARMMMUIdx {
    /*
     * A-profile.
     */
    ARMMMUIdx_E10_0     = 0 | ARM_MMU_IDX_A,
    ARMMMUIdx_E20_0     = 1 | ARM_MMU_IDX_A,
    ARMMMUIdx_E10_1     = 2 | ARM_MMU_IDX_A,
    ARMMMUIdx_E20_2     = 3 | ARM_MMU_IDX_A,
    ARMMMUIdx_E10_1_PAN = 4 | ARM_MMU_IDX_A,
    ARMMMUIdx_E20_2_PAN = 5 | ARM_MMU_IDX_A,
    ARMMMUIdx_E2        = 6 | ARM_MMU_IDX_A,
    ARMMMUIdx_E3        = 7 | ARM_MMU_IDX_A,

    /* TLBs with 1-1 mapping to the physical address spaces. */
    ARMMMUIdx_Phys_NS   = 8 | ARM_MMU_IDX_A,
    ARMMMUIdx_Phys_S    = 9 | ARM_MMU_IDX_A,

    /*
     * Used for second stage of an S12 page table walk, or for descriptor
     * loads during first stage of an S1 page table walk.  Note that both
     * are in use simultaneously for SecureEL2: the security state for
     * the S2 ptw is selected by the NS bit from the S1 ptw.
     */
    ARMMMUIdx_Stage2    = 10 | ARM_MMU_IDX_A,
    ARMMMUIdx_Stage2_S  = 11 | ARM_MMU_IDX_A,

    /*
     * These are not allocated TLBs and are used only for AT system
     * instructions or for the first stage of an S12 page table walk.
     */
    ARMMMUIdx_Stage1_E0 = 0 | ARM_MMU_IDX_NOTLB,
    ARMMMUIdx_Stage1_E1 = 1 | ARM_MMU_IDX_NOTLB,
    ARMMMUIdx_Stage1_E1_PAN = 2 | ARM_MMU_IDX_NOTLB,

    /*
     * M-profile.
     */
    ARMMMUIdx_MUser = ARM_MMU_IDX_M,
    ARMMMUIdx_MPriv = ARM_MMU_IDX_M | ARM_MMU_IDX_M_PRIV,
    ARMMMUIdx_MUserNegPri = ARMMMUIdx_MUser | ARM_MMU_IDX_M_NEGPRI,
    ARMMMUIdx_MPrivNegPri = ARMMMUIdx_MPriv | ARM_MMU_IDX_M_NEGPRI,
    ARMMMUIdx_MSUser = ARMMMUIdx_MUser | ARM_MMU_IDX_M_S,
    ARMMMUIdx_MSPriv = ARMMMUIdx_MPriv | ARM_MMU_IDX_M_S,
    ARMMMUIdx_MSUserNegPri = ARMMMUIdx_MUserNegPri | ARM_MMU_IDX_M_S,
    ARMMMUIdx_MSPrivNegPri = ARMMMUIdx_MPrivNegPri | ARM_MMU_IDX_M_S,
} ARMMMUIdx;

FIELD(TBFLAG_ANY, MMUIDX, 4, 4)

#define EX_TBFLAG_ANY(IN, WHICH)   FIELD_EX32(IN.flags, TBFLAG_ANY, WHICH)

static inline int cpu_mmu_index(CPUARMState *env, bool ifetch)
{
    return EX_TBFLAG_ANY(env->hflags, MMUIDX);
}

enum arm_exception_class {
    EC_UNCATEGORIZED          = 0x00,
    EC_WFX_TRAP               = 0x01,
    EC_CP15RTTRAP             = 0x03,
    EC_CP15RRTTRAP            = 0x04,
    EC_CP14RTTRAP             = 0x05,
    EC_CP14DTTRAP             = 0x06,
    EC_ADVSIMDFPACCESSTRAP    = 0x07,
    EC_FPIDTRAP               = 0x08,
    EC_PACTRAP                = 0x09,
    EC_BXJTRAP                = 0x0a,
    EC_CP14RRTTRAP            = 0x0c,
    EC_BTITRAP                = 0x0d,
    EC_ILLEGALSTATE           = 0x0e,
    EC_AA32_SVC               = 0x11,
    EC_AA32_HVC               = 0x12,
    EC_AA32_SMC               = 0x13,
    EC_AA64_SVC               = 0x15,
    EC_AA64_HVC               = 0x16,
    EC_AA64_SMC               = 0x17,
    EC_SYSTEMREGISTERTRAP     = 0x18,
    EC_SVEACCESSTRAP          = 0x19,
    EC_ERETTRAP               = 0x1a,
    EC_SMETRAP                = 0x1d,
    EC_INSNABORT              = 0x20,
    EC_INSNABORT_SAME_EL      = 0x21,
    EC_PCALIGNMENT            = 0x22,
    EC_DATAABORT              = 0x24,
    EC_DATAABORT_SAME_EL      = 0x25,
    EC_SPALIGNMENT            = 0x26,
    EC_AA32_FPTRAP            = 0x28,
    EC_AA64_FPTRAP            = 0x2c,
    EC_SERROR                 = 0x2f,
    EC_BREAKPOINT             = 0x30,
    EC_BREAKPOINT_SAME_EL     = 0x31,
    EC_SOFTWARESTEP           = 0x32,
    EC_SOFTWARESTEP_SAME_EL   = 0x33,
    EC_WATCHPOINT             = 0x34,
    EC_WATCHPOINT_SAME_EL     = 0x35,
    EC_AA32_BKPT              = 0x38,
    EC_VECTORCATCH            = 0x3a,
    EC_AA64_BKPT              = 0x3c,
};

#define ARM_EL_EC_SHIFT 26

#define ARM_EL_IL_SHIFT 25

#define ARM_EL_IL (1 << ARM_EL_IL_SHIFT)

static inline uint32_t syn_pcalignment(void)
{
    return (EC_PCALIGNMENT << ARM_EL_EC_SHIFT) | ARM_EL_IL;
}

#define M_FAKE_FSR_NSC_EXEC 0xf

#define M_FAKE_FSR_SFAULT 0xe

G_NORETURN void raise_exception(CPUARMState *env, uint32_t excp,
                                uint32_t syndrome, uint32_t target_el);

typedef enum ARMFaultType {
    ARMFault_None,
    ARMFault_AccessFlag,
    ARMFault_Alignment,
    ARMFault_Background,
    ARMFault_Domain,
    ARMFault_Permission,
    ARMFault_Translation,
    ARMFault_AddressSize,
    ARMFault_SyncExternal,
    ARMFault_SyncExternalOnWalk,
    ARMFault_SyncParity,
    ARMFault_SyncParityOnWalk,
    ARMFault_AsyncParity,
    ARMFault_AsyncExternal,
    ARMFault_Debug,
    ARMFault_TLBConflict,
    ARMFault_UnsuppAtomicUpdate,
    ARMFault_Lockdown,
    ARMFault_Exclusive,
    ARMFault_ICacheMaint,
    ARMFault_QEMU_NSCExec, /* v8M: NS executing in S&NSC memory */
    ARMFault_QEMU_SFault, /* v8M: SecureFault INVTRAN, INVEP or AUVIOL */
} ARMFaultType;

typedef struct ARMMMUFaultInfo ARMMMUFaultInfo;

struct ARMMMUFaultInfo {
    ARMFaultType type;
    target_ulong s2addr;
    int level;
    int domain;
    bool stage2;
    bool s1ptw;
    bool s1ns;
    bool ea;
};

static inline uint32_t arm_fi_to_sfsc(ARMMMUFaultInfo *fi)
{
    uint32_t fsc;

    switch (fi->type) {
    case ARMFault_None:
        return 0;
    case ARMFault_AccessFlag:
        fsc = fi->level == 1 ? 0x3 : 0x6;
        break;
    case ARMFault_Alignment:
        fsc = 0x1;
        break;
    case ARMFault_Permission:
        fsc = fi->level == 1 ? 0xd : 0xf;
        break;
    case ARMFault_Domain:
        fsc = fi->level == 1 ? 0x9 : 0xb;
        break;
    case ARMFault_Translation:
        fsc = fi->level == 1 ? 0x5 : 0x7;
        break;
    case ARMFault_SyncExternal:
        fsc = 0x8 | (fi->ea << 12);
        break;
    case ARMFault_SyncExternalOnWalk:
        fsc = fi->level == 1 ? 0xc : 0xe;
        fsc |= (fi->ea << 12);
        break;
    case ARMFault_SyncParity:
        fsc = 0x409;
        break;
    case ARMFault_SyncParityOnWalk:
        fsc = fi->level == 1 ? 0x40c : 0x40e;
        break;
    case ARMFault_AsyncParity:
        fsc = 0x408;
        break;
    case ARMFault_AsyncExternal:
        fsc = 0x406 | (fi->ea << 12);
        break;
    case ARMFault_Debug:
        fsc = 0x2;
        break;
    case ARMFault_TLBConflict:
        fsc = 0x400;
        break;
    case ARMFault_Lockdown:
        fsc = 0x404;
        break;
    case ARMFault_Exclusive:
        fsc = 0x405;
        break;
    case ARMFault_ICacheMaint:
        fsc = 0x4;
        break;
    case ARMFault_Background:
        fsc = 0x0;
        break;
    case ARMFault_QEMU_NSCExec:
        fsc = M_FAKE_FSR_NSC_EXEC;
        break;
    case ARMFault_QEMU_SFault:
        fsc = M_FAKE_FSR_SFAULT;
        break;
    default:
        /* Other faults can't occur in a context that requires a
         * short-format status code.
         */
        g_assert_not_reached();
    }

    fsc |= (fi->domain << 4);
    return fsc;
}

static inline uint32_t arm_fi_to_lfsc(ARMMMUFaultInfo *fi)
{
    uint32_t fsc;

    switch (fi->type) {
    case ARMFault_None:
        return 0;
    case ARMFault_AddressSize:
        assert(fi->level >= -1 && fi->level <= 3);
        if (fi->level < 0) {
            fsc = 0b101001;
        } else {
            fsc = fi->level;
        }
        break;
    case ARMFault_AccessFlag:
        assert(fi->level >= 0 && fi->level <= 3);
        fsc = 0b001000 | fi->level;
        break;
    case ARMFault_Permission:
        assert(fi->level >= 0 && fi->level <= 3);
        fsc = 0b001100 | fi->level;
        break;
    case ARMFault_Translation:
        assert(fi->level >= -1 && fi->level <= 3);
        if (fi->level < 0) {
            fsc = 0b101011;
        } else {
            fsc = 0b000100 | fi->level;
        }
        break;
    case ARMFault_SyncExternal:
        fsc = 0x10 | (fi->ea << 12);
        break;
    case ARMFault_SyncExternalOnWalk:
        assert(fi->level >= -1 && fi->level <= 3);
        if (fi->level < 0) {
            fsc = 0b010011;
        } else {
            fsc = 0b010100 | fi->level;
        }
        fsc |= fi->ea << 12;
        break;
    case ARMFault_SyncParity:
        fsc = 0x18;
        break;
    case ARMFault_SyncParityOnWalk:
        assert(fi->level >= -1 && fi->level <= 3);
        if (fi->level < 0) {
            fsc = 0b011011;
        } else {
            fsc = 0b011100 | fi->level;
        }
        break;
    case ARMFault_AsyncParity:
        fsc = 0x19;
        break;
    case ARMFault_AsyncExternal:
        fsc = 0x11 | (fi->ea << 12);
        break;
    case ARMFault_Alignment:
        fsc = 0x21;
        break;
    case ARMFault_Debug:
        fsc = 0x22;
        break;
    case ARMFault_TLBConflict:
        fsc = 0x30;
        break;
    case ARMFault_UnsuppAtomicUpdate:
        fsc = 0x31;
        break;
    case ARMFault_Lockdown:
        fsc = 0x34;
        break;
    case ARMFault_Exclusive:
        fsc = 0x35;
        break;
    default:
        /* Other faults can't occur in a context that requires a
         * long-format status code.
         */
        g_assert_not_reached();
    }

    fsc |= 1 << 9;
    return fsc;
}

static inline ARMMMUIdx core_to_arm_mmu_idx(CPUARMState *env, int mmu_idx)
{
    if (arm_feature(env, ARM_FEATURE_M)) {
        return mmu_idx | ARM_MMU_IDX_M;
    } else {
        return mmu_idx | ARM_MMU_IDX_A;
    }
}

static inline uint32_t regime_el(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    switch (mmu_idx) {
    case ARMMMUIdx_E20_0:
    case ARMMMUIdx_E20_2:
    case ARMMMUIdx_E20_2_PAN:
    case ARMMMUIdx_Stage2:
    case ARMMMUIdx_Stage2_S:
    case ARMMMUIdx_E2:
        return 2;
    case ARMMMUIdx_E3:
        return 3;
    case ARMMMUIdx_E10_0:
    case ARMMMUIdx_Stage1_E0:
        return arm_el_is_aa64(env, 3) || !arm_is_secure_below_el3(env) ? 1 : 3;
    case ARMMMUIdx_Stage1_E1:
    case ARMMMUIdx_Stage1_E1_PAN:
    case ARMMMUIdx_E10_1:
    case ARMMMUIdx_E10_1_PAN:
    case ARMMMUIdx_MPrivNegPri:
    case ARMMMUIdx_MUserNegPri:
    case ARMMMUIdx_MPriv:
    case ARMMMUIdx_MUser:
    case ARMMMUIdx_MSPrivNegPri:
    case ARMMMUIdx_MSUserNegPri:
    case ARMMMUIdx_MSPriv:
    case ARMMMUIdx_MSUser:
        return 1;
    default:
        g_assert_not_reached();
    }
}

#define VTCR_SHARED_FIELD_MASK \
    (R_VTCR_IRGN0_MASK | R_VTCR_ORGN0_MASK | R_VTCR_SH0_MASK | \
     R_VTCR_PS_MASK | R_VTCR_VS_MASK | R_VTCR_HA_MASK | R_VTCR_HD_MASK | \
     R_VTCR_DS_MASK)

static inline uint64_t regime_tcr(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    if (mmu_idx == ARMMMUIdx_Stage2) {
        return env->cp15.vtcr_el2;
    }
    if (mmu_idx == ARMMMUIdx_Stage2_S) {
        /*
         * Secure stage 2 shares fields from VTCR_EL2. We merge those
         * in with the VSTCR_EL2 value to synthesize a single VTCR_EL2 format
         * value so the callers don't need to special case this.
         *
         * If a future architecture change defines bits in VSTCR_EL2 that
         * overlap with these VTCR_EL2 fields we may need to revisit this.
         */
        uint64_t v = env->cp15.vstcr_el2 & ~VTCR_SHARED_FIELD_MASK;
        v |= env->cp15.vtcr_el2 & VTCR_SHARED_FIELD_MASK;
        return v;
    }
    return env->cp15.tcr_el[regime_el(env, mmu_idx)];
}

static inline bool regime_using_lpae_format(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    int el = regime_el(env, mmu_idx);
    if (el == 2 || arm_el_is_aa64(env, el)) {
        return true;
    }
    if (arm_feature(env, ARM_FEATURE_PMSA) &&
        arm_feature(env, ARM_FEATURE_V8)) {
        return true;
    }
    if (arm_feature(env, ARM_FEATURE_LPAE)
        && (regime_tcr(env, mmu_idx) & TTBCR_EAE)) {
        return true;
    }
    return false;
}

static inline ARMMMUIdx stage_1_mmu_idx(ARMMMUIdx mmu_idx)
{
    return ARMMMUIdx_Stage1_E0;
}

int exception_target_el(CPUARMState *env);

bool arm_s1_regime_using_lpae_format(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    mmu_idx = stage_1_mmu_idx(mmu_idx);
    return regime_using_lpae_format(env, mmu_idx);
}

static uint32_t compute_fsr_fsc(CPUARMState *env, ARMMMUFaultInfo *fi,
                                int target_el, int mmu_idx, uint32_t *ret_fsc)
{
    ARMMMUIdx arm_mmu_idx = core_to_arm_mmu_idx(env, mmu_idx);
    uint32_t fsr, fsc;

    /*
     * For M-profile there is no guest-facing FSR. We compute a
     * short-form value for env->exception.fsr which we will then
     * examine in arm_v7m_cpu_do_interrupt(). In theory we could
     * use the LPAE format instead as long as both bits of code agree
     * (and arm_fi_to_lfsc() handled the M-profile specific
     * ARMFault_QEMU_NSCExec and ARMFault_QEMU_SFault cases).
     */
    if (!arm_feature(env, ARM_FEATURE_M) &&
        (target_el == 2 || arm_el_is_aa64(env, target_el) ||
         arm_s1_regime_using_lpae_format(env, arm_mmu_idx))) {
        /*
         * LPAE format fault status register : bottom 6 bits are
         * status code in the same form as needed for syndrome
         */
        fsr = arm_fi_to_lfsc(fi);
        fsc = extract32(fsr, 0, 6);
    } else {
        fsr = arm_fi_to_sfsc(fi);
        /*
         * Short format FSR : this fault will never actually be reported
         * to an EL that uses a syndrome register. Use a (currently)
         * reserved FSR code in case the constructed syndrome does leak
         * into the guest somehow.
         */
        fsc = 0x3f;
    }

    *ret_fsc = fsc;
    return fsr;
}

void helper_exception_pc_alignment(CPUARMState *env, target_ulong pc)
{
    ARMMMUFaultInfo fi = { .type = ARMFault_Alignment };
    int target_el = exception_target_el(env);
    int mmu_idx = cpu_mmu_index(env, true);
    uint32_t fsc;

    env->exception.vaddress = pc;

    /*
     * Note that the fsc is not applicable to this exception,
     * since any syndrome is pcalignment not insn_abort.
     */
    env->exception.fsr = compute_fsr_fsc(env, &fi, target_el, mmu_idx, &fsc);
    raise_exception(env, EXCP_PREFETCH_ABORT, syn_pcalignment(), target_el);
}


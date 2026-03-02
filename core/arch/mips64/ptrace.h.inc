struct tracee_state_t {
  static constexpr bool is64 = true;

  uint64_t regs[32];
  uint64_t lo;
  uint64_t hi;
  uint64_t cp0_epc;
  uint64_t cp0_badvaddr;
  uint64_t cp0_status;
  uint64_t cp0_cause;

  uint64_t &program_counter(void) { return cp0_epc; }

  uint64_t syscall_number(void) { return regs[2]; }
  uint64_t syscall_argument(unsigned idx) {
    switch (idx) {
      case 0: return regs[4];
      case 1: return regs[5];
      case 2: return regs[6];
      case 3: return regs[7];
      case 4: return UINT64_MAX; /* FIXME */
      case 5: return UINT64_MAX; /* FIXME */
    }
    abort();
  }
  uint64_t syscall_return(void) {
    const auto r7 = regs[7];
    const auto r2 = regs[2];
    return r7 && r2 > 0 ? -r2 : r2;
  }

  STANDARD_GETREGS
  STANDARD_SETREGS
} __attribute__((aligned(8)));

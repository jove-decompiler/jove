struct tracee_state_t
{
  static constexpr bool is64 = true;

  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;

  uint64_t &program_counter(void) { return pc; }

  uint64_t syscall_number(void) { return regs[8]; }
  uint64_t syscall_argument(unsigned idx) {
    switch (idx) {
      case 0: return regs[0];
      case 1: return regs[1];
      case 2: return regs[2];
      case 3: return regs[3];
      case 4: return regs[4];
      case 5: return regs[5];
    }
    abort();
  }
  uint64_t syscall_return(void) { return regs[0]; }

  STANDARD_GETREGSET
  STANDARD_SETREGSET
};

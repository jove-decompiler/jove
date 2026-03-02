struct tracee_state_t
{
  static constexpr bool is64 = true;

  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
  uint64_t rbp;
  uint64_t rbx;
  uint64_t r11;
  uint64_t r10;
  uint64_t r9;
  uint64_t r8;
  uint64_t rax;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t orig_rax;
  uint64_t rip;
  uint64_t cs;
  uint64_t eflags;
  uint64_t rsp;
  uint64_t ss;
  uint64_t fs_base;
  uint64_t gs_base;
  uint64_t ds;
  uint64_t es;
  uint64_t fs;
  uint64_t gs;

  uint64_t &program_counter(void) { return rip; }
  uint64_t &stack_pointer(void) { return rsp; }

  uint64_t syscall_number(void) { return orig_rax; }
  uint64_t syscall_argument(unsigned idx) {
    switch (idx) {
      case 0: return rdi;
      case 1: return rsi;
      case 2: return rdx;
      case 3: return r10;
      case 4: return r8;
      case 5: return r9;
    }
    abort();
  }
  uint64_t syscall_return(void) { return rax; }

  STANDARD_GETREGSET
  STANDARD_SETREGSET
};

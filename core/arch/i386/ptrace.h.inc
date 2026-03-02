#ifdef COMPAT
#define PREFIX compat_
#else
#define PREFIX
#endif

struct BOOST_PP_CAT(PREFIX,tracee_state_t)
{
  static constexpr bool is64 = false;

  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint32_t ebp;
  uint32_t eax;
  uint32_t xds;
  uint32_t xes;
  uint32_t xfs;
  uint32_t xgs;
  uint32_t orig_eax;
  uint32_t eip;
  uint32_t xcs;
  uint32_t eflags;
  uint32_t esp;
  uint32_t xss;

  uint32_t &program_counter(void) { return eip; }
  uint32_t &stack_pointer(void) { return esp; }

  uint32_t syscall_number(void) { return orig_eax; }
  uint32_t syscall_argument(unsigned idx) {
    switch (idx) {
      case 0: return ebx;
      case 1: return ecx;
      case 2: return edx;
      case 3: return esi;
      case 4: return edi;
      case 5: return ebp;
    }
    abort();
  }
  uint32_t syscall_return(void) { return eax; }

  STANDARD_GETREGSET
  STANDARD_SETREGSET
};

struct user_desc {
  unsigned int entry_number;
  unsigned int base_addr;
  unsigned int limit;
  unsigned int seg_32bit : 1;
  unsigned int contents : 2;
  unsigned int read_exec_only : 1;
  unsigned int limit_in_pages : 1;
  unsigned int seg_not_present : 1;
  unsigned int useable : 1;
};

#undef PREFIX

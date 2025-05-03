#pragma once

#include <string>
#include <cstring>

#include <unistd.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#if defined(__mips__)
#include <asm/ptrace.h> /* for pt_regs */
#endif
#include <sys/syscall.h>

namespace jove {

#if defined(__mips64) || defined(__mips__) || defined(__arm__)
typedef struct pt_regs cpu_state_t;
#else
typedef struct user_regs_struct cpu_state_t;
#endif

void _ptrace_get_cpu_state(pid_t, cpu_state_t &out);
void _ptrace_set_cpu_state(pid_t, const cpu_state_t &in);

std::string _ptrace_read_string(pid_t, uintptr_t addr);

unsigned long _ptrace_peekdata(pid_t, uintptr_t addr);
void _ptrace_pokedata(pid_t, uintptr_t addr, unsigned long data);

ssize_t _ptrace_memcpy(pid_t, void *dest, const void *src, size_t n);

#if !defined(__x86_64__) && defined(__i386__)
static uintptr_t segment_address_of_selector(pid_t, unsigned segsel);
#endif

static constexpr auto &pc_of_cpu_state(cpu_state_t &cpu_state) {
  return cpu_state.
#if defined(__x86_64__)
      rip
#elif defined(__i386__)
      eip
#elif defined(__aarch64__)
      pc
#elif defined(__arm__)
      uregs[15]
#elif defined(__mips64) || defined(__mips__)
      cp0_epc
#else
#error
#endif
      ;
}

}

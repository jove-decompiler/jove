#pragma once
#include "sys.h"
#include "likely.h"
#include "jove/jove.h"

#include <string>
#include <vector>
#include <cstring>
#include <cstddef>
#include <exception>
#include <system_error>

#include <unistd.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#if defined(__mips__)
#include <asm/ptrace.h> /* for pt_regs */
#endif
#include <sys/syscall.h>

#if defined(__mips64) || defined(__mips__)
#undef PC /* XXX */
#endif

namespace jove {
namespace ptrace {

using word = unsigned long;

// copies as many bytes as it can, from the tracee. throws on failure.
ssize_t memcpy_from(pid_t,
                    std::vector<std::byte> &dst,
                    const void *src,
                    size_t N);

// copies as many bytes as it can, to the tracee. throws on failure.
ssize_t memcpy_to(pid_t,
                  void *dst,
                  const std::byte *src,
                  size_t N);

#if !defined(__x86_64__) && defined(__i386__)
uintptr_t segment_address_of_selector(pid_t, unsigned segsel);
#endif

//
// NOT fine-grained.
//
using tracee_state_t =
#if defined(__mips64) || defined(__mips__) || defined(__arm__)
    struct pt_regs
#else
    struct user_regs_struct
#endif
    ;

static constexpr auto &pc_of_tracee_state(tracee_state_t &tracee_state) {
  return tracee_state.
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

struct tracer_exception {};

std::string read_c_str(pid_t, uintptr_t addr);

template <bool Throw = true>
static inline unsigned long peekdata(pid_t child, uintptr_t addr) {
  unsigned long res;

  unsigned long _request = PTRACE_PEEKDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);
  if constexpr (Throw) {
  if (unlikely(ret < 0))
    throw tracer_exception();
  }

  return res;
}

template <bool Throw = true>
static inline void pokedata(pid_t child, uintptr_t addr, unsigned long data) {
  unsigned long _request = PTRACE_POKEDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = data;

  long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);
  if constexpr (Throw) {
  if (unlikely(ret < 0))
    throw tracer_exception();
  }
}

static inline void get(pid_t child, tracee_state_t &out) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_GETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 0;
  unsigned long _data = reinterpret_cast<unsigned long>(&out.regs[0]);
#else
  struct iovec iov = {.iov_base = &out,
                      .iov_len = sizeof(tracee_state_t)};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);
#endif

  long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);
  if (unlikely(ret < 0))
    throw tracer_exception();
}

static inline void set(pid_t child, const tracee_state_t &in) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_SETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&in.regs[0]);
#else
  struct iovec iov = {.iov_base = const_cast<tracee_state_t *>(&in),
                      .iov_len = sizeof(tracee_state_t)};

  unsigned long _request = PTRACE_SETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);
#endif

  long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);
  if (unlikely(ret < 0))
    throw tracer_exception();
}

struct scoped_tracee_state_t {
  const pid_t child;
  tracee_state_t &tracee_state;

  scoped_tracee_state_t(pid_t child, tracee_state_t &tracee_state)
      : child(child), tracee_state(tracee_state) {
    get(child, tracee_state);
  }
  ~scoped_tracee_state_t() {
    if (std::uncaught_exceptions() == 0)
      set(child, tracee_state);
  }
};

}
}

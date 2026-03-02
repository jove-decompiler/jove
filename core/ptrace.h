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

#if 0
// copies as many bytes as it can, from the tracee. throws on failure.
void memcpy_from(pid_t,
                 std::vector<uint8_t> &dst,
                 const uint64_t src,
                 const size_t N);

// copies as many bytes as it can, to the tracee. throws on failure.
ssize_t memcpy_to(pid_t,
                  uint64_t dst,
                  const uint8_t *src,
                  size_t N);
#endif

struct tracer_exception {
  int err;
  taddr_t addr;

  tracer_exception(int err, taddr_t addr = ~0ULL) : err(err), addr(addr) {}
};

#if defined(TARGET_I386)
uint32_t segment_address_of_selector(pid_t, unsigned segsel);
#endif

#define STANDARD_GETREGSET                                                     \
  template <bool Throw = true> void get(pid_t child) {                         \
    struct iovec iov = {.iov_base = this, .iov_len = sizeof(*this)};           \
                                                                               \
    unsigned long _request = PTRACE_GETREGSET;                                 \
    unsigned long _pid = child;                                                \
    unsigned long _addr = 1 /* NT_PRSTATUS */;                                 \
    unsigned long _data = reinterpret_cast<unsigned long>(&iov);               \
                                                                               \
    long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);                 \
    if constexpr (Throw) {                                                     \
      if (unlikely(ret < 0))                                                   \
        throw tracer_exception(-ret);                                          \
    }                                                                          \
  }

#define STANDARD_GETREGS                                                       \
  template <bool Throw = true> void get(pid_t child) {                         \
    unsigned long _request = PTRACE_GETREGS;                                   \
    unsigned long _pid = child;                                                \
    unsigned long _addr = 0;                                                   \
    unsigned long _data = reinterpret_cast<unsigned long>(this);               \
                                                                               \
    long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);                 \
    if constexpr (Throw) {                                                     \
      if (unlikely(ret < 0))                                                   \
        throw tracer_exception(-ret);                                          \
    }                                                                          \
  }

#define STANDARD_SETREGSET                                                     \
  template <bool Throw = true> void set(pid_t child) {                         \
    struct iovec iov = {.iov_base = this, .iov_len = sizeof(*this)};           \
                                                                               \
    unsigned long _request = PTRACE_SETREGSET;                                 \
    unsigned long _pid = child;                                                \
    unsigned long _addr = 1 /* NT_PRSTATUS */;                                 \
    unsigned long _data = reinterpret_cast<unsigned long>(&iov);               \
                                                                               \
    long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);                 \
    if constexpr (Throw) {                                                     \
      if (unlikely(ret < 0))                                                   \
        throw tracer_exception(-ret);                                          \
    }                                                                          \
  }

#define STANDARD_SETREGS                                                       \
  template <bool Throw = true> void set(pid_t child) {                         \
    unsigned long _request = PTRACE_SETREGS;                                   \
    unsigned long _pid = child;                                                \
    unsigned long _addr = 1 /* NT_PRSTATUS */;                                 \
    unsigned long _data = reinterpret_cast<unsigned long>(this);               \
                                                                               \
    long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);                 \
    if constexpr (Throw) {                                                     \
      if (unlikely(ret < 0))                                                   \
        throw tracer_exception(-ret);                                          \
    }                                                                          \
  }

//
// tracee_state_t (and compat_tracee_state_t)
//
#if defined(__x86_64__)

#include "arch/x86_64/ptrace.h.inc"
#define COMPAT
#  include "arch/i386/ptrace.h.inc"

#if defined(TARGET_X86_64)
using target_tracee_state_t = tracee_state_t;
constexpr bool is_target_compat = false;
#elif defined(TARGET_I386)
using target_tracee_state_t = compat_tracee_state_t;
constexpr bool is_target_compat = true;
#else /* not applicable */
using target_tracee_state_t = void;
constexpr bool is_target_compat = false;
#endif

#elif defined(__i386__)

#include "arch/i386/ptrace.h.inc"
using compat_tracee_state_t = void;

using target_tracee_state_t = tracee_state_t;
constexpr bool is_target_compat = false;

#elif defined(__mips64)

#include "arch/mips64el/ptrace.h.inc"
#define COMPAT
#  include "arch/mipsel/ptrace.h.inc"

#if defined(TARGET_MIPS64)
using target_tracee_state_t = tracee_state_t;
constexpr bool is_target_compat = false;
#elif defined(TARGET_MIPS32)
using target_tracee_state_t = compat_tracee_state_t;
constexpr bool is_target_compat = true;
#else /* not applicable */
using target_tracee_state_t = void;
constexpr bool is_target_compat = false;
#endif

#elif defined(__mips__)

#include "arch/mipsel/ptrace.h.inc"
using compat_tracee_state_t = void;

using target_tracee_state_t = tracee_state_t;
constexpr bool is_target_compat = false;

#elif defined(__aarch64__)

#include "arch/aarch64/ptrace.h.inc"
using compat_tracee_state_t = void;

#ifdef TARGET_AARCH64

using target_tracee_state_t = tracee_state_t;
constexpr bool is_target_compat = false;

#else
#error "TODO (compat)"
#endif

#else
#error
#endif

std::string read_c_str(pid_t, uint64_t addr);

template <bool Throw = true>
static inline unsigned long peekdata(pid_t child, taddr_t addr) {
  unsigned long res = ~0ULL;

  unsigned long _request = PTRACE_PEEKDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  if constexpr (Throw) {
    if (addr % sizeof(unsigned long) != 0)
      throw tracer_exception(ESPIPE);
  }

  long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);

  if constexpr (Throw) {
    if (unlikely(ret < 0))
      throw tracer_exception(-ret, addr);
  }

  return res;
}

template <bool Throw = true>
static inline long pokedata(pid_t child, taddr_t addr, unsigned long data) {
  unsigned long _request = PTRACE_POKEDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = data;

#if 0
  if constexpr (Throw) {
    if (addr % sizeof(unsigned long) != 0)
      throw tracer_exception(ESPIPE);
  }
#endif

  long ret = _jove_sys_ptrace(_request, _pid, _addr, _data);

  if constexpr (Throw) {
    if (unlikely(ret < 0))
      throw tracer_exception(-ret, addr);
  }

  return ret;
}

template <typename TraceeState>
struct scoped_tracee_state_t {
  const pid_t child;
  TraceeState &tracee_state;

  scoped_tracee_state_t(pid_t child, TraceeState &tracee_state)
      : child(child), tracee_state(tracee_state) {
    tracee_state.get(child);
  }
  ~scoped_tracee_state_t() {
    if (std::uncaught_exceptions() == 0)
      tracee_state.set(child);
  }
};

template <bool Throw = true>
static ssize_t vm_read(pid_t child,
                       taddr_t addr,
                       uint8_t *buf,
                       size_t len) {
  //
  // TODO: use process_vm_readv
  //
  abort();
}

template <bool Throw = true>
static ssize_t vm_write(pid_t child,
                        taddr_t addr,
                        const uint8_t *buf,
                        size_t len) {
  //
  // TODO: use process_vm_writev
  //
  abort();
}

template <bool Throw = true>
static ssize_t vm_peek(pid_t child,
                       taddr_t addr,
                       uint8_t *buf,
                       size_t len) {
  //
  // TODO: use PTRACE_PEEKDATA
  //
  abort();
}

template <bool Throw = true>
static ssize_t vm_poke(pid_t child,
                       taddr_t addr,
                       const uint8_t *buf,
                       size_t len) {
  //
  // TODO: use PTRACE_POKEDATA
  //
  abort();
}

}
}

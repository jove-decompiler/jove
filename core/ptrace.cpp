#include "ptrace.h"

#include <stdexcept>
#include <boost/format.hpp>

namespace jove {

typedef boost::format fmt;

void _ptrace_get_cpu_state(pid_t child, cpu_state_t &out) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_GETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 0;
  unsigned long _data = reinterpret_cast<unsigned long>(&out.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = &out,
                      .iov_len = sizeof(cpu_state_t)};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

void _ptrace_set_cpu_state(pid_t child, const cpu_state_t &in) {
#if defined(__mips64) || defined(__mips__)
  unsigned long _request = PTRACE_SETREGS;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&in.regs[0]);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGS failed : ") +
                             std::string(strerror(errno)));
#else
  struct iovec iov = {.iov_base = const_cast<cpu_state_t *>(&in),
                      .iov_len = sizeof(cpu_state_t)};

  unsigned long _request = PTRACE_SETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 1 /* NT_PRSTATUS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_SETREGSET failed : ") +
                             std::string(strerror(errno)));
#endif
}

unsigned long _ptrace_peekdata(pid_t child, uintptr_t addr) {
  unsigned long res;

  unsigned long _request = PTRACE_PEEKDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = reinterpret_cast<unsigned long>(&res);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error((fmt("PTRACE_PEEKDATA(%d, %p) failed : %s") %
                              child % addr % strerror(errno)).str());

  return res;
}

void _ptrace_pokedata(pid_t child, uintptr_t addr, unsigned long data) {
  unsigned long _request = PTRACE_POKEDATA;
  unsigned long _pid = child;
  unsigned long _addr = addr;
  unsigned long _data = data;

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_POKEDATA failed : ") +
                             std::string(strerror(errno)));
}

ssize_t _ptrace_memcpy(pid_t child, void *dest, const void *src, size_t n) {
  std::vector<uint8_t> buff;
  buff.reserve(n);

  uintptr_t Addr = reinterpret_cast<uintptr_t>(src);

  for (;;) {
    auto word = _ptrace_peekdata(child, Addr);

    for (unsigned i = 0; i < sizeof(word); ++i) {
      buff.push_back(reinterpret_cast<uint8_t *>(&word)[i]);
      if (buff.size() == n) {
        memcpy(dest, &buff[0], n); /* we're done */
        return n;
      }
    }

    Addr += sizeof(word);
  }

  __builtin_trap();
  __builtin_unreachable();
}

}

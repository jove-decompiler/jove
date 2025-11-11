#include "ptrace.h"

#include <stdexcept>
#include <array>
#include <boost/format.hpp>

#if !defined(__x86_64__) && defined(__i386__)
#include <asm/ldt.h>
#endif

namespace jove {
namespace ptrace {

typedef boost::format fmt;

ssize_t memcpy(pid_t child,
               std::vector<std::byte> &dst,
               const void *src,
               const size_t N) {
  dst.reserve(N);
  dst.clear();

  uintptr_t Addr = reinterpret_cast<uintptr_t>(src);

  size_t done = 0;
  for (; done < N; done += sizeof(ptrace::word)) {
    const auto chunk = peekdata(child, Addr);
    static_assert(sizeof(chunk) == sizeof(ptrace::word));

    Addr += sizeof(chunk);

    const size_t M = dst.size();
    dst.resize(dst.size() + sizeof(chunk));
    __builtin_memcpy_inline(&dst[M], &chunk, sizeof(chunk));
  }

  dst.resize(N);
  return N;
}

#if !defined(__x86_64__) && defined(__i386__)
constexpr unsigned GDT_ENTRY_TLS_ENTRIES = 3;

static void get_segment_descriptors(
    pid_t child, std::array<struct user_desc, GDT_ENTRY_TLS_ENTRIES> &out) {
  struct iovec iov = {.iov_base = out.data(),
                      .iov_len = sizeof(struct user_desc) * out.size()};

  unsigned long _request = PTRACE_GETREGSET;
  unsigned long _pid = child;
  unsigned long _addr = 0x200 /* NT_386_TLS */;
  unsigned long _data = reinterpret_cast<unsigned long>(&iov);

  if (syscall(__NR_ptrace, _request, _pid, _addr, _data) < 0)
    throw std::runtime_error(std::string("PTRACE_GETREGSET failed : ") +
                             std::string(strerror(errno)));
}

uintptr_t segment_address_of_selector(pid_t child, unsigned segsel) {
  unsigned index = segsel >> 3;

  std::array<struct user_desc, GDT_ENTRY_TLS_ENTRIES> seg_descs;
  get_segment_descriptors(child, seg_descs);

  auto it = std::find_if(seg_descs.begin(), seg_descs.end(),
                         [&](const struct user_desc &desc) -> bool {
                           return desc.entry_number == index;
                         });

  if (it == seg_descs.end())
    throw std::runtime_error(std::string("segment_address_of_selector failed"));

  return (*it).base_addr;
}
#endif

std::string read_c_str(pid_t child, uintptr_t Addr) {
  std::string res;

  for (;;) {
    auto word = peekdata(child, Addr);

    for (unsigned i = 0; i < sizeof(word); ++i) {
      char ch = reinterpret_cast<char *>(&word)[i];
      if (ch == '\0')
        return res;
      res.push_back(ch);
    }

    Addr += sizeof(word);
  }

  return res;
}

}
}

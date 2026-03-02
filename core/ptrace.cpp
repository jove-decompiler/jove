#if (defined(__x86_64__)  && defined(TARGET_X86_64))  || \
    (defined(__x86_64__)  && defined(TARGET_I386))  || \
    (defined(__i386__)    && defined(TARGET_I386))    || \
    (defined(__aarch64__) && defined(TARGET_AARCH64)) || \
    (defined(__mips64)    && defined(TARGET_MIPS64))  || \
    (defined(__mips64)    && defined(TARGET_MIPS32))  || \
    (defined(__mips__)    && defined(TARGET_MIPS32))
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

#if 0
void memcpy_from(pid_t child,
                 std::vector<uint8_t> &dst,
                 const uint64_t src,
                 const size_t N) {
  dst.clear();

  if (N == 0)
    return;

  dst.reserve(N);

  constexpr size_t W = sizeof(unsigned long);
  const size_t before = src % W;
  const size_t need = N + before;

  try {
    size_t done = 0;
    for (uint64_t Addr = src - before; done < need; done += W, Addr += W) {
      const auto chunk = peekdata<true>(child, Addr);

      for (unsigned i = 0; i < sizeof(chunk); ++i)
        dst.push_back(reinterpret_cast<const uint8_t *>(&chunk)[i]);
    }
  } catch (const tracer_exception &) {}

  if (dst.size() == 0)
    return;

  aassert(dst.size() >= W);
  if (before) {
    aassert(dst.size() >= before);
    dst.erase(dst.begin(), dst.begin() + before);
  }

  aassert(dst.size() >= N);
  dst.resize(N);
}

ssize_t memcpy_to(pid_t child,
                  uint64_t dst,
                  const uint8_t *src,
                  size_t N) {
  uint64_t Addr = dst;

  try {
    ssize_t left = N;
    for (; left > 0; left -= sizeof(unsigned long), Addr += sizeof(unsigned long)) {
      const size_t pos = N - left;

      unsigned long chunk;
      size_t M = std::min<size_t>(left, sizeof(chunk));
      if (M < sizeof(chunk))
        chunk = peekdata(child, Addr);
      memcpy(&chunk, &src[pos], M);

      pokedata(child, Addr, chunk);
    }
  } catch (const tracer_exception &) {}

  return Addr - dst;
}
#endif

#if defined(TARGET_I386)
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

uint32_t segment_address_of_selector(pid_t child, unsigned segsel) {
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

std::string read_c_str(pid_t child, uint64_t Addr) {
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
#endif

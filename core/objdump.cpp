#include "objdump.h"
#include "locator.h"
#include "pipe.h"
#include "temp.h"
#include "process.h"
#include "fd.h"
#include "B.h"

#include <cstdlib>
#include <stdexcept>
#include <cstdio>

namespace jove {

template <typename T>
int run_objdump_and_parse_addresses(const char *filename,
                                    llvm::object::Binary &Bin, T &out) {
  std::unique_ptr<temp_executable> temp_exe;
  if (!filename) {
    temp_exe = std::make_unique<temp_executable>(
        Bin.getMemoryBufferRef().getBufferStart(),
        Bin.getMemoryBufferRef().getBufferSize(),
        "objdump-" TARGET_ARCH_NAME);
    temp_exe->store();
    filename = temp_exe->path().c_str();
  }

  std::string path_to_objdump = locator_t::objdump(B::is_coff(Bin));

  int pipefd[2];
  if (::pipe(pipefd) < 0)
    throw std::runtime_error("pipe failed: " + std::string(strerror(errno)));

  auto rfd = std::make_unique<scoped_fd>(pipefd[0]);
  auto wfd = std::make_unique<scoped_fd>(pipefd[1]);

  pid_t pid = RunExecutable(
      path_to_objdump,
      [&](auto Arg) {
        Arg(path_to_objdump);
        Arg("-d");
        Arg(filename);
      },
      "", "",
      [&](const char **argv, const char **envp) {
        rfd.reset();
        ::dup2(wfd->get(), STDOUT_FILENO);
        wfd.reset();
      });
  wfd.reset();

  taddr_t minaddr = ~0UL;
  taddr_t maxaddr = 0UL;

  pipe_line_reader pipe;

  auto do_parse_line = [&](std::string &line) -> void {
    auto it = line.begin();

#define ret_if_end()                                                           \
  do {                                                                         \
    if (it == line.end())                                                      \
      return;                                                                  \
  } while (false)

#define get()                                                                  \
  ({                                                                           \
    ret_if_end();                                                              \
    *it;                                                                       \
  })

#define next()                                                                 \
  ({                                                                           \
    ret_if_end();                                                              \
    it++;                                                                      \
  })

#define get_and_next()                                                         \
  ({                                                                           \
    ret_if_end();                                                              \
    *it++;                                                                     \
  })

#define pos()                                                                  \
  ({                                                                           \
    ret_if_end();                                                              \
    std::distance(line.begin(), it);                                           \
  })

    std::string::iterator addr_beg, addr_end;

    for (;;) {
      switch (get()) {
      default: return;
      case ' ': next(); continue;
      case '0' ... '9':
      case 'a' ... 'f':
        addr_beg = next();
        break;
      }
      break;
    }

    for (;;) {
      switch (get()) {
      default: return;
      case '0' ... '9':
      case 'a' ... 'f': next(); continue;
      case ':':
        addr_end = next();
        break;
      }
      break;
    }

    if (get_and_next() != '\t')
      return;
    if (line.find('\t', pos()) == std::string::npos)
      return;

    *addr_end = '\0';

    errno = 0;
    unsigned long addr = strtoul(&(*addr_beg), nullptr, 0x10);
    if (errno != 0)
      return;

    if (~minaddr == 0)
      minaddr = addr;

    if (addr < minaddr)
      return; // new section maybe?

    maxaddr = addr;

    unsigned long idx = addr - minaddr;

    static const std::string bad("(bad)");
    bool is_good = line.find(bad) == std::string::npos;
    if (is_good) {
#if 0
      fprintf(stderr, "good: %" PRIx64 " in %s\n", (uint64_t)addr, filename);
#endif

      if (unlikely(idx >= out.good.size()))
        out.good.resize(idx + 1, false);

      out.good.set(idx);
    }

#undef ret_if_end
#undef get
#undef next
#undef get_and_next
#undef pos
  };

  out.good.clear();
  {
    uint64_t SectsStartAddr, SectsEndAddr;
    std::tie(SectsStartAddr, SectsEndAddr) = B::bounds_of_binary(Bin);

    out.good.resize(SectsEndAddr - SectsStartAddr); /* estimate */
  }

  while (auto o = pipe.get_line(rfd->get()))
    do_parse_line(*o);

  int rc = WaitForProcessToExit(pid);

  if (rc) {
    out.begin = ~0UL;
    out.good.clear();
  } else {
    out.begin = minaddr;
    out.good.resize(maxaddr - minaddr + 1);
  }

  return rc;
}

template int run_objdump_and_parse_addresses<objdump_output_t<false>>(const char *filename, llvm::object::Binary &Bin, objdump_output_t<false> &out);
template int run_objdump_and_parse_addresses<objdump_output_t<true>>(const char *filename, llvm::object::Binary &Bin, objdump_output_t<true> &out);

template int run_objdump_and_parse_addresses<binary_t::Analysis_t::objdump_output_type>(const char *filename, llvm::object::Binary &Bin, binary_t::Analysis_t::objdump_output_type &out);

}

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

template <typename Alloc, bool MT>
int objdump_thinks_t<Alloc, MT>::run(const char *filename,
                                     llvm::object::Binary &Bin) {
  std::unique_ptr<temp_exe> the_exe;
  if (!filename) {
    the_exe = std::make_unique<temp_exe>(
        Bin.getMemoryBufferRef().getBufferStart(),
        Bin.getMemoryBufferRef().getBufferSize(),
        "objdump-" TARGET_ARCH_NAME, false);
    the_exe->store();
    filename = the_exe->path().c_str();
  }

  std::string path_to_objdump = locator_t::objdump(B::is_coff(Bin));

  int pipefd[2];
  if (::pipe(pipefd) < 0)
    throw std::runtime_error("pipe failed: " + std::string(strerror(errno)));

  scoped_fd rfd(pipefd[0]);
  scoped_fd wfd(pipefd[1]);

  pid_t pid = RunExecutable(
      path_to_objdump,
      [&](auto Arg) {
        Arg(path_to_objdump);
        Arg("-d");
        Arg(filename);
      },
      "", "",
      [&](const char **argv, const char **envp) {
        rfd.close();
        ::dup2(wfd.get(), STDOUT_FILENO);
        wfd.close();
      });
  wfd.close();

  taddr_t minaddr = ~0UL;
  taddr_t maxaddr = 0UL;

  pipe_line_reader pipe;

  auto do_parse_line = [&](std::string &line) -> void {
    auto it = line.begin();

#define ret_if_end()                                                           \
  do {                                                                         \
    if (unlikely(it == line.end()))                                            \
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
    unsigned long long addr = strtoull(&(*addr_beg), nullptr, 0x10);
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

      if (unlikely(idx >= this->good.size()))
        this->good.resize(idx + 1, false);

      this->good.set(idx);
    }

#undef ret_if_end
#undef get
#undef next
#undef get_and_next
#undef pos
  };

  while (auto o = pipe.get_line(rfd.get()))
    do_parse_line(*o);

  int rc = WaitForProcessToExit(pid);

  if (rc) {
    this->begin = ~0UL;
    this->good.clear();
  } else {
    this->begin = minaddr;
  }

  return rc;
}

typedef boost::interprocess::allocator<unsigned long, segment_manager_t>
    alloc_t;

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((alloc_t))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct objdump_thinks_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),   \
                                   GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>;

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}

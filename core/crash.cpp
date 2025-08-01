#include "crash.h"
#include "util.h"
#include "fd.h"

#include <sys/mman.h>
#include <signal.h>

namespace jove {

void setup_crash_handler(void) {
  const unsigned altstack_size = SIGSTKSZ;

  void *altstack = mmap(NULL, altstack_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (altstack == MAP_FAILED)
    throw std::runtime_error("mmap failed: " + std::string(strerror(errno)));

  stack_t ss;
  ss.ss_sp = altstack;
  ss.ss_size = altstack_size;
  ss.ss_flags = 0;

  if (::sigaltstack(&ss, nullptr) < 0)
    throw std::runtime_error("sigaltstack failed: " + std::string(strerror(errno)));

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_NODEFER | SA_ONSTACK;
  sa.sa_handler = [](int no) -> void {
    static const char rest[] = " crashed! attach a debugger...\n";

    char msg[65 + sizeof(rest)];
    memcpy(uint_to_string(::gettid(), msg, 10), rest, sizeof(rest));
    size_t len = strlen(msg);

    for (;;) {
      robust_write(STDERR_FILENO, msg, len);
      robust_write(STDOUT_FILENO, msg, len);

      sleep(1);
    }
    __builtin_unreachable();
  };

  if (::sigaction(SIGSEGV, &sa, nullptr) < 0 ||
      ::sigaction(SIGABRT, &sa, nullptr) < 0 ||
      ::sigaction(SIGBUS, &sa, nullptr) < 0)
    throw std::runtime_error("sigaction failed: " +
                             std::string(strerror(errno)));
}

}
